// SPDX-License-Identifier: GPL-2.0
// Advanced SIMD (NEON) execution.
//
// Covers the integer and FP operations that mainstream compilers and glibc
// string/memory routines emit. Element access treats each V register as two
// u64 halves (little-endian lanes).

use super::{Exit, Step};
use crate::decode::*;
use crate::env::{Env, Fault};
use crate::softfloat::{self as sf, Fmt};
use crate::state::CpuState;

/// Number of bytes in the vector (8 or 16).
#[inline]
fn vbytes(q: bool) -> u32 {
    if q {
        16
    } else {
        8
    }
}

/// Read lane `i` of size `esize` (log2 bytes) from register `r`.
fn get_lane(cpu: &CpuState, r: u32, esize: u8, i: u32) -> u64 {
    let v = cpu.vreg(r);
    let bits = 8u32 << esize;
    let off = i * bits;
    let (word, shift) = if off >= 64 { (v[1], off - 64) } else { (v[0], off) };
    let mask = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
    if shift >= 64 {
        0
    } else {
        (word >> shift) & mask
    }
}

/// Insert `val` into lane `i` of size `esize` in a [u64;2] vector.
fn put_lane(vec: &mut [u64; 2], esize: u8, i: u32, val: u64) {
    let bits = 8u32 << esize;
    let off = i * bits;
    let mask = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
    let v = val & mask;
    if off >= 128 {
        return;
    }
    let (idx, shift) = if off >= 64 { (1usize, off - 64) } else { (0usize, off) };
    if shift >= 64 {
        return;
    }
    vec[idx] = (vec[idx] & !(mask << shift)) | (v << shift);
}

#[inline]
fn sext(v: u64, esize: u8) -> i64 {
    let bits = 8u32 << esize;
    let sb = 64 - bits;
    ((v << sb) as i64) >> sb
}

#[inline]
fn fmt_of(esize: u8) -> Fmt {
    if esize == 3 {
        Fmt::D
    } else {
        Fmt::S
    }
}

pub(super) fn exec<E: Env>(cpu: &mut CpuState, env: &mut E, insn: Insn, word: u32) -> Step {
    match insn {
        Insn::SimdThree { q, u, size, op, rd, rn, rm, scalar } => {
            three_same(cpu, q, u, size, op, rd, rn, rm, scalar);
            Step::Next
        }
        Insn::SimdMisc { q, u, size, op, rd, rn, scalar } => {
            two_misc(cpu, q, u, size, op, rd, rn, scalar);
            Step::Next
        }
        Insn::SimdAcross { q, size, op, rd, rn } => {
            across(cpu, q, size, op, rd, rn);
            Step::Next
        }
        Insn::SimdDup { q, imm5, rd, rn, from_gpr } => {
            dup(cpu, q, imm5, rd, rn, from_gpr);
            Step::Next
        }
        Insn::SimdInsElt { imm5, imm4, rd, rn } => {
            ins_elt(cpu, imm5, imm4, rd, rn);
            Step::Next
        }
        Insn::SimdInsGpr { imm5, rd, rn } => {
            let (esize, idx) = elt_index(imm5);
            let mut v = cpu.vreg(rd);
            put_lane(&mut v, esize, idx, cpu.xr(rn));
            cpu.set_vreg(rd, v);
            Step::Next
        }
        Insn::SimdUmov { q, imm5, rd, rn } => {
            let (esize, idx) = elt_index(imm5);
            let _ = q;
            cpu.set_xr(rd, get_lane(cpu, rn, esize, idx));
            Step::Next
        }
        Insn::SimdSmov { q, imm5, rd, rn } => {
            let (esize, idx) = elt_index(imm5);
            let v = get_lane(cpu, rn, esize, idx);
            let s = sext(v, esize) as u64;
            cpu.set_xr(rd, if q { s } else { s & 0xffff_ffff });
            Step::Next
        }
        Insn::SimdScalarCopy { imm5, rd, rn } => {
            let (esize, idx) = elt_index(imm5);
            let v = get_lane(cpu, rn, esize, idx);
            let mut out = [0u64; 2];
            put_lane(&mut out, esize, 0, v);
            cpu.set_vreg(rd, out);
            Step::Next
        }
        Insn::SimdModImm { q, op, cmode, rd, imm, fp } => {
            mod_imm(cpu, q, op, cmode, rd, imm, fp);
            Step::Next
        }
        Insn::SimdShift { q, u, immh, immb, opcode, rd, rn, scalar } => {
            shift_imm(cpu, q, u, immh, immb, opcode, rd, rn, scalar);
            Step::Next
        }
        Insn::SimdExt { q, imm4, rd, rn, rm } => {
            ext(cpu, q, imm4, rd, rn, rm);
            Step::Next
        }
        Insn::SimdPermute { q, size, opcode, rd, rn, rm } => {
            permute(cpu, q, size, opcode, rd, rn, rm);
            Step::Next
        }
        Insn::SimdTbl { q, len, tbx, rd, rn, rm } => {
            tbl(cpu, q, len, tbx, rd, rn, rm);
            Step::Next
        }
        Insn::SimdIndexed { q, u, size, opcode, rd, rn, rm, index, scalar } => {
            if indexed(cpu, q, u, size, opcode, rd, rn, rm, index, scalar) {
                Step::Next
            } else {
                Step::Exit(Exit::Undefined(word))
            }
        }
        Insn::SimdLdSt { .. } => ldst_struct(cpu, env, insn),
        Insn::Aese { rd, rn } => {
            aes(cpu, rd, rn, false);
            Step::Next
        }
        Insn::Aesd { rd, rn } => {
            aes(cpu, rd, rn, true);
            Step::Next
        }
        Insn::Aesmc { rd, rn } => {
            aesmc(cpu, rd, rn, false);
            Step::Next
        }
        Insn::Aesimc { rd, rn } => {
            aesmc(cpu, rd, rn, true);
            Step::Next
        }
        Insn::Sha1 { op, rd, rn, rm } => {
            if sha1(cpu, op, rd, rn, rm) {
                Step::Next
            } else {
                Step::Exit(Exit::Undefined(word))
            }
        }
        Insn::Sha256 { op, rd, rn, rm } => {
            if sha256(cpu, op, rd, rn, rm) {
                Step::Next
            } else {
                Step::Exit(Exit::Undefined(word))
            }
        }
        _ => Step::Exit(Exit::Undefined(word)),
    }
}

/// Decode imm5 for element move: returns (esize, index).
fn elt_index(imm5: u32) -> (u8, u32) {
    if imm5 & 1 != 0 {
        (0, imm5 >> 1)
    } else if imm5 & 2 != 0 {
        (1, imm5 >> 2)
    } else if imm5 & 4 != 0 {
        (2, imm5 >> 3)
    } else {
        (3, imm5 >> 4)
    }
}

fn dup(cpu: &mut CpuState, q: bool, imm5: u32, rd: u32, rn: u32, from_gpr: bool) {
    let (esize, idx) = elt_index(imm5);
    let val = if from_gpr {
        cpu.xr(rn)
    } else {
        get_lane(cpu, rn, esize, idx)
    };
    let lanes = vbytes(q) >> esize;
    let mut out = [0u64; 2];
    for i in 0..lanes {
        put_lane(&mut out, esize, i, val);
    }
    cpu.set_vreg(rd, out);
}

fn ins_elt(cpu: &mut CpuState, imm5: u32, imm4: u32, rd: u32, rn: u32) {
    let (esize, didx) = elt_index(imm5);
    let sidx = imm4 >> esize;
    let v = get_lane(cpu, rn, esize, sidx);
    let mut out = cpu.vreg(rd);
    put_lane(&mut out, esize, didx, v);
    cpu.set_vreg(rd, out);
}

fn mod_imm(cpu: &mut CpuState, q: bool, op: u8, cmode: u8, rd: u32, imm: u64, _fp: bool) {
    // op/cmode selects MOVI / MVNI / ORR / BIC / FMOV. `imm` already carries
    // the expanded (MSL/replicated) pattern from adv_simd_expand_imm.
    let odd = cmode & 1 == 1;
    let is_bic_orr = odd && (cmode >> 1) <= 0b101; // cmode 0001..1011 odd
    let mut out;
    if is_bic_orr {
        let cur = cpu.vreg(rd);
        if op == 1 {
            // BIC (immediate): AND with NOT imm
            out = [cur[0] & !imm, cur[1] & !imm];
        } else {
            // ORR (immediate)
            out = [cur[0] | imm, cur[1] | imm];
        }
    } else if op == 1 && !(cmode == 0b1110) && !(cmode == 0b1111) {
        // MVNI (including cmode 110x MSL): bitwise-NOT of the pattern.
        out = [!imm, !imm];
    } else {
        // MOVI / FMOV / MOVI-64: use the pattern directly.
        out = [imm, imm];
    }
    if !q {
        out[1] = 0;
    }
    cpu.set_vreg(rd, out);
}

include!("simd_three.rs");
include!("simd_misc.rs");
include!("simd_shift.rs");
include!("simd_ldst.rs");
include!("simd_crypto.rs");

fn ext(cpu: &mut CpuState, q: bool, imm4: u32, rd: u32, rn: u32, rm: u32) {
    let n = vbytes(q);
    let mut bytes = [0u8; 16];
    for i in 0..n {
        let src = imm4 + i;
        let v = if src < n {
            get_lane(cpu, rn, 0, src)
        } else {
            get_lane(cpu, rm, 0, src - n)
        };
        bytes[i as usize] = v as u8;
    }
    let mut out = [0u64; 2];
    for i in 0..n {
        put_lane(&mut out, 0, i, bytes[i as usize] as u64);
    }
    cpu.set_vreg(rd, out);
}

fn permute(cpu: &mut CpuState, q: bool, size: u8, opcode: u8, rd: u32, rn: u32, rm: u32) {
    let esize = size;
    let lanes = vbytes(q) >> esize;
    let mut out = [0u64; 2];
    let pairs = lanes / 2;
    match opcode {
        0b001 | 0b101 => {
            // UZP1 (1) / UZP2 (5): pick even/odd lanes across n:m
            let start = if opcode == 0b101 { 1 } else { 0 };
            for i in 0..lanes {
                let srcidx = 2 * i + start;
                let v = if srcidx < lanes {
                    get_lane(cpu, rn, esize, srcidx)
                } else {
                    get_lane(cpu, rm, esize, srcidx - lanes)
                };
                put_lane(&mut out, esize, i, v);
            }
        }
        0b010 | 0b110 => {
            // TRN1 (2) / TRN2 (6)
            let start = if opcode == 0b110 { 1 } else { 0 };
            for i in 0..pairs {
                let a = get_lane(cpu, rn, esize, 2 * i + start);
                let b = get_lane(cpu, rm, esize, 2 * i + start);
                put_lane(&mut out, esize, 2 * i, a);
                put_lane(&mut out, esize, 2 * i + 1, b);
            }
        }
        0b011 | 0b111 => {
            // ZIP1 (3) / ZIP2 (7)
            let base = if opcode == 0b111 { pairs } else { 0 };
            for i in 0..pairs {
                let a = get_lane(cpu, rn, esize, base + i);
                let b = get_lane(cpu, rm, esize, base + i);
                put_lane(&mut out, esize, 2 * i, a);
                put_lane(&mut out, esize, 2 * i + 1, b);
            }
        }
        _ => {}
    }
    cpu.set_vreg(rd, out);
}

fn tbl(cpu: &mut CpuState, q: bool, len: u8, tbx: bool, rd: u32, rn: u32, rm: u32) {
    let n = vbytes(q);
    let table_regs = len + 1;
    let mut out = [0u64; 2];
    let orig = cpu.vreg(rd);
    for i in 0..n {
        let sel = get_lane(cpu, rm, 0, i) as u32;
        let reg = sel / 16;
        let lane = sel % 16;
        let byte = if reg < table_regs as u32 {
            get_lane(cpu, (rn + reg) & 31, 0, lane)
        } else if tbx {
            // keep existing
            let (word, sh) = if i >= 8 { (orig[1], (i - 8) * 8) } else { (orig[0], i * 8) };
            (word >> sh) & 0xff
        } else {
            0
        };
        put_lane(&mut out, 0, i, byte);
    }
    cpu.set_vreg(rd, out);
}

fn across(cpu: &mut CpuState, q: bool, size: u8, op: AcrossOp, rd: u32, rn: u32) {
    let esize = size;
    let lanes = vbytes(q) >> esize;
    let mut out = [0u64; 2];
    match op {
        AcrossOp::AddV => {
            let mut acc = 0u64;
            for i in 0..lanes {
                acc = acc.wrapping_add(get_lane(cpu, rn, esize, i));
            }
            put_lane(&mut out, esize, 0, acc);
        }
        AcrossOp::SAddLV | AcrossOp::UAddLV => {
            let mut acc = 0u64;
            for i in 0..lanes {
                let v = get_lane(cpu, rn, esize, i);
                acc = acc.wrapping_add(if matches!(op, AcrossOp::SAddLV) {
                    sext(v, esize) as u64
                } else {
                    v
                });
            }
            put_lane(&mut out, esize + 1, 0, acc);
        }
        AcrossOp::UMaxV | AcrossOp::SMaxV | AcrossOp::UMinV | AcrossOp::SMinV => {
            let signed = matches!(op, AcrossOp::SMaxV | AcrossOp::SMinV);
            let is_max = matches!(op, AcrossOp::UMaxV | AcrossOp::SMaxV);
            let mut acc = get_lane(cpu, rn, esize, 0);
            for i in 1..lanes {
                let v = get_lane(cpu, rn, esize, i);
                let take = if signed {
                    if is_max {
                        sext(v, esize) > sext(acc, esize)
                    } else {
                        sext(v, esize) < sext(acc, esize)
                    }
                } else if is_max {
                    v > acc
                } else {
                    v < acc
                };
                if take {
                    acc = v;
                }
            }
            put_lane(&mut out, esize, 0, acc);
        }
        AcrossOp::FMaxV | AcrossOp::FMinV | AcrossOp::FMaxNmV | AcrossOp::FMinNmV => {
            let f = fmt_of(esize);
            let mut c = sf::FpCtx::new(cpu.fpcr, cpu.fpsr);
            let mut acc = get_lane(cpu, rn, esize, 0);
            for i in 1..lanes {
                let v = get_lane(cpu, rn, esize, i);
                acc = match op {
                    AcrossOp::FMaxV => sf::max(&mut c, f, acc, v),
                    AcrossOp::FMinV => sf::min(&mut c, f, acc, v),
                    AcrossOp::FMaxNmV => sf::maxnum(&mut c, f, acc, v),
                    _ => sf::minnum(&mut c, f, acc, v),
                };
            }
            cpu.fpsr = c.fpsr & sf::FPSR_MASK;
            put_lane(&mut out, esize, 0, acc);
        }
    }
    cpu.set_vreg(rd, out);
}
