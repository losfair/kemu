// SPDX-License-Identifier: GPL-2.0
// Advanced SIMD (NEON) execution, following the Arm A64 ASL operation
// pseudocode. Each V register is two u64 halves (little-endian lanes).
// Saturating operations set FPSR.QC.

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

#[inline]
fn lmask(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

/// Lane `i` of size `esize` (log2 bytes) of a vector value.
#[inline]
fn lane(v: &[u64; 2], esize: u8, i: u32) -> u64 {
    let bits = 8u32 << esize;
    let off = i * bits;
    if off >= 128 {
        return 0;
    }
    let (word, shift) = if off >= 64 { (v[1], off - 64) } else { (v[0], off) };
    (word >> shift) & lmask(bits)
}

/// Read lane `i` of size `esize` from register `r`.
fn get_lane(cpu: &CpuState, r: u32, esize: u8, i: u32) -> u64 {
    lane(&cpu.vreg(r), esize, i)
}

/// Insert `val` into lane `i` of size `esize` in a [u64;2] vector.
fn put_lane(vec: &mut [u64; 2], esize: u8, i: u32, val: u64) {
    let bits = 8u32 << esize;
    let off = i * bits;
    if off >= 128 {
        return;
    }
    let mask = lmask(bits);
    let (idx, shift) = if off >= 64 { (1usize, off - 64) } else { (0usize, off) };
    vec[idx] = (vec[idx] & !(mask << shift)) | ((val & mask) << shift);
}

/// Sign-extend the low 8<<esize bits of `v`.
#[inline]
fn sext(v: u64, esize: u8) -> i64 {
    let bits = 8u32 << esize;
    if bits >= 64 {
        return v as i64;
    }
    let sb = 64 - bits;
    ((v << sb) as i64) >> sb
}

/// Signed or unsigned value of a lane as i128.
#[inline]
fn ival(v: u64, esize: u8, signed: bool) -> i128 {
    if signed {
        sext(v, esize) as i128
    } else {
        (v & lmask(8 << esize)) as i128
    }
}

/// SignedSatQ: saturate to a `bits`-bit signed integer (returned masked).
#[inline]
fn sat_s(v: i128, bits: u32, qc: &mut bool) -> u64 {
    let bits = bits.clamp(1, 64);
    let max = (1i128 << (bits - 1)) - 1;
    let min = -(1i128 << (bits - 1));
    let r = if v > max {
        *qc = true;
        max
    } else if v < min {
        *qc = true;
        min
    } else {
        v
    };
    (r as u64) & lmask(bits)
}

/// UnsignedSatQ: saturate to a `bits`-bit unsigned integer.
#[inline]
fn sat_u(v: i128, bits: u32, qc: &mut bool) -> u64 {
    let bits = bits.min(64);
    let max = (1i128 << bits) - 1;
    if v > max {
        *qc = true;
        max as u64
    } else if v < 0 {
        *qc = true;
        0
    } else {
        v as u64
    }
}

/// SatQ with signedness selected at runtime.
#[inline]
fn sat(v: i128, bits: u32, unsigned: bool, qc: &mut bool) -> u64 {
    if unsigned {
        sat_u(v, bits, qc)
    } else {
        sat_s(v, bits, qc)
    }
}

#[inline]
fn bool_lane(c: bool) -> u64 {
    if c {
        u64::MAX
    } else {
        0
    }
}

#[inline]
fn fmt_of(esize: u8) -> Fmt {
    if esize == 3 {
        Fmt::D
    } else {
        Fmt::S
    }
}

#[inline]
fn set_qc(cpu: &mut CpuState, qc: bool) {
    if qc {
        cpu.fpsr |= sf::FPSR_QC;
    }
}

/// Write a vector result, clearing the upper half for 64-bit operations.
#[inline]
fn write_vec(cpu: &mut CpuState, rd: u32, q: bool, mut v: [u64; 2]) {
    if !q {
        v[1] = 0;
    }
    cpu.set_vreg(rd, v);
}

/// Write a narrowing result (64 bits) to the lower or upper half of Vd.
#[inline]
fn write_part(cpu: &mut CpuState, rd: u32, upper: bool, half: u64) {
    if upper {
        let mut v = cpu.vreg(rd);
        v[1] = half;
        cpu.set_vreg(rd, v);
    } else {
        cpu.set_vreg(rd, [half, 0]);
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
            let (esize, didx) = elt_index(imm5);
            let v = get_lane(cpu, rn, esize, imm4 >> esize);
            let mut out = cpu.vreg(rd);
            put_lane(&mut out, esize, didx, v);
            cpu.set_vreg(rd, out);
            Step::Next
        }
        Insn::SimdInsGpr { imm5, rd, rn } => {
            let (esize, idx) = elt_index(imm5);
            let mut v = cpu.vreg(rd);
            put_lane(&mut v, esize, idx, cpu.xr(rn));
            cpu.set_vreg(rd, v);
            Step::Next
        }
        Insn::SimdUmov { q: _, imm5, rd, rn } => {
            let (esize, idx) = elt_index(imm5);
            cpu.set_xr(rd, get_lane(cpu, rn, esize, idx));
            Step::Next
        }
        Insn::SimdSmov { q, imm5, rd, rn } => {
            let (esize, idx) = elt_index(imm5);
            let s = sext(get_lane(cpu, rn, esize, idx), esize) as u64;
            cpu.set_xr(rd, if q { s } else { s & 0xffff_ffff });
            Step::Next
        }
        Insn::SimdScalarCopy { imm5, rd, rn } => {
            let (esize, idx) = elt_index(imm5);
            let mut out = [0u64; 2];
            put_lane(&mut out, esize, 0, get_lane(cpu, rn, esize, idx));
            cpu.set_vreg(rd, out);
            Step::Next
        }
        Insn::SimdModImm { q, op, cmode, rd, imm, fp: _ } => {
            mod_imm(cpu, q, op, cmode, rd, imm);
            Step::Next
        }
        Insn::SimdShift { q, u, immh, immb, opcode, rd, rn, scalar } => {
            if shift_imm(cpu, q, u, immh, immb, opcode, rd, rn, scalar) {
                Step::Next
            } else {
                Step::Exit(Exit::Undefined(word))
            }
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

/// Decode imm5 for element moves: returns (esize, index).
fn elt_index(imm5: u32) -> (u8, u32) {
    if imm5 & 1 != 0 {
        (0, (imm5 >> 1) & 15)
    } else if imm5 & 2 != 0 {
        (1, (imm5 >> 2) & 7)
    } else if imm5 & 4 != 0 {
        (2, (imm5 >> 3) & 3)
    } else {
        (3, (imm5 >> 4) & 1)
    }
}

fn dup(cpu: &mut CpuState, q: bool, imm5: u32, rd: u32, rn: u32, from_gpr: bool) {
    let (esize, idx) = elt_index(imm5);
    let val = if from_gpr { cpu.xr(rn) } else { get_lane(cpu, rn, esize, idx) };
    let lanes = vbytes(q) >> esize;
    let mut out = [0u64; 2];
    for i in 0..lanes {
        put_lane(&mut out, esize, i, val);
    }
    cpu.set_vreg(rd, out);
}

fn mod_imm(cpu: &mut CpuState, q: bool, op: u8, cmode: u8, rd: u32, imm: u64) {
    // `imm` is AdvSIMDExpandImm(op, cmode, imm8) (64-bit pattern).
    let orr_bic = cmode & 1 == 1 && cmode < 0b1100;
    let out = if orr_bic {
        let cur = cpu.vreg(rd);
        if op == 1 {
            [cur[0] & !imm, cur[1] & !imm] // BIC
        } else {
            [cur[0] | imm, cur[1] | imm] // ORR
        }
    } else if op == 1 && cmode < 0b1110 {
        [!imm, !imm] // MVNI
    } else {
        [imm, imm] // MOVI / FMOV
    };
    write_vec(cpu, rd, q, out);
}

include!("simd_three.rs");
include!("simd_misc.rs");
include!("simd_shift.rs");
include!("simd_ldst.rs");
include!("simd_crypto.rs");

fn ext(cpu: &mut CpuState, q: bool, imm4: u32, rd: u32, rn: u32, rm: u32) {
    let n = vbytes(q);
    let (a, b) = (cpu.vreg(rn), cpu.vreg(rm));
    let mut out = [0u64; 2];
    for i in 0..n {
        let src = imm4 + i;
        let v = if src < n { lane(&a, 0, src) } else { lane(&b, 0, src - n) };
        put_lane(&mut out, 0, i, v);
    }
    cpu.set_vreg(rd, out);
}

fn permute(cpu: &mut CpuState, q: bool, size: u8, opcode: u8, rd: u32, rn: u32, rm: u32) {
    let esize = size;
    let lanes = vbytes(q) >> esize;
    let pairs = lanes / 2;
    let (a, b) = (cpu.vreg(rn), cpu.vreg(rm));
    let part = (opcode >> 2) as u32; // 0 for *1, 1 for *2
    let mut out = [0u64; 2];
    match opcode & 3 {
        0b01 => {
            // UZP1/UZP2: even/odd elements of the concatenation Vm:Vn.
            for i in 0..lanes {
                let s = 2 * i + part;
                let v = if s < lanes { lane(&a, esize, s) } else { lane(&b, esize, s - lanes) };
                put_lane(&mut out, esize, i, v);
            }
        }
        0b10 => {
            // TRN1/TRN2
            for p in 0..pairs {
                put_lane(&mut out, esize, 2 * p, lane(&a, esize, 2 * p + part));
                put_lane(&mut out, esize, 2 * p + 1, lane(&b, esize, 2 * p + part));
            }
        }
        _ => {
            // ZIP1/ZIP2
            let base = part * pairs;
            for p in 0..pairs {
                put_lane(&mut out, esize, 2 * p, lane(&a, esize, base + p));
                put_lane(&mut out, esize, 2 * p + 1, lane(&b, esize, base + p));
            }
        }
    }
    cpu.set_vreg(rd, out);
}

fn tbl(cpu: &mut CpuState, q: bool, len: u8, tbx: bool, rd: u32, rn: u32, rm: u32) {
    let n = vbytes(q);
    let regs = len as u32 + 1;
    let idxv = cpu.vreg(rm);
    let orig = cpu.vreg(rd);
    let mut out = [0u64; 2];
    for i in 0..n {
        let sel = lane(&idxv, 0, i) as u32;
        let byte = if sel < 16 * regs {
            get_lane(cpu, (rn + sel / 16) & 31, 0, sel % 16)
        } else if tbx {
            lane(&orig, 0, i)
        } else {
            0
        };
        put_lane(&mut out, 0, i, byte);
    }
    cpu.set_vreg(rd, out);
}

/// FP Reduce(): recursive halving, op(lo, hi).
fn fp_reduce(c: &mut sf::FpCtx, f: Fmt, op: AcrossOp, v: &[u64; 2], esize: u8, lo: u32, n: u32) -> u64 {
    if n == 1 {
        return lane(v, esize, lo);
    }
    let h = n / 2;
    let a = fp_reduce(c, f, op, v, esize, lo, h);
    let b = fp_reduce(c, f, op, v, esize, lo + h, h);
    match op {
        AcrossOp::FMaxV | AcrossOp::FMaxP => sf::max(c, f, a, b),
        AcrossOp::FMinV | AcrossOp::FMinP => sf::min(c, f, a, b),
        AcrossOp::FMaxNmV | AcrossOp::FMaxNmP => sf::maxnum(c, f, a, b),
        AcrossOp::FMinNmV | AcrossOp::FMinNmP => sf::minnum(c, f, a, b),
        _ => sf::add(c, f, a, b),
    }
}

fn across(cpu: &mut CpuState, q: bool, size: u8, op: AcrossOp, rd: u32, rn: u32) {
    let esize = size;
    let lanes = vbytes(q) >> esize;
    let v = cpu.vreg(rn);
    let mut out = [0u64; 2];
    match op {
        AcrossOp::AddV | AcrossOp::AddP => {
            let mut acc = 0u64;
            for i in 0..lanes {
                acc = acc.wrapping_add(lane(&v, esize, i));
            }
            put_lane(&mut out, esize, 0, acc);
        }
        AcrossOp::SAddLV | AcrossOp::UAddLV => {
            let signed = op == AcrossOp::SAddLV;
            let mut acc = 0i128;
            for i in 0..lanes {
                acc += ival(lane(&v, esize, i), esize, signed);
            }
            put_lane(&mut out, esize + 1, 0, acc as u64);
        }
        AcrossOp::UMaxV | AcrossOp::SMaxV | AcrossOp::UMinV | AcrossOp::SMinV => {
            let signed = matches!(op, AcrossOp::SMaxV | AcrossOp::SMinV);
            let is_max = matches!(op, AcrossOp::UMaxV | AcrossOp::SMaxV);
            let mut acc = ival(lane(&v, esize, 0), esize, signed);
            for i in 1..lanes {
                let x = ival(lane(&v, esize, i), esize, signed);
                if (is_max && x > acc) || (!is_max && x < acc) {
                    acc = x;
                }
            }
            put_lane(&mut out, esize, 0, acc as u64);
        }
        _ => {
            let f = fmt_of(esize);
            let mut c = sf::FpCtx::new(cpu.fpcr, cpu.fpsr);
            let r = fp_reduce(&mut c, f, op, &v, esize, 0, lanes);
            cpu.fpsr = c.fpsr & sf::FPSR_MASK;
            put_lane(&mut out, esize, 0, r);
        }
    }
    cpu.set_vreg(rd, out);
}
