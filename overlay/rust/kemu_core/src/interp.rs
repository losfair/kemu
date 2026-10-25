// SPDX-License-Identifier: GPL-2.0
//! Reference AArch64 EL0 interpreter.
//!
//! This is the correctness oracle for kemu: it executes decoded instructions
//! against a [`CpuState`] and an [`Env`]. It is architecturally exact for the
//! advertised feature set and never panics on guest input.

use crate::decode::*;
use crate::env::{Access, Env, Fault};
use crate::softfloat as sf;
use crate::state::{CpuState, NZCV_C, NZCV_N, NZCV_V, NZCV_Z};
use crate::sysregs;

/// Reason the interpreter returned to its caller.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Exit {
    /// Instruction budget exhausted. `pc` points at the next instruction,
    /// which may be one that gave up before completing (a contended
    /// atomic) and must simply be executed again.
    Budget,
    /// `SVC` executed. `pc` already advanced past the `svc`.
    Svc,
    /// `BRK #imm`. `pc` points at the `brk`.
    Brk(u16),
    /// Undefined/unsupported instruction `word`. `pc` points at it; no effect.
    Undefined(u32),
    /// Memory (or misaligned-PC) fault. `pc` points at the faulting insn.
    Fault(Fault),
    /// `IC IVAU` to the given VA. `pc` has advanced.
    IcInvalidate(u64),
}

mod fp;
mod simd;

/// Run up to `max_insns` guest instructions.
pub fn run<E: Env>(cpu: &mut CpuState, env: &mut E, max_insns: u32) -> (Exit, u32) {
    let mut n = 0u32;
    while n < max_insns {
        if cpu.pc & 3 != 0 {
            return (Exit::Fault(Fault { addr: cpu.pc, access: Access::Exec, align: true }), n);
        }
        let word = match env.fetch(cpu.pc) {
            Ok(w) => w,
            Err(f) => return (Exit::Fault(f), n),
        };
        let insn = decode(word);
        match step(cpu, &mut crate::env::Tbi(&mut *env), insn, word) {
            Step::Next => {
                cpu.pc = cpu.pc.wrapping_add(4);
                n += 1;
            }
            Step::Branch(t) => {
                cpu.pc = t;
                n += 1;
            }
            Step::Exit(Exit::IcInvalidate(va)) => return (Exit::IcInvalidate(crate::env::untag(va)), n),
            Step::Exit(e) => return (e, n),
        }
    }
    (Exit::Budget, n)
}

enum Step {
    Next,
    Branch(u64),
    Exit(Exit),
}

#[inline]
fn mask_bits(sf64: bool) -> u64 {
    if sf64 {
        u64::MAX
    } else {
        0xffff_ffff
    }
}

#[inline]
fn trunc(v: u64, sf64: bool) -> u64 {
    v & mask_bits(sf64)
}

#[inline]
fn get_nzcv(cpu: &CpuState) -> (bool, bool, bool, bool) {
    (
        cpu.nzcv & NZCV_N != 0,
        cpu.nzcv & NZCV_Z != 0,
        cpu.nzcv & NZCV_C != 0,
        cpu.nzcv & NZCV_V != 0,
    )
}

#[inline]
fn set_nzcv(cpu: &mut CpuState, n: bool, z: bool, c: bool, v: bool) {
    let mut f = 0;
    if n {
        f |= NZCV_N;
    }
    if z {
        f |= NZCV_Z;
    }
    if c {
        f |= NZCV_C;
    }
    if v {
        f |= NZCV_V;
    }
    cpu.nzcv = f;
}

/// Evaluate an AArch64 condition code against the flags.
fn cond_holds(cpu: &CpuState, cond: u32) -> bool {
    let (n, z, c, v) = get_nzcv(cpu);
    let base = match cond >> 1 {
        0b000 => z,
        0b001 => c,
        0b010 => n,
        0b011 => v,
        0b100 => c && !z,
        0b101 => n == v,
        0b110 => (n == v) && !z,
        _ => true,
    };
    if cond & 1 != 0 && cond != 0b1111 {
        !base
    } else {
        base
    }
}

/// Add with carry, computing NZCV. Returns (result, n, z, c, v).
fn addc(a: u64, b: u64, carry: bool, sf64: bool) -> (u64, bool, bool, bool, bool) {
    if sf64 {
        let (s1, c1) = a.overflowing_add(b);
        let (s2, c2) = s1.overflowing_add(carry as u64);
        let res = s2;
        let carry_out = c1 || c2;
        let n = res >> 63 != 0;
        let z = res == 0;
        // Overflow: signs of a,b equal and differ from result.
        let v = (!(a ^ b) & (a ^ res)) >> 63 != 0;
        (res, n, z, carry_out, v)
    } else {
        let a = a & 0xffff_ffff;
        let b = b & 0xffff_ffff;
        let wide = a + b + carry as u64;
        let res = wide & 0xffff_ffff;
        let carry_out = wide >> 32 != 0;
        let n = res >> 31 != 0;
        let z = res == 0;
        let v = (!(a ^ b) & (a ^ res)) >> 31 != 0;
        (res, n, z, carry_out, v)
    }
}

fn step<E: Env>(cpu: &mut CpuState, env: &mut E, insn: Insn, word: u32) -> Step {
    match insn {
        Insn::Undefined | Insn::Hlt { .. } => Step::Exit(Exit::Undefined(word)),
        Insn::Nop | Insn::CacheNop | Insn::Prfm | Insn::Dmb | Insn::Dsb | Insn::Isb | Insn::Sb => Step::Next,
        Insn::MsrImm { op, .. } => {
            // FLAGM: CFINV (0), XAFLAG (1), AXFLAG (2).
            let (n, z, c, v) = get_nzcv(cpu);
            match op {
                0 => set_nzcv(cpu, n, z, !c, v),
                1 => set_nzcv(cpu, !c && !z, z && c, c || z, !c && z),
                2 => set_nzcv(cpu, false, z || v, c && !v, false),
                _ => return Step::Exit(Exit::Undefined(word)),
            }
            Step::Next
        }
        Insn::Clrex => {
            cpu.excl_addr = u64::MAX;
            Step::Next
        }
        Insn::Svc { .. } => {
            cpu.pc = cpu.pc.wrapping_add(4);
            Step::Exit(Exit::Svc)
        }
        Insn::Brk { imm } => Step::Exit(Exit::Brk(imm)),

        Insn::Adr { rd, imm } => {
            cpu.set_xr(rd, cpu.pc.wrapping_add(imm as u64));
            Step::Next
        }
        Insn::Adrp { rd, imm } => {
            let base = cpu.pc & !0xfff;
            cpu.set_xr(rd, base.wrapping_add(imm as u64));
            Step::Next
        }
        Insn::AddSubImm { sf, sub, setflags, rd, rn, imm } => {
            do_addsub(cpu, sf, sub, setflags, rd, rn, imm, true);
            Step::Next
        }
        Insn::LogicImm { sf, op, rd, rn, imm } => {
            do_logic(cpu, sf, op, false, rd, rn, trunc(imm, sf));
            Step::Next
        }
        Insn::MovN { sf, rd, imm } | Insn::MovZ { sf, rd, imm } => {
            cpu.set_xr(rd, trunc(imm, sf));
            Step::Next
        }
        Insn::MovK { sf, rd, shift, imm16 } => {
            let cur = cpu.xr(rd);
            let m = 0xffffu64 << shift;
            let v = (cur & !m) | (imm16 << shift);
            cpu.set_xr(rd, trunc(v, sf));
            Step::Next
        }
        Insn::Bitfield { sf, op, rd, rn, immr, imms } => {
            do_bitfield(cpu, sf, op, rd, rn, immr, imms);
            Step::Next
        }
        Insn::Extr { sf, rd, rn, rm, lsb } => {
            let width = if sf { 64 } else { 32 };
            let hi = trunc(cpu.xr(rn), sf);
            let lo = trunc(cpu.xr(rm), sf);
            let res = if lsb == 0 {
                lo
            } else {
                let combined = ((hi as u128) << width) | lo as u128;
                (combined >> lsb) as u64
            };
            cpu.set_xr(rd, trunc(res, sf));
            Step::Next
        }
        Insn::AddSubShift { sf, sub, setflags, shift, amount, rd, rn, rm } => {
            let op2 = shift_reg(cpu.xr(rm), shift, amount, sf);
            do_addsub(cpu, sf, sub, setflags, rd, rn, op2, false);
            Step::Next
        }
        Insn::AddSubExt { sf, sub, setflags, ext, amount, rd, rn, rm } => {
            let op2 = extend_reg(cpu.xr(rm), ext, amount);
            // rn/rd are SP-encoded here.
            let a = cpu.xsp(rn);
            let (res, n, z, c, v) = if sub {
                addc(trunc(a, sf), trunc(!op2, sf), true, sf)
            } else {
                addc(trunc(a, sf), trunc(op2, sf), false, sf)
            };
            if setflags {
                set_nzcv(cpu, n, z, c, v);
                cpu.set_xr(rd, trunc(res, sf));
            } else {
                cpu.set_xsp(rd, trunc(res, sf));
            }
            Step::Next
        }
        Insn::LogicShift { sf, op, negate, shift, amount, rd, rn, rm } => {
            let mut op2 = shift_reg(cpu.xr(rm), shift, amount, sf);
            if negate {
                op2 = !op2;
            }
            do_logic(cpu, sf, op, true, rd, rn, trunc(op2, sf));
            Step::Next
        }
        Insn::AddSubCarry { sf, sub, setflags, rd, rn, rm } => {
            let (_, _, c, _) = get_nzcv(cpu);
            let b = if sub { !cpu.xr(rm) } else { cpu.xr(rm) };
            let (res, n, z, co, v) = addc(trunc(cpu.xr(rn), sf), trunc(b, sf), c, sf);
            if setflags {
                set_nzcv(cpu, n, z, co, v);
            }
            cpu.set_xr(rd, trunc(res, sf));
            Step::Next
        }
        Insn::Rmif { rn, lsb, mask } => {
            let v = cpu.xr(rn).rotate_right(lsb);
            let (mut n, mut z, mut c, mut vv) = get_nzcv(cpu);
            let nv = v >> 3 & 1 != 0;
            let zv = v >> 2 & 1 != 0;
            let cv = v >> 1 & 1 != 0;
            let vvv = v & 1 != 0;
            if mask & 0b1000 != 0 {
                n = nv;
            }
            if mask & 0b0100 != 0 {
                z = zv;
            }
            if mask & 0b0010 != 0 {
                c = cv;
            }
            if mask & 0b0001 != 0 {
                vv = vvv;
            }
            set_nzcv(cpu, n, z, c, vv);
            Step::Next
        }
        Insn::SetfFlags { sz, rn } => {
            // SETF8/SETF16: N = reg<size-1>, Z = (reg<size-1:0> == 0),
            // V = reg<size> XOR reg<size-1>, C unchanged.
            let v = cpu.xr(rn);
            let bits = if sz == 0 { 8 } else { 16 };
            let n = (v >> (bits - 1)) & 1 != 0;
            let z = v & ((1u64 << bits) - 1) == 0;
            let vf = ((v >> bits) ^ (v >> (bits - 1))) & 1 != 0;
            let c = get_nzcv(cpu).2;
            set_nzcv(cpu, n, z, c, vf);
            Step::Next
        }
        Insn::CondCmp { sf, sub, reg, rn, imm_or_rm, nzcv, cond } => {
            if cond_holds(cpu, cond) {
                let b = if reg { cpu.xr(imm_or_rm) } else { imm_or_rm as u64 };
                let (_, n, z, c, v) = if sub {
                    addc(trunc(cpu.xr(rn), sf), trunc(!b, sf), true, sf)
                } else {
                    addc(trunc(cpu.xr(rn), sf), trunc(b, sf), false, sf)
                };
                set_nzcv(cpu, n, z, c, v);
            } else {
                set_nzcv(
                    cpu,
                    nzcv & 8 != 0,
                    nzcv & 4 != 0,
                    nzcv & 2 != 0,
                    nzcv & 1 != 0,
                );
            }
            Step::Next
        }
        Insn::CondSel { sf, op, rd, rn, rm, cond } => {
            let take = cond_holds(cpu, cond);
            let res = if take {
                cpu.xr(rn)
            } else {
                let m = cpu.xr(rm);
                match op {
                    CselOp::Csel => m,
                    CselOp::Csinc => m.wrapping_add(1),
                    CselOp::Csinv => !m,
                    CselOp::Csneg => (!m).wrapping_add(1),
                }
            };
            cpu.set_xr(rd, trunc(res, sf));
            Step::Next
        }
        Insn::Dp1 { sf, op, rd, rn } => {
            let v = trunc(cpu.xr(rn), sf);
            let res = match op {
                Dp1Op::Rbit => {
                    let r = v.reverse_bits();
                    if sf {
                        r
                    } else {
                        r >> 32
                    }
                }
                Dp1Op::Rev16 => rev_bytes_in_chunks(v, 2, sf),
                Dp1Op::Rev32 => rev_bytes_in_chunks(v, 4, sf),
                Dp1Op::Rev => {
                    if sf {
                        v.swap_bytes()
                    } else {
                        (v as u32).swap_bytes() as u64
                    }
                }
                Dp1Op::Clz => {
                    if sf {
                        v.leading_zeros() as u64
                    } else {
                        (v as u32).leading_zeros() as u64
                    }
                }
                Dp1Op::Cls => cls(v, sf) as u64,
            };
            cpu.set_xr(rd, trunc(res, sf));
            Step::Next
        }
        Insn::Dp2 { sf, op, rd, rn, rm, crc_sz } => {
            do_dp2(cpu, sf, op, rd, rn, rm, crc_sz);
            Step::Next
        }
        Insn::Mul { op, rd, rn, rm, ra } => {
            // Only MADD/MSUB have a 32-bit (sf=0) form; the long/high ops
            // always have bit31=1, so reading it here is correct for all.
            let sf = (word >> 31) & 1 != 0;
            do_mul(cpu, sf, op, rd, rn, rm, ra);
            Step::Next
        }

        // --- branches ---
        Insn::B { imm } => Step::Branch(cpu.pc.wrapping_add(imm as u64)),
        Insn::Bl { imm } => {
            cpu.set_xr(30, cpu.pc.wrapping_add(4));
            Step::Branch(cpu.pc.wrapping_add(imm as u64))
        }
        Insn::BCond { cond, imm } => {
            if cond_holds(cpu, cond) {
                Step::Branch(cpu.pc.wrapping_add(imm as u64))
            } else {
                Step::Next
            }
        }
        Insn::Cbz { sf, nz, rt, imm } => {
            let v = trunc(cpu.xr(rt), sf);
            if (v == 0) != nz {
                Step::Branch(cpu.pc.wrapping_add(imm as u64))
            } else {
                Step::Next
            }
        }
        Insn::Tbz { bit, nz, rt, imm } => {
            let set = (cpu.xr(rt) >> (bit & 63)) & 1 != 0;
            if set == nz {
                Step::Branch(cpu.pc.wrapping_add(imm as u64))
            } else {
                Step::Next
            }
        }
        Insn::Br { rn } => Step::Branch(cpu.xr(rn)),
        Insn::Blr { rn } => {
            let t = cpu.xr(rn);
            cpu.set_xr(30, cpu.pc.wrapping_add(4));
            Step::Branch(t)
        }
        Insn::Ret { rn } => Step::Branch(cpu.xr(rn)),

        // --- memory ---
        Insn::LdSt { .. }
        | Insn::LdStReg { .. }
        | Insn::LdStPair { .. }
        | Insn::LdStLiteral { .. } => mem::exec_ldst(cpu, env, insn),
        Insn::LdStExcl { .. } => mem::exec_excl(cpu, env, insn),
        Insn::Atomic { .. } => mem::exec_atomic(cpu, env, insn),
        Insn::Cas { .. } => mem::exec_cas(cpu, env, insn),
        Insn::DcZva { rt } => mem::exec_dc_zva(cpu, env, rt),
        Insn::IcIvau { rt } => {
            // Exit::IcInvalidate is reported with the PC already advanced.
            let addr = cpu.xr(rt);
            cpu.pc = cpu.pc.wrapping_add(4);
            Step::Exit(Exit::IcInvalidate(addr))
        }

        // --- system registers ---
        Insn::Mrs { rt, enc } => {
            // RNDR / RNDRRS also set NZCV (0b0000 success, 0b0100 failure).
            if enc == e(3, 3, 2, 4, 0) || enc == e(3, 3, 2, 4, 1) {
                match env.random() {
                    Some(v) => {
                        cpu.set_xr(rt, v);
                        set_nzcv(cpu, false, false, false, false);
                    }
                    None => {
                        cpu.set_xr(rt, 0);
                        set_nzcv(cpu, false, true, false, false);
                    }
                }
                return Step::Next;
            }
            match read_sysreg(cpu, env, enc) {
                Some(v) => {
                    cpu.set_xr(rt, v);
                    Step::Next
                }
                None => Step::Exit(Exit::Undefined(word)),
            }
        }
        Insn::MsrReg { rt, enc } => {
            if write_sysreg(cpu, enc, cpu.xr(rt)) {
                Step::Next
            } else {
                Step::Exit(Exit::Undefined(word))
            }
        }

        // --- floating point & SIMD ---
        Insn::FpImm { .. }
        | Insn::FpCmp { .. }
        | Insn::FpCCmp { .. }
        | Insn::FpCSel { .. }
        | Insn::Fp1 { .. }
        | Insn::Fp2 { .. }
        | Insn::Fp3 { .. }
        | Insn::FpCvt { .. } => fp::exec(cpu, insn, word),

        _ => simd::exec(cpu, env, insn, word),
    }
}

fn do_addsub(cpu: &mut CpuState, sf: bool, sub: bool, setflags: bool, rd: u32, rn: u32, imm: u64, sp_form: bool) {
    // For add/sub (immediate), Rn is always SP-encoded (even for the
    // flag-setting ADDS/SUBS/CMP/CMN forms); only Rd is ZR-encoded.
    let a = if sp_form {
        cpu.xsp(rn)
    } else {
        cpu.xr(rn)
    };
    let (res, n, z, c, v) = if sub {
        addc(trunc(a, sf), trunc(!imm, sf), true, sf)
    } else {
        addc(trunc(a, sf), trunc(imm, sf), false, sf)
    };
    if setflags {
        set_nzcv(cpu, n, z, c, v);
        cpu.set_xr(rd, trunc(res, sf));
    } else if sp_form {
        cpu.set_xsp(rd, trunc(res, sf));
    } else {
        cpu.set_xr(rd, trunc(res, sf));
    }
}

fn do_logic(cpu: &mut CpuState, sf: bool, op: LogicOp, _shifted: bool, rd: u32, rn: u32, op2: u64) {
    let a = cpu.xr(rn);
    let res = match op {
        LogicOp::And | LogicOp::Ands => a & op2,
        LogicOp::Orr => a | op2,
        LogicOp::Eor => a ^ op2,
    };
    let res = trunc(res, sf);
    if op == LogicOp::Ands {
        let n = res >> (if sf { 63 } else { 31 }) & 1 != 0;
        set_nzcv(cpu, n, res == 0, false, false);
        cpu.set_xr(rd, res);
    } else if _shifted {
        // Logical (shifted register) non-flag forms use XZR for rd==31.
        cpu.set_xr(rd, res);
    } else {
        // Logical (immediate) non-flag forms use SP for rd==31.
        cpu.set_xsp(rd, res);
    }
}

fn do_bitfield(cpu: &mut CpuState, sf: bool, op: BfOp, rd: u32, rn: u32, immr: u32, imms: u32) {
    // Canonical ARM BFM/SBFM/UBFM, with DecodeBitMasks(immediate = FALSE).
    let d = if sf { 64u32 } else { 32 };
    let src = trunc(cpu.xr(rn), sf);
    let r = immr & (d - 1);
    let s = imms & (d - 1);
    let welem = ones(s + 1);
    let wmask = ror_in(welem, r, d);
    let diff = s.wrapping_sub(r) & (d - 1);
    let tmask = ones(diff + 1);
    let ror_src = ror_in(src, r, d);
    let dst = trunc(cpu.xr(rd), sf);
    let (top, bot) = match op {
        BfOp::Unsigned => (0u64, ror_src & wmask),
        BfOp::Signed => {
            let signbit = (src >> s) & 1;
            let top = if signbit != 0 { u64::MAX } else { 0 };
            (top, ror_src & wmask)
        }
        BfOp::Insert => (dst, (dst & !wmask) | (ror_src & wmask)),
    };
    let res = (top & !tmask) | (bot & tmask);
    cpu.set_xr(rd, trunc(res, sf));
}

/// Low `n` bits set (n may be 0..=64).
#[inline]
fn ones(n: u32) -> u64 {
    if n == 0 {
        0
    } else if n >= 64 {
        u64::MAX
    } else {
        (1u64 << n) - 1
    }
}

/// Rotate `v` right by `r` within the low `width` bits.
#[inline]
fn ror_in(v: u64, r: u32, width: u32) -> u64 {
    let m = if width >= 64 { u64::MAX } else { (1u64 << width) - 1 };
    let v = v & m;
    let r = r % width;
    if r == 0 {
        v
    } else {
        ((v >> r) | (v << (width - r))) & m
    }
}

fn shift_reg(v: u64, shift: Shift, amount: u32, sf: bool) -> u64 {
    let width = if sf { 64 } else { 32 };
    let a = amount % width;
    let v = trunc(v, sf);
    match shift {
        Shift::Lsl => {
            if a == 0 {
                v
            } else {
                trunc(v << a, sf)
            }
        }
        Shift::Lsr => {
            if a == 0 {
                v
            } else {
                v >> a
            }
        }
        Shift::Asr => {
            if sf {
                ((v as i64) >> a) as u64
            } else {
                (((v as u32) as i32) >> a) as u32 as u64
            }
        }
        Shift::Ror => {
            if sf {
                v.rotate_right(a)
            } else {
                (v as u32).rotate_right(a) as u64
            }
        }
    }
}

fn extend_reg(v: u64, ext: Ext, shift: u32) -> u64 {
    let bits = ext.src_bits();
    let masked = if bits >= 64 { v } else { v & ((1u64 << bits) - 1) };
    let extended = if ext.signed() && bits < 64 {
        let sb = 64 - bits;
        (((masked << sb) as i64) >> sb) as u64
    } else {
        masked
    };
    extended.wrapping_shl(shift)
}

fn rev_bytes_in_chunks(v: u64, chunk: u32, sf: bool) -> u64 {
    let width = if sf { 64 } else { 32 };
    let mut out = 0u64;
    let mut i = 0;
    while i < width {
        // reverse bytes within each `chunk`-byte container
        let mut b = 0u64;
        let mut j = 0;
        while j < chunk {
            let byte = (v >> ((i + j * 8) )) & 0xff;
            b |= byte << (i + (chunk - 1 - j) * 8);
            j += 1;
        }
        out |= b;
        i += chunk * 8;
    }
    out
}

fn cls(v: u64, sf: bool) -> u32 {
    let (v, width) = if sf { (v, 64u32) } else { (v & 0xffff_ffff, 32) };
    let top = (v >> (width - 1)) & 1;
    let x = if top != 0 { !v } else { v };
    let x = if sf { x } else { x & 0xffff_ffff };
    let lead = if sf {
        x.leading_zeros()
    } else {
        (x as u32).leading_zeros()
    };
    lead.saturating_sub(1)
}

fn do_dp2(cpu: &mut CpuState, sf: bool, op: Dp2Op, rd: u32, rn: u32, rm: u32, crc_sz: u8) {
    let a = cpu.xr(rn);
    let b = cpu.xr(rm);
    let res = match op {
        Dp2Op::Udiv => {
            let (x, y) = (trunc(a, sf), trunc(b, sf));
            if y == 0 {
                0
            } else {
                x / y
            }
        }
        Dp2Op::Sdiv => {
            if sf {
                let (x, y) = (a as i64, b as i64);
                if y == 0 {
                    0
                } else if x == i64::MIN && y == -1 {
                    i64::MIN as u64
                } else {
                    (x / y) as u64
                }
            } else {
                let (x, y) = (a as i32, b as i32);
                if y == 0 {
                    0
                } else if x == i32::MIN && y == -1 {
                    i32::MIN as u32 as u64
                } else {
                    (x / y) as u32 as u64
                }
            }
        }
        Dp2Op::Lslv => shift_reg(a, Shift::Lsl, (b & if sf { 63 } else { 31 }) as u32, sf),
        Dp2Op::Lsrv => shift_reg(a, Shift::Lsr, (b & if sf { 63 } else { 31 }) as u32, sf),
        Dp2Op::Asrv => shift_reg(a, Shift::Asr, (b & if sf { 63 } else { 31 }) as u32, sf),
        Dp2Op::Rorv => shift_reg(a, Shift::Ror, (b & if sf { 63 } else { 31 }) as u32, sf),
        Dp2Op::Crc32 => crc32(a as u32, b, crc_sz, false),
        Dp2Op::Crc32c => crc32(a as u32, b, crc_sz, true),
    };
    cpu.set_xr(rd, trunc(res, sf));
}

fn crc32(acc: u32, data: u64, sz: u8, castagnoli: bool) -> u64 {
    let poly: u32 = if castagnoli { 0x82f6_3b78 } else { 0xedb8_8320 };
    let mut crc = acc;
    let nbytes = 1usize << sz;
    for i in 0..nbytes {
        let byte = ((data >> (i * 8)) & 0xff) as u32;
        crc ^= byte;
        for _ in 0..8 {
            let m = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (poly & m);
        }
    }
    crc as u64
}

fn do_mul(cpu: &mut CpuState, sf: bool, op: MulOp, rd: u32, rn: u32, rm: u32, ra: u32) {
    let res = match op {
        MulOp::Madd => trunc(cpu.xr(ra).wrapping_add(cpu.xr(rn).wrapping_mul(cpu.xr(rm))), sf),
        MulOp::Msub => trunc(cpu.xr(ra).wrapping_sub(cpu.xr(rn).wrapping_mul(cpu.xr(rm))), sf),
        MulOp::Smaddl => {
            let p = (cpu.xr(rn) as i32 as i64).wrapping_mul(cpu.xr(rm) as i32 as i64);
            (cpu.xr(ra) as i64).wrapping_add(p) as u64
        }
        MulOp::Smsubl => {
            let p = (cpu.xr(rn) as i32 as i64).wrapping_mul(cpu.xr(rm) as i32 as i64);
            (cpu.xr(ra) as i64).wrapping_sub(p) as u64
        }
        MulOp::Umaddl => {
            let p = (cpu.xr(rn) as u32 as u64).wrapping_mul(cpu.xr(rm) as u32 as u64);
            cpu.xr(ra).wrapping_add(p)
        }
        MulOp::Umsubl => {
            let p = (cpu.xr(rn) as u32 as u64).wrapping_mul(cpu.xr(rm) as u32 as u64);
            cpu.xr(ra).wrapping_sub(p)
        }
        MulOp::Smulh => {
            let p = (cpu.xr(rn) as i64 as i128).wrapping_mul(cpu.xr(rm) as i64 as i128);
            (p >> 64) as u64
        }
        MulOp::Umulh => {
            let p = (cpu.xr(rn) as u128).wrapping_mul(cpu.xr(rm) as u128);
            (p >> 64) as u64
        }
    };
    cpu.set_xr(rd, res);
}

fn read_sysreg<E: Env>(cpu: &CpuState, env: &mut E, enc: u32) -> Option<u64> {
    Some(match enc {
        // op0=3,op1=3,crn=13,crm=0,op2=2 TPIDR_EL0
        _ if enc == e(3, 3, 13, 0, 2) => cpu.tpidr,
        _ if enc == e(3, 3, 13, 0, 3) => cpu.tpidrro,
        _ if enc == e(3, 3, 4, 2, 0) => cpu.nzcv,
        _ if enc == e(3, 3, 4, 4, 0) => cpu.fpcr as u64,
        _ if enc == e(3, 3, 4, 4, 1) => cpu.fpsr as u64,
        _ if enc == e(3, 3, 14, 0, 2) => env.cntvct(), // CNTVCT_EL0
        _ if enc == e(3, 3, 14, 0, 0) => env.cntfrq(),  // CNTFRQ_EL0
        _ if enc == e(3, 3, 14, 0, 5) => env.cntvct(),  // CNTVCTSS_EL0
        _ if enc == e(3, 3, 0, 0, 1) => sysregs::CTR_EL0,
        _ if enc == e(3, 3, 0, 0, 7) => sysregs::DCZID_EL0,
        _ if enc == e(3, 0, 0, 0, 0) => sysregs::MIDR_EL1,
        _ if enc == e(3, 0, 0, 0, 5) => sysregs::MPIDR_EL1,
        _ if enc == e(3, 0, 0, 0, 6) => sysregs::REVIDR_EL1,
        _ if enc == e(3, 0, 0, 4, 0) => sysregs::ID_AA64PFR0_EL1,
        _ if enc == e(3, 0, 0, 4, 1) => sysregs::ID_AA64PFR1_EL1,
        _ if enc == e(3, 0, 0, 4, 4) => sysregs::ID_AA64ZFR0_EL1,
        _ if enc == e(3, 0, 0, 5, 0) => sysregs::ID_AA64DFR0_EL1,
        _ if enc == e(3, 0, 0, 5, 1) => sysregs::ID_AA64DFR1_EL1,
        _ if enc == e(3, 0, 0, 5, 4) => sysregs::ID_AA64AFR0_EL1,
        _ if enc == e(3, 0, 0, 5, 5) => sysregs::ID_AA64AFR1_EL1,
        _ if enc == e(3, 0, 0, 6, 0) => sysregs::ID_AA64ISAR0_EL1,
        _ if enc == e(3, 0, 0, 6, 1) => sysregs::ID_AA64ISAR1_EL1,
        _ if enc == e(3, 0, 0, 6, 2) => sysregs::ID_AA64ISAR2_EL1,
        _ if enc == e(3, 0, 0, 7, 0) => sysregs::ID_AA64MMFR0_EL1,
        _ if enc == e(3, 0, 0, 7, 1) => sysregs::ID_AA64MMFR1_EL1,
        _ if enc == e(3, 0, 0, 7, 2) => sysregs::ID_AA64MMFR2_EL1,
        // Linux emulates every other ID register in op0=3, op1=0, CRn=0,
        // CRm=2..7 as RAZ (reserved, untracked or AArch32 ID registers).
        _ if enc >> 7 == (3 << 7) && (2..=7).contains(&((enc >> 3) & 15)) => 0,
        // RNDR / RNDRRS: op0=3,op1=3,crn=2,crm=4,op2=0/1
        _ if enc == e(3, 3, 2, 4, 0) || enc == e(3, 3, 2, 4, 1) => {
            // handled specially by caller for NZCV; here return value or 0.
            return env.random().or(Some(0));
        }
        _ => return None,
    })
}

#[inline]
const fn e(op0: u32, op1: u32, crn: u32, crm: u32, op2: u32) -> u32 {
    (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2
}

fn write_sysreg(cpu: &mut CpuState, enc: u32, val: u64) -> bool {
    if enc == e(3, 3, 13, 0, 2) {
        cpu.tpidr = val;
    } else if enc == e(3, 3, 4, 2, 0) {
        cpu.nzcv = val & 0xf000_0000;
    } else if enc == e(3, 3, 4, 4, 0) {
        cpu.fpcr = (val as u32) & sf::FPCR_MASK;
    } else if enc == e(3, 3, 4, 4, 1) {
        cpu.fpsr = (val as u32) & sf::FPSR_MASK;
    } else {
        return false;
    }
    true
}

mod mem;

#[cfg(test)]
mod tests;
