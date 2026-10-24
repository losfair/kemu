// SPDX-License-Identifier: GPL-2.0
// Scalar floating-point execution.

use super::{cond_holds, set_nzcv, Exit, Step};
use crate::decode::{FcvtOp, Fp1Op, Fp2Op, Insn};
use crate::softfloat::{self as sf, Fmt, Rounding};
use crate::state::CpuState;

/// Format for an ftype field (00=S, 01=D, 11=H).
fn ftype_fmt(ft: u8) -> Option<Fmt> {
    match ft {
        0b00 => Some(Fmt::S),
        0b01 => Some(Fmt::D),
        0b11 => Some(Fmt::H),
        _ => None,
    }
}

/// Read the scalar FP value from Vn (low bits per format).
fn readf(cpu: &CpuState, n: u32, f: Fmt) -> u64 {
    let lo = cpu.vreg(n)[0];
    lo & f.mask()
}

/// Write a scalar FP result to Vd, zeroing the rest of the register.
fn writef(cpu: &mut CpuState, d: u32, f: Fmt, val: u64) {
    cpu.set_vreg(d, [val & f.mask(), 0]);
}

fn ctx(cpu: &CpuState) -> sf::FpCtx {
    sf::FpCtx::new(cpu.fpcr, cpu.fpsr)
}
fn commit(cpu: &mut CpuState, c: sf::FpCtx) {
    cpu.fpsr = c.fpsr & sf::FPSR_MASK;
}

pub(super) fn exec(cpu: &mut CpuState, insn: Insn, word: u32) -> Step {
    match insn {
        Insn::FpImm { ftype, rd, imm8 } => {
            let f = match ftype_fmt(ftype) {
                Some(f) => f,
                None => return Step::Exit(Exit::Undefined(word)),
            };
            let val = vfp_expand_imm(f, imm8);
            writef(cpu, rd, f, val);
            Step::Next
        }
        Insn::FpCmp { ftype, rn, rm, zero, signal } => {
            let f = match ftype_fmt(ftype) {
                Some(f) => f,
                None => return Step::Exit(Exit::Undefined(word)),
            };
            let a = readf(cpu, rn, f);
            let b = if zero { sf::zero(f, false) } else { readf(cpu, rm, f) };
            let mut c = ctx(cpu);
            let nzcv = sf::compare(&mut c, f, a, b, signal);
            commit(cpu, c);
            set_nzcv(
                cpu,
                nzcv & (1 << 31) != 0,
                nzcv & (1 << 30) != 0,
                nzcv & (1 << 29) != 0,
                nzcv & (1 << 28) != 0,
            );
            Step::Next
        }
        Insn::FpCCmp { ftype, rn, rm, nzcv, cond, signal } => {
            let f = match ftype_fmt(ftype) {
                Some(f) => f,
                None => return Step::Exit(Exit::Undefined(word)),
            };
            if cond_holds(cpu, cond) {
                let a = readf(cpu, rn, f);
                let b = readf(cpu, rm, f);
                let mut c = ctx(cpu);
                let r = sf::compare(&mut c, f, a, b, signal);
                commit(cpu, c);
                set_nzcv(
                    cpu,
                    r & (1 << 31) != 0,
                    r & (1 << 30) != 0,
                    r & (1 << 29) != 0,
                    r & (1 << 28) != 0,
                );
            } else {
                set_nzcv(cpu, nzcv & 8 != 0, nzcv & 4 != 0, nzcv & 2 != 0, nzcv & 1 != 0);
            }
            Step::Next
        }
        Insn::FpCSel { ftype, rd, rn, rm, cond } => {
            let f = match ftype_fmt(ftype) {
                Some(f) => f,
                None => return Step::Exit(Exit::Undefined(word)),
            };
            let v = if cond_holds(cpu, cond) {
                readf(cpu, rn, f)
            } else {
                readf(cpu, rm, f)
            };
            writef(cpu, rd, f, v);
            Step::Next
        }
        Insn::Fp1 { ftype, op, to, rd, rn } => exec_fp1(cpu, ftype, op, to, rd, rn, word),
        Insn::Fp2 { ftype, op, rd, rn, rm } => {
            let f = match ftype_fmt(ftype) {
                Some(f) => f,
                None => return Step::Exit(Exit::Undefined(word)),
            };
            let a = readf(cpu, rn, f);
            let b = readf(cpu, rm, f);
            let mut c = ctx(cpu);
            let r = match op {
                Fp2Op::Add => sf::add(&mut c, f, a, b),
                Fp2Op::Sub => sf::sub(&mut c, f, a, b),
                Fp2Op::Mul => sf::mul(&mut c, f, a, b),
                Fp2Op::Div => sf::div(&mut c, f, a, b),
                Fp2Op::Max => sf::max(&mut c, f, a, b),
                Fp2Op::Min => sf::min(&mut c, f, a, b),
                Fp2Op::MaxNm => sf::maxnum(&mut c, f, a, b),
                Fp2Op::MinNm => sf::minnum(&mut c, f, a, b),
                Fp2Op::Nmul => sf::neg(f, sf::mul(&mut c, f, a, b)),
            };
            commit(cpu, c);
            writef(cpu, rd, f, r);
            Step::Next
        }
        Insn::Fp3 { ftype, neg, sub, rd, rn, rm, ra } => {
            let f = match ftype_fmt(ftype) {
                Some(f) => f,
                None => return Step::Exit(Exit::Undefined(word)),
            };
            let a = readf(cpu, rn, f);
            let b = readf(cpu, rm, f);
            let acc = readf(cpu, ra, f);
            let mut c = ctx(cpu);
            // FMADD: acc + a*b ; FMSUB: acc + (-a)*b ; FNMADD: -acc + (-a)*b;
            // FNMSUB: -acc + a*b.
            let (neg_add, neg_a) = match (neg, sub) {
                (false, false) => (false, false),
                (false, true) => (false, true),
                (true, false) => (true, true),
                (true, true) => (true, false),
            };
            let r = sf::muladd(&mut c, f, acc, a, b, neg_add, neg_a);
            commit(cpu, c);
            writef(cpu, rd, f, r);
            Step::Next
        }
        Insn::FpCvt { ftype, sf: sf64, op, rd, rn } => exec_cvt(cpu, ftype, sf64, op, rd, rn, word),
        _ => Step::Exit(Exit::Undefined(word)),
    }
}

fn exec_fp1(cpu: &mut CpuState, ftype: u8, op: Fp1Op, to: u8, rd: u32, rn: u32, word: u32) -> Step {
    let f = match ftype_fmt(ftype) {
        Some(f) => f,
        None => return Step::Exit(Exit::Undefined(word)),
    };
    let a = readf(cpu, rn, f);
    let mut c = ctx(cpu);
    let rnd = c.rmode();
    if op == Fp1Op::Cvt {
        let tf = match to {
            0 => Fmt::S,
            1 => Fmt::D,
            2 => Fmt::H,
            _ => return Step::Exit(Exit::Undefined(word)),
        };
        if tf == f {
            return Step::Exit(Exit::Undefined(word));
        }
        let r = sf::convert(&mut c, f, tf, a, rnd);
        commit(cpu, c);
        writef(cpu, rd, tf, r);
        return Step::Next;
    }
    let r = match op {
        Fp1Op::Mov => a,
        Fp1Op::Abs => sf::abs(f, a),
        Fp1Op::Neg => sf::neg(f, a),
        Fp1Op::Sqrt => sf::sqrt(&mut c, f, a),
        Fp1Op::RintN => sf::round_int(&mut c, f, a, Rounding::TieEven, false),
        Fp1Op::RintP => sf::round_int(&mut c, f, a, Rounding::PosInf, false),
        Fp1Op::RintM => sf::round_int(&mut c, f, a, Rounding::NegInf, false),
        Fp1Op::RintZ => sf::round_int(&mut c, f, a, Rounding::Zero, false),
        Fp1Op::RintA => sf::round_int(&mut c, f, a, Rounding::TieAway, false),
        Fp1Op::RintX => sf::round_int(&mut c, f, a, rnd, true),
        Fp1Op::RintI => sf::round_int(&mut c, f, a, rnd, false),
        Fp1Op::Rint32Z => sf::round_int_n(&mut c, f, a, Rounding::Zero, 32),
        Fp1Op::Rint32X => sf::round_int_n(&mut c, f, a, rnd, 32),
        Fp1Op::Rint64Z => sf::round_int_n(&mut c, f, a, Rounding::Zero, 64),
        Fp1Op::Rint64X => sf::round_int_n(&mut c, f, a, rnd, 64),
        Fp1Op::Recpx => sf::recpx(&mut c, f, a),
        Fp1Op::Cvt => a,
    };
    commit(cpu, c);
    writef(cpu, rd, f, r);
    Step::Next
}

fn exec_cvt(cpu: &mut CpuState, ftype: u8, sf64: bool, op: FcvtOp, rd: u32, rn: u32, word: u32) -> Step {
    if let FcvtOp::Fmov { to_fp: true, top: true } = op {
        // FMOV Vd.D[1], Xn: only the top 64 bits change.
        let mut v = cpu.vreg(rd);
        v[1] = cpu.xr(rn);
        cpu.set_vreg(rd, v);
        return Step::Next;
    }
    if let FcvtOp::Fmov { to_fp: false, top: true } = op {
        cpu.set_xr(rd, cpu.vreg(rn)[1]);
        return Step::Next;
    }
    let f = match ftype_fmt(ftype) {
        Some(f) => f,
        None => {
            if let FcvtOp::Fjcvt = op {
                Fmt::D
            } else {
                return Step::Exit(Exit::Undefined(word));
            }
        }
    };
    let mut c = ctx(cpu);
    let rnd = c.rmode();
    let isize = if sf64 { 64 } else { 32 };
    match op {
        FcvtOp::FtoI { round, unsigned } => {
            let a = readf(cpu, rn, f);
            let r = match round {
                0 => Rounding::TieEven,
                1 => Rounding::PosInf,
                2 => Rounding::NegInf,
                3 => Rounding::Zero,
                _ => Rounding::TieAway,
            };
            let v = sf::to_fixed(&mut c, f, a, 0, unsigned, isize, r);
            commit(cpu, c);
            cpu.set_xr(rd, if sf64 { v } else { v & 0xffff_ffff });
        }
        FcvtOp::FtoFixed { unsigned, fbits } => {
            let a = readf(cpu, rn, f);
            let v = sf::to_fixed(&mut c, f, a, fbits, unsigned, isize, Rounding::Zero);
            commit(cpu, c);
            cpu.set_xr(rd, if sf64 { v } else { v & 0xffff_ffff });
        }
        FcvtOp::ItoF { unsigned } => {
            let raw = cpu.xr(rn);
            let v = sf::from_fixed(&mut c, f, raw, 0, !unsigned, isize, rnd);
            commit(cpu, c);
            writef(cpu, rd, f, v);
        }
        FcvtOp::FixedToF { unsigned, fbits } => {
            let raw = cpu.xr(rn);
            let v = sf::from_fixed(&mut c, f, raw, fbits, !unsigned, isize, rnd);
            commit(cpu, c);
            writef(cpu, rd, f, v);
        }
        FcvtOp::Fmov { to_fp, top } => {
            if top {
                // 128-bit element [1] moves (FMOV Xd, Vn.D[1] / Vd.D[1], Xn).
                if to_fp {
                    let mut v = cpu.vreg(rd);
                    v[1] = cpu.xr(rn);
                    cpu.set_vreg(rd, v);
                } else {
                    cpu.set_xr(rd, cpu.vreg(rn)[1]);
                }
            } else if to_fp {
                let raw = cpu.xr(rn);
                writef(cpu, rd, f, raw & f.mask());
            } else {
                let v = readf(cpu, rn, f);
                cpu.set_xr(rd, if sf64 { v } else { v & 0xffff_ffff });
            }
        }
        FcvtOp::Fjcvt => {
            let a = cpu.vreg(rn)[0];
            let (res, z) = sf::fjcvtzs(&mut c, a);
            commit(cpu, c);
            cpu.set_xr(rd, res as u64);
            set_nzcv(cpu, false, z, false, false);
        }
    }
    Step::Next
}

/// VFPExpandImm(imm8, N): construct the floating-point constant.
fn vfp_expand_imm(f: Fmt, imm8: u8) -> u64 {
    let e = f.ebits();
    let fb = f.fbits();
    let sign = ((imm8 >> 7) & 1) as u64;
    let b6 = ((imm8 >> 6) & 1) as u64;
    let notb6 = b6 ^ 1;
    // exp (E bits): [E-1]=notb6 ; [E-2:2]=replicate(b6, E-3) ; [1:0]=imm8<5:4>
    let rep = if b6 == 1 { (1u64 << (e - 3)) - 1 } else { 0 };
    let exp = (notb6 << (e - 1)) | (rep << 2) | (((imm8 >> 4) & 3) as u64);
    // frac (F bits): top 4 = imm8<3:0>, rest 0.
    let frac = ((imm8 & 0xf) as u64) << (fb - 4);
    (sign << (e + fb)) | (exp << fb) | frac
}
