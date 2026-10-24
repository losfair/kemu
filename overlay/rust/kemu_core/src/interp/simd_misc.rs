// SPDX-License-Identifier: GPL-2.0
// SIMD two-register-miscellaneous execution. Included by simd.rs.

#[allow(clippy::too_many_arguments)]
fn two_misc(cpu: &mut CpuState, q: bool, _u: bool, size: u8, op: Simd2Op, rd: u32, rn: u32, scalar: bool) {
    use Simd2Op::*;
    let esize = size;
    let bits = 8u32 << esize;
    let m = lmask(bits);
    let src = cpu.vreg(rn);
    let lanes = if scalar { 1 } else { vbytes(q) >> esize };
    let mut c = sf::FpCtx::new(cpu.fpcr, cpu.fpsr);
    let mut qc = false;
    let mut out = [0u64; 2];

    match op {
        Rev16 | Rev32 | Rev64 => {
            let cont: u32 = match op {
                Rev16 => 16,
                Rev32 => 32,
                _ => 64,
            };
            let per = cont / bits; // elements per container
            if per == 0 {
                return;
            }
            for i in 0..lanes {
                let base = i - i % per;
                let j = base + (per - 1 - i % per);
                put_lane(&mut out, esize, i, lane(&src, esize, j));
            }
            write_vec(cpu, rd, q, out);
            return;
        }
        Xtn | Xtn2 | SqXtn | SqXtn2 | UqXtn | UqXtn2 | SqXtun | SqXtun2 => {
            // Source elements are 2*esize; result is 64 bits (or one element).
            let n = if scalar { 1 } else { 8u32 >> esize };
            let mut half = [0u64; 2];
            for i in 0..n {
                let v = lane(&src, esize + 1, i);
                let r = match op {
                    Xtn | Xtn2 => v & m,
                    SqXtn | SqXtn2 => sat_s(ival(v, esize + 1, true), bits, &mut qc),
                    UqXtn | UqXtn2 => sat_u(ival(v, esize + 1, false), bits, &mut qc),
                    _ => sat_u(ival(v, esize + 1, true), bits, &mut qc),
                };
                put_lane(&mut half, esize, i, r);
            }
            set_qc(cpu, qc);
            if scalar {
                cpu.set_vreg(rd, half);
            } else {
                write_part(cpu, rd, q, half[0]);
            }
            return;
        }
        FcvtN | FcvtN2 | FcvtXn | FcvtXn2 => {
            // Narrow: size is the destination element size (H = 1, S = 2).
            let (from, to) = if esize == 2 { (Fmt::D, Fmt::S) } else { (Fmt::S, Fmt::H) };
            let rnd = if matches!(op, FcvtXn | FcvtXn2) { sf::Rounding::Odd } else { c.rmode() };
            let n = if scalar { 1 } else { 64 / bits };
            let mut half = [0u64; 2];
            for i in 0..n {
                let r = sf::convert(&mut c, from, to, lane(&src, esize + 1, i), rnd);
                put_lane(&mut half, esize, i, r);
            }
            cpu.fpsr = c.fpsr & sf::FPSR_MASK;
            if scalar {
                cpu.set_vreg(rd, half);
            } else {
                write_part(cpu, rd, q, half[0]);
            }
            return;
        }
        FcvtL | FcvtL2 => {
            // Widen: size is the source element size (H = 1, S = 2).
            let (from, to) = if esize == 2 { (Fmt::S, Fmt::D) } else { (Fmt::H, Fmt::S) };
            let n = 64 / bits;
            let off = if q { n } else { 0 };
            let rnd = c.rmode();
            for i in 0..n {
                let r = sf::convert(&mut c, from, to, lane(&src, esize, off + i), rnd);
                put_lane(&mut out, esize + 1, i, r);
            }
            cpu.fpsr = c.fpsr & sf::FPSR_MASK;
            cpu.set_vreg(rd, out);
            return;
        }
        Shll | Shll2 => {
            let n = 8u32 >> esize;
            let off = if q { n } else { 0 };
            for i in 0..n {
                put_lane(&mut out, esize + 1, i, lane(&src, esize, off + i) << bits);
            }
            cpu.set_vreg(rd, out);
            return;
        }
        SaddLp | UaddLp | SadaLp | UadaLp => {
            let signed = matches!(op, SaddLp | SadaLp);
            let acc = matches!(op, SadaLp | UadaLp);
            let d0 = cpu.vreg(rd);
            for i in 0..lanes / 2 {
                let s = ival(lane(&src, esize, 2 * i), esize, signed) + ival(lane(&src, esize, 2 * i + 1), esize, signed);
                let mut r = s as u64;
                if acc {
                    r = r.wrapping_add(lane(&d0, esize + 1, i));
                }
                put_lane(&mut out, esize + 1, i, r);
            }
            write_vec(cpu, rd, q, out);
            return;
        }
        Urecpe | Ursqrte => {
            for i in 0..lanes {
                let v = lane(&src, 2, i) as u32;
                let r = if op == Urecpe { sf::unsigned_recip_estimate(v) } else { sf::unsigned_rsqrt_estimate(v) };
                put_lane(&mut out, 2, i, r as u64);
            }
            write_vec(cpu, rd, q, out);
            return;
        }
        _ => {}
    }

    let fp = is_fp_misc(op);
    let d0 = cpu.vreg(rd);
    for i in 0..lanes {
        let v = lane(&src, esize, i);
        let r = if fp {
            fp_misc_lane(&mut c, fmt_of(esize), op, v)
        } else {
            match op {
                SuqAdd => sat_s(ival(lane(&d0, esize, i), esize, true) + ival(v, esize, false), bits, &mut qc),
                UsqAdd => sat_u(ival(lane(&d0, esize, i), esize, false) + ival(v, esize, true), bits, &mut qc),
                SqAbs => sat_s(ival(v, esize, true).abs(), bits, &mut qc),
                SqNeg => sat_s(-ival(v, esize, true), bits, &mut qc),
                _ => int_misc_lane(op, v, esize, m),
            }
        };
        put_lane(&mut out, esize, i, r);
    }
    cpu.fpsr = c.fpsr & sf::FPSR_MASK;
    set_qc(cpu, qc);
    write_vec(cpu, rd, q && !scalar, out);
}

fn int_misc_lane(op: Simd2Op, v: u64, esize: u8, mask: u64) -> u64 {
    let bits = 8u32 << esize;
    let v = v & mask;
    (match op {
        Simd2Op::Not => !v,
        Simd2Op::Rbit => v.reverse_bits() >> (64 - bits),
        Simd2Op::Cnt => v.count_ones() as u64,
        Simd2Op::Clz => (v << (64 - bits)).leading_zeros().min(bits) as u64,
        Simd2Op::Cls => {
            let x = if sext(v, esize) < 0 { !v & mask } else { v };
            ((x << (64 - bits)).leading_zeros().min(bits) - 1) as u64
        }
        Simd2Op::Neg => v.wrapping_neg(),
        Simd2Op::Abs => sext(v, esize).unsigned_abs(),
        Simd2Op::CmEq0 => bool_lane(v == 0),
        Simd2Op::CmGe0 => bool_lane(sext(v, esize) >= 0),
        Simd2Op::CmGt0 => bool_lane(sext(v, esize) > 0),
        Simd2Op::CmLe0 => bool_lane(sext(v, esize) <= 0),
        Simd2Op::CmLt0 => bool_lane(sext(v, esize) < 0),
        _ => 0,
    }) & mask
}

fn is_fp_misc(op: Simd2Op) -> bool {
    use Simd2Op::*;
    matches!(
        op,
        Fabs | Fneg | Fsqrt | FrintN | FrintP | FrintM | FrintZ | FrintA | FrintX | FrintI | Frint32Z | Frint32X
            | Frint64Z | Frint64X | Fcvtns | Fcvtnu | Fcvtps | Fcvtpu | Fcvtms | Fcvtmu | Fcvtzs | Fcvtzu | Fcvtas
            | Fcvtau | Scvtf | Ucvtf | Frecpe | Frsqrte | Frecpx | FCmEq0 | FCmGe0 | FCmGt0 | FCmLe0 | FCmLt0
    )
}

fn fp_misc_lane(c: &mut sf::FpCtx, f: Fmt, op: Simd2Op, v: u64) -> u64 {
    use crate::softfloat::Rounding as R;
    let rnd = c.rmode();
    let isize = f.nbits();
    let z = sf::zero(f, false);
    match op {
        Simd2Op::Fabs => sf::abs(f, v),
        Simd2Op::Fneg => sf::neg(f, v),
        Simd2Op::Fsqrt => sf::sqrt(c, f, v),
        Simd2Op::FrintN => sf::round_int(c, f, v, R::TieEven, false),
        Simd2Op::FrintP => sf::round_int(c, f, v, R::PosInf, false),
        Simd2Op::FrintM => sf::round_int(c, f, v, R::NegInf, false),
        Simd2Op::FrintZ => sf::round_int(c, f, v, R::Zero, false),
        Simd2Op::FrintA => sf::round_int(c, f, v, R::TieAway, false),
        Simd2Op::FrintX => sf::round_int(c, f, v, rnd, true),
        Simd2Op::FrintI => sf::round_int(c, f, v, rnd, false),
        Simd2Op::Frint32Z => sf::round_int_n(c, f, v, R::Zero, 32),
        Simd2Op::Frint32X => sf::round_int_n(c, f, v, rnd, 32),
        Simd2Op::Frint64Z => sf::round_int_n(c, f, v, R::Zero, 64),
        Simd2Op::Frint64X => sf::round_int_n(c, f, v, rnd, 64),
        Simd2Op::Fcvtns => sf::to_fixed(c, f, v, 0, false, isize, R::TieEven),
        Simd2Op::Fcvtnu => sf::to_fixed(c, f, v, 0, true, isize, R::TieEven),
        Simd2Op::Fcvtps => sf::to_fixed(c, f, v, 0, false, isize, R::PosInf),
        Simd2Op::Fcvtpu => sf::to_fixed(c, f, v, 0, true, isize, R::PosInf),
        Simd2Op::Fcvtms => sf::to_fixed(c, f, v, 0, false, isize, R::NegInf),
        Simd2Op::Fcvtmu => sf::to_fixed(c, f, v, 0, true, isize, R::NegInf),
        Simd2Op::Fcvtzs => sf::to_fixed(c, f, v, 0, false, isize, R::Zero),
        Simd2Op::Fcvtzu => sf::to_fixed(c, f, v, 0, true, isize, R::Zero),
        Simd2Op::Fcvtas => sf::to_fixed(c, f, v, 0, false, isize, R::TieAway),
        Simd2Op::Fcvtau => sf::to_fixed(c, f, v, 0, true, isize, R::TieAway),
        Simd2Op::Scvtf => sf::from_fixed(c, f, v, 0, true, isize, rnd),
        Simd2Op::Ucvtf => sf::from_fixed(c, f, v, 0, false, isize, rnd),
        Simd2Op::Frecpe => sf::recip_estimate_fp(c, f, v),
        Simd2Op::Frsqrte => sf::rsqrt_estimate_fp(c, f, v),
        Simd2Op::Frecpx => sf::recpx(c, f, v),
        Simd2Op::FCmEq0 => bool_lane(sf::compare_op(c, f, v, z, sf::CmpOp::Eq)),
        Simd2Op::FCmGe0 => bool_lane(sf::compare_op(c, f, v, z, sf::CmpOp::Ge)),
        Simd2Op::FCmGt0 => bool_lane(sf::compare_op(c, f, v, z, sf::CmpOp::Gt)),
        Simd2Op::FCmLe0 => bool_lane(sf::compare_op(c, f, z, v, sf::CmpOp::Ge)),
        Simd2Op::FCmLt0 => bool_lane(sf::compare_op(c, f, z, v, sf::CmpOp::Gt)),
        _ => 0,
    }
}
