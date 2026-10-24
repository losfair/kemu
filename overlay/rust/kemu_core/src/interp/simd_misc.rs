// SPDX-License-Identifier: GPL-2.0
// SIMD two-register-misc execution. Included by simd.rs.

#[allow(clippy::too_many_arguments)]
fn two_misc(cpu: &mut CpuState, q: bool, _u: bool, size: u8, op: Simd2Op, rd: u32, rn: u32, scalar: bool) {
    let esize = size;
    let lanes = if scalar { 1 } else { vbytes(q) >> esize };
    let mut out = [0u64; 2];
    let mut c = sf::FpCtx::new(cpu.fpcr, cpu.fpsr);
    let bits = 8u32 << esize;
    let mask = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };

    // Narrowing ops write the lower/upper half.
    match op {
        Simd2Op::Xtn | Simd2Op::Xtn2 | Simd2Op::SqXtn | Simd2Op::SqXtn2 | Simd2Op::UqXtn
        | Simd2Op::UqXtn2 | Simd2Op::SqXtun | Simd2Op::SqXtun2 => {
            let src_es = esize + 1;
            let src_lanes = 8u32 >> esize; // result is 64-bit (or upper 64)
            let top = matches!(
                op,
                Simd2Op::Xtn2 | Simd2Op::SqXtn2 | Simd2Op::UqXtn2 | Simd2Op::SqXtun2
            );
            let base = if top { cpu.vreg(rd) } else { [0u64; 2] };
            out = base;
            let lane_off = if top { src_lanes } else { 0 };
            for i in 0..src_lanes {
                let v = get_lane(cpu, rn, src_es, i);
                let r = match op {
                    Simd2Op::Xtn | Simd2Op::Xtn2 => v & mask,
                    Simd2Op::SqXtn | Simd2Op::SqXtn2 => sat_signed(sext(v, src_es), esize) as u64 & mask,
                    Simd2Op::UqXtn | Simd2Op::UqXtn2 => sat_unsigned(v as i128, esize),
                    _ => sat_unsigned(sext(v, src_es) as i128, esize),
                };
                put_lane(&mut out, esize, lane_off + i, r);
            }
            cpu.set_vreg(rd, out);
            return;
        }
        Simd2Op::FcvtN | Simd2Op::FcvtN2 => {
            // Narrow F32->F16 or F64->F32.
            let from = if esize == 2 { Fmt::D } else { Fmt::S };
            let to = if esize == 2 { Fmt::S } else { Fmt::H };
            let top = matches!(op, Simd2Op::FcvtN2);
            out = if top { cpu.vreg(rd) } else { [0u64; 2] };
            let src_lanes = 8u32 >> esize;
            let off = if top { src_lanes } else { 0 };
            let rnd = c.rmode();
            for i in 0..src_lanes {
                let v = get_lane(cpu, rn, esize + 1, i);
                let r = sf::convert(&mut c, from, to, v, rnd);
                put_lane(&mut out, esize, off + i, r);
            }
            cpu.fpsr = c.fpsr & sf::FPSR_MASK;
            cpu.set_vreg(rd, out);
            return;
        }
        Simd2Op::FcvtL | Simd2Op::FcvtL2 => {
            let from = if esize == 2 { Fmt::S } else { Fmt::H };
            let to = if esize == 2 { Fmt::D } else { Fmt::S };
            let top = matches!(op, Simd2Op::FcvtL2);
            let src_lanes = 8u32 >> esize;
            let off = if top { src_lanes } else { 0 };
            let rnd = c.rmode();
            for i in 0..src_lanes {
                let v = get_lane(cpu, rn, esize, off + i);
                let r = sf::convert(&mut c, from, to, v, rnd);
                put_lane(&mut out, esize + 1, i, r);
            }
            cpu.fpsr = c.fpsr & sf::FPSR_MASK;
            cpu.set_vreg(rd, out);
            return;
        }
        _ => {}
    }

    let fp = is_fp_misc(op);
    for i in 0..lanes {
        let v = get_lane(cpu, rn, esize, i);
        let r = if fp {
            fp_misc_lane(&mut c, fmt_of(esize), op, v)
        } else {
            int_misc_lane(op, v, esize, mask)
        };
        put_lane(&mut out, esize, i, r);
    }
    cpu.fpsr = c.fpsr & sf::FPSR_MASK;
    cpu.set_vreg(rd, out);
}

fn int_misc_lane(op: Simd2Op, v: u64, esize: u8, mask: u64) -> u64 {
    let bits = 8u32 << esize;
    (match op {
        Simd2Op::Not => !v,
        Simd2Op::Rbit => v.reverse_bits() >> (64 - bits),
        Simd2Op::Cnt => (v & mask).count_ones() as u64,
        Simd2Op::Clz => ((v & mask) << (64 - bits)).leading_zeros() as u64,
        Simd2Op::Cls => {
            let s = sext(v, esize);
            let x = if s < 0 { !(v & mask) } else { v & mask };
            (((x << (64 - bits)) as u64).leading_zeros().saturating_sub(1)) as u64
        }
        Simd2Op::Neg => (v & mask).wrapping_neg(),
        Simd2Op::Abs => sext(v, esize).unsigned_abs(),
        Simd2Op::Rev16 => rev_in(v, esize, 1),
        Simd2Op::Rev32 => rev_in(v, esize, 2),
        Simd2Op::Rev64 => rev_in(v, esize, 3),
        Simd2Op::CmEq0 => bool_lane(v & mask == 0),
        Simd2Op::CmGe0 => bool_lane(sext(v, esize) >= 0),
        Simd2Op::CmGt0 => bool_lane(sext(v, esize) > 0),
        Simd2Op::CmLe0 => bool_lane(sext(v, esize) <= 0),
        Simd2Op::CmLt0 => bool_lane(sext(v, esize) < 0),
        _ => 0,
    }) & mask
}

/// Reverse elements of size `in_es` within containers of size `cont_es`.
fn rev_in(v: u64, in_es: u8, cont_es: u8) -> u64 {
    let esz = 8u32 << in_es;
    let csz = 8u32 << cont_es;
    if csz > 64 || esz >= csz {
        return v;
    }
    let per = csz / esz;
    let mut out = 0u64;
    let mut base = 0;
    while base < 64 {
        for i in 0..per {
            let e = (v >> (base + i * esz)) & ((1u64 << esz) - 1);
            out |= e << (base + (per - 1 - i) * esz);
        }
        base += csz;
    }
    out
}

fn is_fp_misc(op: Simd2Op) -> bool {
    use Simd2Op::*;
    matches!(
        op,
        Fabs | Fneg | Fsqrt | FrintN | FrintP | FrintM | FrintZ | FrintA | FrintX | FrintI
            | Frint32Z | Frint32X | Frint64Z | Frint64X | Fcvtns | Fcvtnu | Fcvtps | Fcvtpu
            | Fcvtms | Fcvtmu | Fcvtzs | Fcvtzu | Fcvtas | Fcvtau | Scvtf | Ucvtf | Frecpe
            | Frsqrte | Frecpx | FCmEq0 | FCmGe0 | FCmGt0 | FCmLe0 | FCmLt0
    )
}

fn fp_misc_lane(c: &mut sf::FpCtx, f: Fmt, op: Simd2Op, v: u64) -> u64 {
    use crate::softfloat::Rounding as R;
    let rnd = c.rmode();
    let isize = f.nbits();
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
        Simd2Op::FCmEq0 => bool_lane(sf::compare_op(c, f, v, sf::zero(f, false), sf::CmpOp::Eq)),
        Simd2Op::FCmGe0 => bool_lane(sf::compare_op(c, f, v, sf::zero(f, false), sf::CmpOp::Ge)),
        Simd2Op::FCmGt0 => bool_lane(sf::compare_op(c, f, v, sf::zero(f, false), sf::CmpOp::Gt)),
        Simd2Op::FCmLe0 => bool_lane(sf::compare_op(c, f, sf::zero(f, false), v, sf::CmpOp::Ge)),
        Simd2Op::FCmLt0 => bool_lane(sf::compare_op(c, f, sf::zero(f, false), v, sf::CmpOp::Gt)),
        _ => 0,
    }
}
