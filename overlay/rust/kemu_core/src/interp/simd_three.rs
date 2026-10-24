// SPDX-License-Identifier: GPL-2.0
// SIMD three-same / three-different execution. Included by simd.rs.

#[allow(clippy::too_many_arguments)]
fn three_same(cpu: &mut CpuState, q: bool, _u: bool, size: u8, op: SimdOp, rd: u32, rn: u32, rm: u32, scalar: bool) {
    // Logical ops operate on whole registers.
    let (a, b) = (cpu.vreg(rn), cpu.vreg(rm));
    let d0 = cpu.vreg(rd);
    let whole = |f: &dyn Fn(u64, u64, u64) -> u64| {
        let mut o = [f(a[0], b[0], d0[0]), f(a[1], b[1], d0[1])];
        if !q {
            o[1] = 0;
        }
        o
    };
    let simple = match op {
        SimdOp::And => Some(whole(&|x, y, _| x & y)),
        SimdOp::Orr => Some(whole(&|x, y, _| x | y)),
        SimdOp::Eor => Some(whole(&|x, y, _| x ^ y)),
        SimdOp::Bic => Some(whole(&|x, y, _| x & !y)),
        SimdOp::Orn => Some(whole(&|x, y, _| x | !y)),
        SimdOp::Bsl => Some(whole(&|x, y, d| (d & x) | (y & !d))),
        SimdOp::Bit => Some(whole(&|x, y, d| (d & !y) | (x & y))),
        SimdOp::Bif => Some(whole(&|x, y, d| (d & y) | (x & !y))),
        _ => None,
    };
    if let Some(o) = simple {
        cpu.set_vreg(rd, o);
        return;
    }

    // FP ops.
    if is_fp_op(op) {
        fp_three(cpu, q, size, op, rd, rn, rm, scalar);
        return;
    }

    let esize = size;
    let lanes = if scalar { 1 } else { vbytes(q) >> esize };
    let mut out = [0u64; 2];
    let mut c = sf::FpCtx::new(cpu.fpcr, cpu.fpsr);
    let _ = &mut c;
    for i in 0..lanes {
        let x = get_lane(cpu, rn, esize, i);
        let y = get_lane(cpu, rm, esize, i);
        let dd = get_lane(cpu, rd, esize, i);
        let r = int_three_lane(op, x, y, dd, esize);
        put_lane(&mut out, esize, i, r);
    }
    // Pairwise ops need special handling across n:m.
    if is_pairwise(op) {
        out = [0u64; 2];
        pairwise(cpu, q, esize, op, rn, rm, &mut out);
    }
    cpu.set_vreg(rd, out);
}

fn int_three_lane(op: SimdOp, x: u64, y: u64, d: u64, esize: u8) -> u64 {
    let bits = 8u32 << esize;
    let mask = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
    let sx = sext(x, esize);
    let sy = sext(y, esize);
    let res = match op {
        SimdOp::Add => x.wrapping_add(y),
        SimdOp::Sub => x.wrapping_sub(y),
        SimdOp::Mul => x.wrapping_mul(y),
        SimdOp::Mla => d.wrapping_add(x.wrapping_mul(y)),
        SimdOp::Mls => d.wrapping_sub(x.wrapping_mul(y)),
        SimdOp::CmEq => bool_lane(x & mask == y & mask),
        SimdOp::CmGe => bool_lane(sx >= sy),
        SimdOp::CmGt => bool_lane(sx > sy),
        SimdOp::CmHi => bool_lane(x & mask > y & mask),
        SimdOp::CmHs => bool_lane(x & mask >= y & mask),
        SimdOp::CmTst => bool_lane(x & y & mask != 0),
        SimdOp::SMax => if sx >= sy { x } else { y },
        SimdOp::SMin => if sx <= sy { x } else { y },
        SimdOp::UMax => if x & mask >= y & mask { x } else { y },
        SimdOp::UMin => if x & mask <= y & mask { x } else { y },
        SimdOp::SAbd => (sx - sy).unsigned_abs(),
        SimdOp::UAbd => (x & mask).abs_diff(y & mask),
        SimdOp::SAba => d.wrapping_add((sx - sy).unsigned_abs()),
        SimdOp::UAba => d.wrapping_add((x & mask).abs_diff(y & mask)),
        SimdOp::SHAdd => ((sx + sy) >> 1) as u64,
        SimdOp::UHAdd => ((x & mask) + (y & mask)) >> 1,
        SimdOp::SRHAdd => ((sx + sy + 1) >> 1) as u64,
        SimdOp::URHAdd => ((x & mask) + (y & mask) + 1) >> 1,
        SimdOp::SHSub => ((sx - sy) >> 1) as u64,
        SimdOp::UHSub => (((x & mask).wrapping_sub(y & mask)) as i64 >> 1) as u64,
        SimdOp::SQAdd => sat_signed(sx + sy, esize) as u64,
        SimdOp::UQAdd => sat_unsigned((x & mask) as i128 + (y & mask) as i128, esize),
        SimdOp::SQSub => sat_signed(sx - sy, esize) as u64,
        SimdOp::UQSub => sat_unsigned((x & mask) as i128 - (y & mask) as i128, esize),
        SimdOp::SShl => sshl(x, sy, esize),
        SimdOp::UShl => ushl(x & mask, sy, esize),
        SimdOp::PMul => pmul(x, y, bits),
        _ => 0,
    };
    res & mask
}

#[inline]
fn bool_lane(c: bool) -> u64 {
    if c {
        u64::MAX
    } else {
        0
    }
}

fn sshl(x: u64, shift: i64, esize: u8) -> u64 {
    let sx = sext(x, esize);
    let s = (shift as i8) as i32; // shift amount is low byte, signed
    if s >= 0 {
        if s >= 64 {
            0
        } else {
            (sx << s) as u64
        }
    } else {
        let sh = (-s).min(63);
        (sx >> sh) as u64
    }
}
fn ushl(x: u64, shift: i64, _esize: u8) -> u64 {
    let s = (shift as i8) as i32;
    if s >= 0 {
        if s >= 64 {
            0
        } else {
            x << s
        }
    } else {
        let sh = (-s).min(63);
        x >> sh
    }
}

fn sat_signed(v: i64, esize: u8) -> i64 {
    let bits = 8u32 << esize;
    let max = (1i64 << (bits - 1)) - 1;
    let min = -(1i64 << (bits - 1));
    v.clamp(min, max)
}
fn sat_unsigned(v: i128, esize: u8) -> u64 {
    let bits = 8u32 << esize;
    let max = if bits >= 64 { u64::MAX as i128 } else { (1i128 << bits) - 1 };
    v.clamp(0, max) as u64
}

fn pmul(x: u64, y: u64, bits: u32) -> u64 {
    let mut r = 0u64;
    for i in 0..bits {
        if (y >> i) & 1 != 0 {
            r ^= x << i;
        }
    }
    r
}

fn is_fp_op(op: SimdOp) -> bool {
    use SimdOp::*;
    matches!(
        op,
        FAdd | FSub | FMul | FDiv | FMla | FMls | FAbd | FMax | FMin | FMaxNm | FMinNm | FMulx
            | FCmEq | FCmGe | FCmGt | FRecps | FRsqrts | FAcGe | FAcGt | FMaxP | FMinP | FAddP
            | FMaxNmP | FMinNmP
    )
}

fn is_pairwise(op: SimdOp) -> bool {
    use SimdOp::*;
    matches!(op, AddP | SMaxP | SMinP | UMaxP | UMinP)
}

fn pairwise(cpu: &CpuState, q: bool, esize: u8, op: SimdOp, rn: u32, rm: u32, out: &mut [u64; 2]) {
    let lanes = vbytes(q) >> esize;
    let half = lanes;
    for i in 0..lanes {
        let (src, base) = if i < half / 1 { (rn, 0) } else { (rm, 0) };
        let _ = (src, base);
    }
    // Concatenate rn:rm, then reduce adjacent pairs.
    let total = lanes * 2;
    let getv = |idx: u32| {
        if idx < lanes {
            get_lane(cpu, rn, esize, idx)
        } else {
            get_lane(cpu, rm, esize, idx - lanes)
        }
    };
    for i in 0..total / 2 {
        let a = getv(2 * i);
        let b = getv(2 * i + 1);
        let r = match op {
            SimdOp::AddP => a.wrapping_add(b),
            SimdOp::SMaxP => if sext(a, esize) >= sext(b, esize) { a } else { b },
            SimdOp::SMinP => if sext(a, esize) <= sext(b, esize) { a } else { b },
            SimdOp::UMaxP => if a >= b { a } else { b },
            SimdOp::UMinP => if a <= b { a } else { b },
            _ => 0,
        };
        put_lane(out, esize, i, r);
    }
}

#[allow(clippy::too_many_arguments)]
fn fp_three(cpu: &mut CpuState, q: bool, esize: u8, op: SimdOp, rd: u32, rn: u32, rm: u32, scalar: bool) {
    let f = fmt_of(esize);
    let lanes = if scalar { 1 } else { vbytes(q) >> esize };
    let mut out = [0u64; 2];
    let mut c = sf::FpCtx::new(cpu.fpcr, cpu.fpsr);
    let pairwise = matches!(op, SimdOp::FAddP | SimdOp::FMaxP | SimdOp::FMinP | SimdOp::FMaxNmP | SimdOp::FMinNmP);
    if pairwise && !scalar {
        let getv = |idx: u32| {
            if idx < lanes {
                get_lane(cpu, rn, esize, idx)
            } else {
                get_lane(cpu, rm, esize, idx - lanes)
            }
        };
        for i in 0..lanes {
            let a = getv(2 * i);
            let b = getv(2 * i + 1);
            let r = fp_binop(&mut c, f, op, a, b);
            put_lane(&mut out, esize, i, r);
        }
    } else {
        for i in 0..lanes {
            let a = get_lane(cpu, rn, esize, i);
            let b = get_lane(cpu, rm, esize, i);
            let d = get_lane(cpu, rd, esize, i);
            let r = match op {
                SimdOp::FMla => sf::muladd(&mut c, f, d, a, b, false, false),
                SimdOp::FMls => sf::muladd(&mut c, f, d, a, b, false, true),
                _ => fp_binop(&mut c, f, op, a, b),
            };
            put_lane(&mut out, esize, i, r);
        }
    }
    cpu.fpsr = c.fpsr & sf::FPSR_MASK;
    cpu.set_vreg(rd, out);
}

fn fp_binop(c: &mut sf::FpCtx, f: Fmt, op: SimdOp, a: u64, b: u64) -> u64 {
    match op {
        SimdOp::FAdd | SimdOp::FAddP => sf::add(c, f, a, b),
        SimdOp::FSub => sf::sub(c, f, a, b),
        SimdOp::FMul => sf::mul(c, f, a, b),
        SimdOp::FDiv => sf::div(c, f, a, b),
        SimdOp::FMulx => sf::mulx(c, f, a, b),
        SimdOp::FAbd => sf::abs(f, sf::sub(c, f, a, b)),
        SimdOp::FMax | SimdOp::FMaxP => sf::max(c, f, a, b),
        SimdOp::FMin | SimdOp::FMinP => sf::min(c, f, a, b),
        SimdOp::FMaxNm | SimdOp::FMaxNmP => sf::maxnum(c, f, a, b),
        SimdOp::FMinNm | SimdOp::FMinNmP => sf::minnum(c, f, a, b),
        SimdOp::FRecps => sf::recip_step(c, f, a, b),
        SimdOp::FRsqrts => sf::rsqrt_step(c, f, a, b),
        SimdOp::FCmEq => bool_lane(sf::compare_op(c, f, a, b, sf::CmpOp::Eq)),
        SimdOp::FCmGe => bool_lane(sf::compare_op(c, f, a, b, sf::CmpOp::Ge)),
        SimdOp::FCmGt => bool_lane(sf::compare_op(c, f, a, b, sf::CmpOp::Gt)),
        SimdOp::FAcGe => bool_lane(sf::compare_op(c, f, sf::abs(f, a), sf::abs(f, b), sf::CmpOp::Ge)),
        SimdOp::FAcGt => bool_lane(sf::compare_op(c, f, sf::abs(f, a), sf::abs(f, b), sf::CmpOp::Gt)),
        _ => 0,
    }
}
