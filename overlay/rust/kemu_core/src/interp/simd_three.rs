// SPDX-License-Identifier: GPL-2.0
// SIMD three-same / three-different / three-same-extra execution.
// Included by simd.rs.

#[allow(clippy::too_many_arguments)]
fn three_same(cpu: &mut CpuState, q: bool, _u: bool, size: u8, op: SimdOp, rd: u32, rn: u32, rm: u32, scalar: bool) {
    let (a, b) = (cpu.vreg(rn), cpu.vreg(rm));
    let d0 = cpu.vreg(rd);
    let whole = |f: &dyn Fn(u64, u64, u64) -> u64| [f(a[0], b[0], d0[0]), f(a[1], b[1], d0[1])];
    let logical = match op {
        SimdOp::And => Some(whole(&|x, y, _| x & y)),
        SimdOp::Orr => Some(whole(&|x, y, _| x | y)),
        SimdOp::Eor => Some(whole(&|x, y, _| x ^ y)),
        SimdOp::Bic => Some(whole(&|x, y, _| x & !y)),
        SimdOp::Orn => Some(whole(&|x, y, _| x | !y)),
        SimdOp::Bsl => Some(whole(&|x, y, d| (d & x) | (!d & y))),
        SimdOp::Bit => Some(whole(&|x, y, d| (d & !y) | (x & y))),
        SimdOp::Bif => Some(whole(&|x, y, d| (d & y) | (x & !y))),
        _ => None,
    };
    if let Some(o) = logical {
        write_vec(cpu, rd, q, o);
        return;
    }
    if is_fp_op(op) {
        fp_three(cpu, q, size, op, rd, rn, rm, scalar);
        return;
    }
    if is_diff(op) {
        three_diff(cpu, size, op, rd, rn, rm, scalar);
        return;
    }
    let esize = size;
    let bits = 8u32 << esize;
    let lanes = if scalar { 1 } else { vbytes(q) >> esize };
    let mut out = [0u64; 2];
    let mut qc = false;
    match op {
        SimdOp::AddP | SimdOp::SMaxP | SimdOp::SMinP | SimdOp::UMaxP | SimdOp::UMinP => {
            // Pairwise over the concatenation Vm:Vn.
            let signed = matches!(op, SimdOp::SMaxP | SimdOp::SMinP);
            for i in 0..lanes {
                let pick = |k: u32| if k < lanes { lane(&a, esize, k) } else { lane(&b, esize, k - lanes) };
                let (x, y) = (pick(2 * i), pick(2 * i + 1));
                let (sx, sy) = (ival(x, esize, signed), ival(y, esize, signed));
                let r = match op {
                    SimdOp::AddP => x.wrapping_add(y),
                    SimdOp::SMaxP | SimdOp::UMaxP => if sx >= sy { x } else { y },
                    _ => if sx <= sy { x } else { y },
                };
                put_lane(&mut out, esize, i, r);
            }
        }
        SimdOp::SQRDMlah | SimdOp::SQRDMlsh => {
            for i in 0..lanes {
                let x = ival(lane(&a, esize, i), esize, true);
                let y = ival(lane(&b, esize, i), esize, true);
                let d = ival(lane(&d0, esize, i), esize, true);
                let p = 2 * x * y;
                let acc = if op == SimdOp::SQRDMlsh { (d << bits) - p } else { (d << bits) + p };
                let r = sat_s((acc + (1i128 << (bits - 1))) >> bits, bits, &mut qc);
                put_lane(&mut out, esize, i, r);
            }
        }
        SimdOp::SDot | SimdOp::UDot => {
            let signed = op == SimdOp::SDot;
            for i in 0..vbytes(q) / 4 {
                let mut acc = lane(&d0, 2, i) as i128;
                for j in 0..4 {
                    acc += ival(lane(&a, 0, 4 * i + j), 0, signed) * ival(lane(&b, 0, 4 * i + j), 0, signed);
                }
                put_lane(&mut out, 2, i, acc as u64);
            }
        }
        _ => {
            for i in 0..lanes {
                let r = int_three_lane(op, lane(&a, esize, i), lane(&b, esize, i), lane(&d0, esize, i), esize, &mut qc);
                put_lane(&mut out, esize, i, r);
            }
        }
    }
    set_qc(cpu, qc);
    write_vec(cpu, rd, q && !scalar, out);
}

/// Shift by a signed register amount (SSHL/USHL/SRSHL/URSHL/SQSHL/UQSHL/
/// SQRSHL/UQRSHL). `e` is the extended element, `shift` = SInt(Vm<7:0>).
fn shl_reg(e: i128, shift: i32, bits: u32, unsigned: bool, round: bool, saturate: bool, qc: &mut bool) -> u64 {
    let res: i128 = if shift >= 0 {
        if e == 0 {
            0
        } else if shift >= 64 || (saturate && e.unsigned_abs() >> (126 - shift as u32) != 0) {
            // |e << shift| >= 2^126: the result saturates (or is 0 when
            // truncated, for shift >= 64).
            if !saturate {
                if shift >= 64 {
                    return 0;
                }
                e.wrapping_shl(shift as u32)
            } else if e > 0 {
                i128::MAX >> 1
            } else {
                i128::MIN >> 1
            }
        } else {
            e.wrapping_shl(shift as u32)
        }
    } else {
        let n = (-shift).min(65) as u32;
        let rc = if round { 1i128 << (n - 1) } else { 0 };
        (e + rc) >> n
    };
    if saturate {
        sat(res, bits, unsigned, qc)
    } else {
        (res as u64) & lmask(bits)
    }
}

fn int_three_lane(op: SimdOp, x: u64, y: u64, d: u64, esize: u8, qc: &mut bool) -> u64 {
    use SimdOp::*;
    let bits = 8u32 << esize;
    let m = lmask(bits);
    let (sx, sy) = (ival(x, esize, true), ival(y, esize, true));
    let (ux, uy) = (ival(x, esize, false), ival(y, esize, false));
    let sh = (y as u8) as i8 as i32;
    let res = match op {
        Add => x.wrapping_add(y),
        Sub => x.wrapping_sub(y),
        Mul => x.wrapping_mul(y),
        Mla => d.wrapping_add(x.wrapping_mul(y)),
        Mls => d.wrapping_sub(x.wrapping_mul(y)),
        PMul => clmul(x & m, y & m, bits) as u64,
        CmEq => bool_lane(ux == uy),
        CmGe => bool_lane(sx >= sy),
        CmGt => bool_lane(sx > sy),
        CmHi => bool_lane(ux > uy),
        CmHs => bool_lane(ux >= uy),
        CmTst => bool_lane(x & y & m != 0),
        SMax => if sx >= sy { x } else { y },
        SMin => if sx <= sy { x } else { y },
        UMax => if ux >= uy { x } else { y },
        UMin => if ux <= uy { x } else { y },
        SAbd => (sx - sy).unsigned_abs() as u64,
        UAbd => (ux - uy).unsigned_abs() as u64,
        SAba => d.wrapping_add((sx - sy).unsigned_abs() as u64),
        UAba => d.wrapping_add((ux - uy).unsigned_abs() as u64),
        SHAdd => ((sx + sy) >> 1) as u64,
        UHAdd => ((ux + uy) >> 1) as u64,
        SRHAdd => ((sx + sy + 1) >> 1) as u64,
        URHAdd => ((ux + uy + 1) >> 1) as u64,
        SHSub => ((sx - sy) >> 1) as u64,
        UHSub => ((ux - uy) >> 1) as u64,
        SQAdd => sat_s(sx + sy, bits, qc),
        UQAdd => sat_u(ux + uy, bits, qc),
        SQSub => sat_s(sx - sy, bits, qc),
        UQSub => sat_u(ux - uy, bits, qc),
        SShl => shl_reg(sx, sh, bits, false, false, false, qc),
        UShl => shl_reg(ux, sh, bits, true, false, false, qc),
        SRShl => shl_reg(sx, sh, bits, false, true, false, qc),
        URShl => shl_reg(ux, sh, bits, true, true, false, qc),
        SQShl => shl_reg(sx, sh, bits, false, false, true, qc),
        UQShl => shl_reg(ux, sh, bits, true, false, true, qc),
        SQRShl => shl_reg(sx, sh, bits, false, true, true, qc),
        UQRShl => shl_reg(ux, sh, bits, true, true, true, qc),
        SQDMulh => sat_s((2 * sx * sy) >> bits, bits, qc),
        SQRDMulh => sat_s((2 * sx * sy + (1i128 << (bits - 1))) >> bits, bits, qc),
        _ => 0,
    };
    res & m
}

/// Carry-less multiply of two `bits`-bit values (result up to 2*bits bits).
fn clmul(x: u64, y: u64, bits: u32) -> u128 {
    let mut r = 0u128;
    for i in 0..bits.min(64) {
        if (y >> i) & 1 != 0 {
            r ^= (x as u128) << i;
        }
    }
    r
}

fn is_fp_op(op: SimdOp) -> bool {
    use SimdOp::*;
    matches!(
        op,
        FAdd | FSub | FMul | FDiv | FMla | FMls | FAbd | FMax | FMin | FMaxNm | FMinNm | FMulx | FCmEq | FCmGe
            | FCmGt | FRecps | FRsqrts | FAcGe | FAcGt | FMaxP | FMinP | FAddP | FMaxNmP | FMinNmP
    )
}

#[allow(clippy::too_many_arguments)]
fn fp_three(cpu: &mut CpuState, q: bool, esize: u8, op: SimdOp, rd: u32, rn: u32, rm: u32, scalar: bool) {
    let f = fmt_of(esize);
    let lanes = if scalar { 1 } else { vbytes(q) >> esize };
    let (a, b, d0) = (cpu.vreg(rn), cpu.vreg(rm), cpu.vreg(rd));
    let mut out = [0u64; 2];
    let mut c = sf::FpCtx::new(cpu.fpcr, cpu.fpsr);
    let pairwise = matches!(op, SimdOp::FAddP | SimdOp::FMaxP | SimdOp::FMinP | SimdOp::FMaxNmP | SimdOp::FMinNmP);
    for i in 0..lanes {
        let r = if pairwise {
            let pick = |k: u32| if k < lanes { lane(&a, esize, k) } else { lane(&b, esize, k - lanes) };
            fp_binop(&mut c, f, op, pick(2 * i), pick(2 * i + 1))
        } else {
            let (x, y) = (lane(&a, esize, i), lane(&b, esize, i));
            match op {
                SimdOp::FMla => sf::muladd(&mut c, f, lane(&d0, esize, i), x, y, false, false),
                SimdOp::FMls => sf::muladd(&mut c, f, lane(&d0, esize, i), x, y, false, true),
                _ => fp_binop(&mut c, f, op, x, y),
            }
        };
        put_lane(&mut out, esize, i, r);
    }
    cpu.fpsr = c.fpsr & sf::FPSR_MASK;
    write_vec(cpu, rd, q && !scalar, out);
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

fn is_diff(op: SimdOp) -> bool {
    use SimdOp::*;
    matches!(
        op,
        SAddL | SAddL2 | UAddL | UAddL2 | SSubL | SSubL2 | USubL | USubL2 | SAddW | SAddW2 | UAddW | UAddW2 | SSubW
            | SSubW2 | USubW | USubW2 | AddHn | AddHn2 | SubHn | SubHn2 | RAddHn | RAddHn2 | RSubHn | RSubHn2 | SMullL
            | SMullL2 | UMullL | UMullL2 | SMlaL | SMlaL2 | UMlaL | UMlaL2 | SMlsL | SMlsL2 | UMlsL | UMlsL2 | SAbdL
            | SAbdL2 | UAbdL | UAbdL2 | SAbaL | SAbaL2 | UAbaL | UAbaL2 | PMull | PMull2 | SQDMull | SQDMull2
            | SQDMlaL | SQDMlaL2 | SQDMlsL | SQDMlsL2
    )
}

/// Three-different ops. `size` is the narrow element size.
fn three_diff(cpu: &mut CpuState, size: u8, op: SimdOp, rd: u32, rn: u32, rm: u32, scalar: bool) {
    use SimdOp::*;
    let (a, b, d0) = (cpu.vreg(rn), cpu.vreg(rm), cpu.vreg(rd));
    let high = matches!(
        op,
        SAddL2 | UAddL2 | SSubL2 | USubL2 | SAddW2 | UAddW2 | SSubW2 | USubW2 | AddHn2 | SubHn2 | RAddHn2 | RSubHn2
            | SMullL2 | UMullL2 | SMlaL2 | UMlaL2 | SMlsL2 | UMlsL2 | SAbdL2 | UAbdL2 | SAbaL2 | UAbaL2 | PMull2
            | SQDMull2 | SQDMlaL2 | SQDMlsL2
    );
    let es = size;
    let bits = 8u32 << es;
    let mut qc = false;

    if matches!(op, AddHn | AddHn2 | SubHn | SubHn2 | RAddHn | RAddHn2 | RSubHn | RSubHn2) {
        let n = 8u32 >> es; // number of narrow results (64 bits)
        let mut half = [0u64; 2];
        for i in 0..n {
            let x = lane(&a, es + 1, i);
            let y = lane(&b, es + 1, i);
            let s = if matches!(op, AddHn | AddHn2 | RAddHn | RAddHn2) { x.wrapping_add(y) } else { x.wrapping_sub(y) };
            let rc = if matches!(op, RAddHn | RAddHn2 | RSubHn | RSubHn2) { 1u64 << (bits - 1) } else { 0 };
            let r = (s.wrapping_add(rc) & lmask(2 * bits)) >> bits;
            put_lane(&mut half, es, i, r);
        }
        write_part(cpu, rd, high, half[0]);
        return;
    }
    if matches!(op, PMull | PMull2) {
        let part = high as u32;
        let mut out = [0u64; 2];
        if es == 3 {
            let r = clmul(lane(&a, 3, part), lane(&b, 3, part), 64);
            out = [r as u64, (r >> 64) as u64];
        } else {
            for i in 0..8u32 {
                let r = clmul(lane(&a, 0, 8 * part + i), lane(&b, 0, 8 * part + i), 8);
                put_lane(&mut out, 1, i, r as u64);
            }
        }
        cpu.set_vreg(rd, out);
        return;
    }
    let n = if scalar { 1 } else { 8u32 >> es }; // number of wide results
    let off = if high { n } else { 0 };
    let signed = matches!(
        op,
        SAddL | SAddL2 | SSubL | SSubL2 | SAddW | SAddW2 | SSubW | SSubW2 | SMullL | SMullL2 | SMlaL | SMlaL2 | SMlsL
            | SMlsL2 | SAbdL | SAbdL2 | SAbaL | SAbaL2 | SQDMull | SQDMull2 | SQDMlaL | SQDMlaL2 | SQDMlsL | SQDMlsL2
    );
    let wide_n = matches!(op, SAddW | SAddW2 | UAddW | UAddW2 | SSubW | SSubW2 | USubW | USubW2);
    let mut out = [0u64; 2];
    for i in 0..n {
        let x = if wide_n { ival(lane(&a, es + 1, i), es + 1, signed) } else { ival(lane(&a, es, off + i), es, signed) };
        let y = ival(lane(&b, es, off + i), es, signed);
        let d = lane(&d0, es + 1, i);
        let r: u64 = match op {
            SAddL | SAddL2 | UAddL | UAddL2 | SAddW | SAddW2 | UAddW | UAddW2 => (x + y) as u64,
            SSubL | SSubL2 | USubL | USubL2 | SSubW | SSubW2 | USubW | USubW2 => (x - y) as u64,
            SMullL | SMullL2 | UMullL | UMullL2 => (x * y) as u64,
            SMlaL | SMlaL2 | UMlaL | UMlaL2 => d.wrapping_add((x * y) as u64),
            SMlsL | SMlsL2 | UMlsL | UMlsL2 => d.wrapping_sub((x * y) as u64),
            SAbdL | SAbdL2 | UAbdL | UAbdL2 => (x - y).unsigned_abs() as u64,
            SAbaL | SAbaL2 | UAbaL | UAbaL2 => d.wrapping_add((x - y).unsigned_abs() as u64),
            SQDMull | SQDMull2 => sat_s(2 * x * y, 2 * bits, &mut qc),
            SQDMlaL | SQDMlaL2 | SQDMlsL | SQDMlsL2 => {
                let p = ival(sat_s(2 * x * y, 2 * bits, &mut qc), es + 1, true);
                let dv = ival(d, es + 1, true);
                let acc = if matches!(op, SQDMlsL | SQDMlsL2) { dv - p } else { dv + p };
                sat_s(acc, 2 * bits, &mut qc)
            }
            _ => 0,
        };
        put_lane(&mut out, es + 1, i, r);
    }
    set_qc(cpu, qc);
    cpu.set_vreg(rd, out);
}
