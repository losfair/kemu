// SPDX-License-Identifier: GPL-2.0
// SIMD shift-by-immediate and vector-by-element. Included by simd.rs.

#[allow(clippy::too_many_arguments)]
fn shift_imm(cpu: &mut CpuState, q: bool, u: bool, immh: u32, immb: u32, opcode: u8, rd: u32, rn: u32, scalar: bool) {
    // Source element size from immh (highest set bit).
    let esize: u8 = if immh & 0b1000 != 0 {
        3
    } else if immh & 0b0100 != 0 {
        2
    } else if immh & 0b0010 != 0 {
        1
    } else {
        0
    };
    let esz_bits = 8u32 << esize;
    let immhb = (immh << 3) | immb;
    let shl = immhb.wrapping_sub(esz_bits);       // left-shift amount
    let shr = (2 * esz_bits).wrapping_sub(immhb); // right-shift amount
    let lanes = if scalar { 1 } else { vbytes(q) >> esize };
    let mask = if esz_bits >= 64 { u64::MAX } else { (1u64 << esz_bits) - 1 };

    // Narrowing shifts (result element is half the source): SHRN/RSHRN,
    // SQSHRUN, SQSHRN/UQSHRN, SQRSHRN/UQRSHRN.
    if matches!(opcode, 0b10000 | 0b10001 | 0b10010 | 0b10011) {
        let src_es = esize + 1;
        let nlanes = 8u32 >> esize;
        let top = q;
        let mut out = if top { cpu.vreg(rd) } else { [0u64; 2] };
        let off = if top { nlanes } else { 0 };
        let rshn = (2 * esz_bits).wrapping_sub(immhb);
        let rounding = matches!(opcode, 0b10001 | 0b10011);
        for i in 0..nlanes {
            let v = get_lane(cpu, rn, src_es, i);
            let round = if rounding && rshn > 0 { 1u64 << (rshn - 1) } else { 0 };
            let r = (v.wrapping_add(round) >> rshn) & mask;
            put_lane(&mut out, esize, off + i, r);
        }
        cpu.set_vreg(rd, out);
        return;
    }

    // Widening left-shift long: SSHLL/USHLL (SHLL/SXTL/UXTL are aliases).
    if opcode == 0b10100 {
        let dst_es = esize + 1;
        let nlanes = 8u32 >> esize;
        let off = if q { nlanes } else { 0 };
        let dbits = 8u32 << dst_es;
        let dmask = if dbits >= 64 { u64::MAX } else { (1u64 << dbits) - 1 };
        let mut out = [0u64; 2];
        for i in 0..nlanes {
            let v = get_lane(cpu, rn, esize, off + i);
            let ext = if u { v } else { sext(v, esize) as u64 };
            put_lane(&mut out, dst_es, i, (ext << (shl & 63)) & dmask);
        }
        cpu.set_vreg(rd, out);
        return;
    }

    // Fixed-point convert: SCVTF/UCVTF (0b11100), FCVTZS/FCVTZU (0b11111).
    if opcode == 0b11100 || opcode == 0b11111 {
        let fbits = (2 * esz_bits).wrapping_sub(immhb);
        let f = fmt_of(esize);
        let mut c = sf::FpCtx::new(cpu.fpcr, cpu.fpsr);
        let mut out = [0u64; 2];
        for i in 0..lanes {
            let v = get_lane(cpu, rn, esize, i);
            let r = if opcode == 0b11100 {
                { let rm = c.rmode(); sf::from_fixed(&mut c, f, v, fbits, !u, esz_bits, rm) }
            } else {
                sf::to_fixed(&mut c, f, v, fbits, u, esz_bits, crate::softfloat::Rounding::Zero)
            };
            put_lane(&mut out, esize, i, r);
        }
        cpu.fpsr = c.fpsr & sf::FPSR_MASK;
        cpu.set_vreg(rd, out);
        return;
    }

    // Element-wise shifts.
    let mut out = [0u64; 2];
    for i in 0..lanes {
        let v = get_lane(cpu, rn, esize, i);
        let d = get_lane(cpu, rd, esize, i);
        let r = match opcode {
            0b01010 => v << (shl & 63),                      // SHL (U=0) / SLI (U=1)
            0b01100 => sat_shl(v, shl, esize, u),            // SQSHL/UQSHL
            0b01110 => sat_shl(v, shl, esize, true),         // SQSHLU
            0b01000 if u => shift_right_insert(v, d, shr, mask), // SRI
            _ => shift_right_variant(opcode, u, v, d, shr, esize, mask),
        };
        put_lane(&mut out, esize, i, r & mask);
    }
    cpu.set_vreg(rd, out);
}

fn shift_right_insert(v: u64, d: u64, shr: u32, mask: u64) -> u64 {
    let sh = shr & 63;
    let shifted = (v & mask) >> sh;
    // Preserve the top `sh` bits of the destination.
    let keep = if sh == 0 { 0 } else { !((1u64 << (64 - sh)).wrapping_sub(1)) } & mask;
    let _ = keep;
    let hi_mask = if sh >= 64 { mask } else { !(mask >> sh) & mask };
    (d & hi_mask) | shifted
}

fn sat_shl(v: u64, shl: u32, esize: u8, unsigned: bool) -> u64 {
    let sh = shl & 63;
    let bits = 8u32 << esize;
    if unsigned {
        let m = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
        let r = (v & m).checked_shl(sh).unwrap_or(u64::MAX);
        // saturate: if shifting out any bits, clamp to max
        let shifted_out = if sh == 0 { 0 } else { (v & m) >> (bits - sh.min(bits)) };
        if shifted_out != 0 || r > m { m } else { r & m }
    } else {
        let sv = sext(v, esize);
        let max = (1i64 << (bits - 1)) - 1;
        let min = -(1i64 << (bits - 1));
        let r = (sv as i128) << sh;
        let sat = r.clamp(min as i128, max as i128) as i64;
        (sat as u64) & (if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 })
    }
}

fn shift_right_variant(opcode: u8, u: bool, v: u64, d: u64, shr: u32, esize: u8, mask: u64) -> u64 {
    let sh = shr & 63;
    match opcode {
        0b00000 => {
            // SSHR / USHR
            if u {
                (v & mask) >> sh
            } else {
                (sext(v, esize) >> sh) as u64
            }
        }
        0b00100 => {
            // SSRA / USRA (accumulate)
            let s = if u { (v & mask) >> sh } else { (sext(v, esize) >> sh) as u64 };
            d.wrapping_add(s)
        }
        0b00010 => {
            // SRSHR / URSHR (rounding)
            let round = if sh > 0 { 1u64 << (sh - 1) } else { 0 };
            if u {
                ((v & mask).wrapping_add(round)) >> sh
            } else {
                ((sext(v, esize) + round as i64) >> sh) as u64
            }
        }
        0b00110 => {
            let round = if sh > 0 { 1u64 << (sh - 1) } else { 0 };
            let s = if u {
                ((v & mask).wrapping_add(round)) >> sh
            } else {
                ((sext(v, esize) + round as i64) >> sh) as u64
            };
            d.wrapping_add(s)
        }
        _ => (v & mask) >> sh,
    }
}

#[allow(clippy::too_many_arguments)]
fn indexed(cpu: &mut CpuState, q: bool, _u: bool, size: u8, opcode: u8, rd: u32, rn: u32, rm: u32, index: u32, scalar: bool) -> bool {
    // FP element ops: FMUL/FMLA/FMLS/FMULX by element; and integer MUL/MLA/MLS.
    let esize = size; // for FP ops, size encodes sz (2=S,3=D)
    let f = fmt_of(esize);
    let lanes = if scalar { 1 } else { vbytes(q) >> esize };
    let elem = get_lane(cpu, rm, esize, index);
    let mut out = [0u64; 2];
    let mut c = sf::FpCtx::new(cpu.fpcr, cpu.fpsr);
    match opcode {
        0b0001 => {
            // FMLA by element
            for i in 0..lanes {
                let a = get_lane(cpu, rn, esize, i);
                let d = get_lane(cpu, rd, esize, i);
                put_lane(&mut out, esize, i, sf::muladd(&mut c, f, d, a, elem, false, false));
            }
        }
        0b0101 => {
            for i in 0..lanes {
                let a = get_lane(cpu, rn, esize, i);
                let d = get_lane(cpu, rd, esize, i);
                put_lane(&mut out, esize, i, sf::muladd(&mut c, f, d, a, elem, false, true));
            }
        }
        0b1001 => {
            // FMUL by element
            for i in 0..lanes {
                let a = get_lane(cpu, rn, esize, i);
                put_lane(&mut out, esize, i, sf::mul(&mut c, f, a, elem));
            }
        }
        0b1000 => {
            // MUL (integer) by element
            let mask = if (8u32 << esize) >= 64 { u64::MAX } else { (1u64 << (8u32 << esize)) - 1 };
            for i in 0..lanes {
                let a = get_lane(cpu, rn, esize, i);
                put_lane(&mut out, esize, i, a.wrapping_mul(elem) & mask);
            }
        }
        _ => return false,
    }
    cpu.fpsr = c.fpsr & sf::FPSR_MASK;
    cpu.set_vreg(rd, out);
    true
}
