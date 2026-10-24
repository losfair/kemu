// SPDX-License-Identifier: GPL-2.0
// SIMD shift-by-immediate and vector-by-element. Included by simd.rs.

#[allow(clippy::too_many_arguments)]
fn shift_imm(cpu: &mut CpuState, q: bool, u: bool, immh: u32, immb: u32, opcode: u8, rd: u32, rn: u32, scalar: bool) {
    // Determine element size from immh.
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
    // Left shift amount = immhb - esz_bits ; right = 2*esz_bits - immhb.
    let shl = immhb.wrapping_sub(esz_bits);
    let shr = (2 * esz_bits).wrapping_sub(immhb);
    let lanes = if scalar { 1 } else { vbytes(q) >> esize };
    let mask = if esz_bits >= 64 { u64::MAX } else { (1u64 << esz_bits) - 1 };

    // Narrowing shifts (SHRN/RSHRN/SQSHRN...) have opcode in 0b1000x..
    let narrowing = matches!(opcode, 0b10000 | 0b10001 | 0b10010 | 0b10011 | 0b10100 | 0b10101);
    if narrowing {
        let src_es = esize + 1;
        let nlanes = 8u32 >> esize;
        let top = q; // Q selects the upper-half (2) variant
        let mut out = if top { cpu.vreg(rd) } else { [0u64; 2] };
        let off = if top { nlanes } else { 0 };
        let rshn = (2 * esz_bits).wrapping_sub(immhb); // shift right amount
        for i in 0..nlanes {
            let v = get_lane(cpu, rn, src_es, i);
            let round = if matches!(opcode, 0b10001 | 0b10011 | 0b10101) {
                1u64 << (rshn - 1)
            } else {
                0
            };
            let shifted = (v.wrapping_add(round)) >> rshn;
            let r = shifted & mask;
            put_lane(&mut out, esize, off + i, r);
        }
        cpu.set_vreg(rd, out);
        return;
    }

    let mut out = [0u64; 2];
    for i in 0..lanes {
        let v = get_lane(cpu, rn, esize, i);
        let d = get_lane(cpu, rd, esize, i);
        let r = match opcode {
            0b00000 => v << (shl & 63),                     // SHL
            0b00010 => {
                // SSRA/USRA (accumulate) & SSHR/USHR distinguished by... opcode
                let s = if u { v >> (shr & 63) } else { (sext(v, esize) >> (shr & 63)) as u64 };
                s
            }
            0b01010 => v << (shl & 63),                     // SHL (alt slot)
            _ => {
                // Right shifts: opcode 0b00000 SSHR? Use standard mapping:
                shift_right_variant(opcode, u, v, d, shr, esize, mask)
            }
        };
        put_lane(&mut out, esize, i, r & mask);
    }
    // SHL uses opcode 0b01010; fix by recomputing for known opcodes.
    if opcode == 0b01010 {
        out = [0u64; 2];
        for i in 0..lanes {
            let v = get_lane(cpu, rn, esize, i);
            put_lane(&mut out, esize, i, (v << (shl & 63)) & mask);
        }
    }
    cpu.set_vreg(rd, out);
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
