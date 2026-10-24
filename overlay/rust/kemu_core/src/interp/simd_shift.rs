// SPDX-License-Identifier: GPL-2.0
// SIMD shift-by-immediate and vector-by-element. Included by simd.rs.

/// Execute a (scalar) shift by immediate from its raw fields. Returns false
/// for encodings the decoder should already have rejected.
#[allow(clippy::too_many_arguments)]
fn shift_imm(cpu: &mut CpuState, q: bool, u: bool, immh: u32, immb: u32, opcode: u8, rd: u32, rn: u32, scalar: bool) -> bool {
    if immh == 0 {
        return false;
    }
    let esize: u8 = (31 - immh.leading_zeros()) as u8; // highest set bit of immh
    let bits = 8u32 << esize;
    let immhb = (immh << 3) | immb;
    let shl = immhb - bits; // left shift: UInt(immh:immb) - esize
    let shr = 2 * bits - immhb; // right shift: 2*esize - UInt(immh:immb)
    let src = cpu.vreg(rn);
    let d0 = cpu.vreg(rd);
    let m = lmask(bits);
    let mut qc = false;
    let mut out = [0u64; 2];

    match (u, opcode) {
        // ---- narrowing: source 2*esize, result esize ----
        (_, 0b10000) | (_, 0b10001) | (_, 0b10010) | (_, 0b10011) => {
            if esize == 3 {
                return false;
            }
            let round = opcode & 1 != 0;
            // (src signed, dst unsigned, saturate)
            let (s_signed, d_unsigned, saturate) = match (u, opcode >> 1) {
                (false, 0b1000) => (false, true, false), // SHRN/RSHRN
                (true, 0b1000) => (true, true, true),    // SQSHRUN/SQRSHRUN
                (false, _) => (true, false, true),       // SQSHRN/SQRSHRN
                (true, _) => (false, true, true),        // UQSHRN/UQRSHRN
            };
            let n = if scalar { 1 } else { 8u32 >> esize };
            let mut half = [0u64; 2];
            for i in 0..n {
                let e = ival(lane(&src, esize + 1, i), esize + 1, s_signed);
                let rc = if round { 1i128 << (shr - 1) } else { 0 };
                let v = (e + rc) >> shr;
                let r = if saturate { sat(v, bits, d_unsigned, &mut qc) } else { (v as u64) & m };
                put_lane(&mut half, esize, i, r);
            }
            set_qc(cpu, qc);
            if scalar {
                cpu.set_vreg(rd, half);
            } else {
                write_part(cpu, rd, q, half[0]);
            }
            return true;
        }
        // ---- long: SSHLL/USHLL ----
        (_, 0b10100) => {
            if esize == 3 {
                return false;
            }
            let n = 8u32 >> esize;
            let off = if q { n } else { 0 };
            for i in 0..n {
                let e = ival(lane(&src, esize, off + i), esize, !u);
                put_lane(&mut out, esize + 1, i, (e << shl) as u64);
            }
            cpu.set_vreg(rd, out);
            return true;
        }
        // ---- fixed-point conversions ----
        (_, 0b11100) | (_, 0b11111) => {
            if esize < 2 {
                return false;
            }
            let f = fmt_of(esize);
            let fbits = shr;
            let lanes = if scalar { 1 } else { vbytes(q) >> esize };
            let mut c = sf::FpCtx::new(cpu.fpcr, cpu.fpsr);
            for i in 0..lanes {
                let v = lane(&src, esize, i);
                let r = if opcode == 0b11100 {
                    let rm = c.rmode();
                    sf::from_fixed(&mut c, f, v, fbits, !u, bits, rm)
                } else {
                    sf::to_fixed(&mut c, f, v, fbits, u, bits, sf::Rounding::Zero)
                };
                put_lane(&mut out, esize, i, r);
            }
            cpu.fpsr = c.fpsr & sf::FPSR_MASK;
            write_vec(cpu, rd, q && !scalar, out);
            return true;
        }
        _ => {}
    }

    let lanes = if scalar { 1 } else { vbytes(q) >> esize };
    for i in 0..lanes {
        let v = lane(&src, esize, i);
        let d = lane(&d0, esize, i);
        let e = ival(v, esize, !u);
        let rshift = |round: bool| -> u64 {
            let rc = if round { 1i128 << (shr - 1) } else { 0 };
            ((e + rc) >> shr) as u64
        };
        let r = match (u, opcode) {
            (_, 0b00000) => rshift(false),                // SSHR/USHR
            (_, 0b00010) => d.wrapping_add(rshift(false)), // SSRA/USRA
            (_, 0b00100) => rshift(true),                 // SRSHR/URSHR
            (_, 0b00110) => d.wrapping_add(rshift(true)), // SRSRA/URSRA
            (true, 0b01000) => {
                // SRI
                let mask = if shr >= 64 { 0 } else { m >> shr };
                (d & !mask) | ((v & m).checked_shr(shr).unwrap_or(0) & mask)
            }
            (false, 0b01010) => v << shl, // SHL
            (true, 0b01010) => {
                // SLI
                let mask = (m << shl) & m;
                (d & !mask) | ((v << shl) & mask)
            }
            (false, 0b01110) => sat_s(ival(v, esize, true) << shl, bits, &mut qc), // SQSHL
            (true, 0b01110) => sat_u(ival(v, esize, false) << shl, bits, &mut qc), // UQSHL
            (true, 0b01100) => sat_u(ival(v, esize, true) << shl, bits, &mut qc),  // SQSHLU
            _ => return false,
        };
        put_lane(&mut out, esize, i, r & m);
    }
    set_qc(cpu, qc);
    write_vec(cpu, rd, q && !scalar, out);
    true
}

/// Vector / scalar by element.
#[allow(clippy::too_many_arguments)]
fn indexed(cpu: &mut CpuState, q: bool, u: bool, size: u8, opcode: u8, rd: u32, rn: u32, rm: u32, index: u32, scalar: bool) -> bool {
    let esize = size;
    let bits = 8u32 << esize;
    let a = cpu.vreg(rn);
    let b = cpu.vreg(rm);
    let d0 = cpu.vreg(rd);
    let elem = lane(&b, esize, index);
    let mut out = [0u64; 2];
    let mut qc = false;
    let lanes = if scalar { 1 } else { vbytes(q) >> esize };
    match (u, opcode) {
        // ---- FP ----
        (false, 0b0001) | (false, 0b0101) | (false, 0b1001) | (true, 0b1001) => {
            let f = fmt_of(esize);
            let mut c = sf::FpCtx::new(cpu.fpcr, cpu.fpsr);
            for i in 0..lanes {
                let x = lane(&a, esize, i);
                let r = match (u, opcode) {
                    (false, 0b0001) => sf::muladd(&mut c, f, lane(&d0, esize, i), x, elem, false, false),
                    (false, 0b0101) => sf::muladd(&mut c, f, lane(&d0, esize, i), x, elem, false, true),
                    (false, _) => sf::mul(&mut c, f, x, elem),
                    _ => sf::mulx(&mut c, f, x, elem),
                };
                put_lane(&mut out, esize, i, r);
            }
            cpu.fpsr = c.fpsr & sf::FPSR_MASK;
            write_vec(cpu, rd, q && !scalar, out);
        }
        // ---- dot product ----
        (_, 0b1110) => {
            for i in 0..vbytes(q) / 4 {
                let mut acc = lane(&d0, 2, i) as i128;
                for j in 0..4 {
                    acc += ival(lane(&a, 0, 4 * i + j), 0, !u) * ival(lane(&b, 0, 4 * index + j), 0, !u);
                }
                put_lane(&mut out, 2, i, acc as u64);
            }
            write_vec(cpu, rd, q, out);
        }
        // ---- same-size integer ----
        (true, 0b0000) | (true, 0b0100) | (false, 0b1000) => {
            for i in 0..lanes {
                let x = lane(&a, esize, i);
                let p = x.wrapping_mul(elem);
                let r = match opcode {
                    0b0000 => lane(&d0, esize, i).wrapping_add(p),
                    0b0100 => lane(&d0, esize, i).wrapping_sub(p),
                    _ => p,
                };
                put_lane(&mut out, esize, i, r);
            }
            write_vec(cpu, rd, q, out);
        }
        (false, 0b1100) | (false, 0b1101) | (true, 0b1101) | (true, 0b1111) => {
            let y = ival(elem, esize, true);
            for i in 0..lanes {
                let x = ival(lane(&a, esize, i), esize, true);
                let r = match (u, opcode) {
                    (false, 0b1100) => sat_s((2 * x * y) >> bits, bits, &mut qc),
                    (false, _) => sat_s((2 * x * y + (1i128 << (bits - 1))) >> bits, bits, &mut qc),
                    _ => {
                        let d = ival(lane(&d0, esize, i), esize, true);
                        let p = 2 * x * y;
                        let acc = if opcode == 0b1111 { (d << bits) - p } else { (d << bits) + p };
                        sat_s((acc + (1i128 << (bits - 1))) >> bits, bits, &mut qc)
                    }
                };
                put_lane(&mut out, esize, i, r);
            }
            set_qc(cpu, qc);
            write_vec(cpu, rd, q && !scalar, out);
        }
        // ---- long ----
        (_, 0b0010) | (_, 0b0110) | (_, 0b1010) | (false, 0b0011) | (false, 0b0111) | (false, 0b1011) => {
            let sq = !u && opcode & 1 == 1; // SQDMLAL/SQDMLSL/SQDMULL
            let signed = !u;
            let n = if scalar { 1 } else { 8u32 >> esize };
            let off = if q && !scalar { n } else { 0 };
            let y = ival(elem, esize, signed);
            for i in 0..n {
                let x = ival(lane(&a, esize, off + i), esize, signed);
                let d = lane(&d0, esize + 1, i);
                let r = if sq {
                    let p = sat_s(2 * x * y, 2 * bits, &mut qc);
                    if opcode == 0b1011 {
                        p
                    } else {
                        let pv = ival(p, esize + 1, true);
                        let dv = ival(d, esize + 1, true);
                        sat_s(if opcode == 0b0111 { dv - pv } else { dv + pv }, 2 * bits, &mut qc)
                    }
                } else {
                    let p = (x * y) as u64;
                    match opcode {
                        0b0010 => d.wrapping_add(p),
                        0b0110 => d.wrapping_sub(p),
                        _ => p,
                    }
                };
                put_lane(&mut out, esize + 1, i, r);
            }
            set_qc(cpu, qc);
            cpu.set_vreg(rd, out);
        }
        _ => return false,
    }
    true
}
