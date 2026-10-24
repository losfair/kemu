// SPDX-License-Identifier: GPL-2.0
// Data processing -- SIMD and floating point. Included by decode.rs.

fn decode_simd_fp(x: u32) -> Insn {
    let op0 = bits(x, 31, 28);
    let op1 = bits(x, 24, 23);
    let op2 = bits(x, 21, 19);
    let op3 = bits(x, 18, 10);
    let _ = (op2, op3);
    // Scalar floating-point (op0 == x0x1, with bit28==0? ) We route by the
    // classic masks instead, which are unambiguous.

    // --- Floating-point family: bit 28 == 0 and bits 25:24 == 11? Use the
    //     fixed masks from the ARM "Data Processing -- Scalar Floating-Point
    //     and Advanced SIMD" top-level. ---

    // Scalar FP data processing: 0001 1110 ... (op0=0001, bit24=1, bit21=1)
    if bits(x, 28, 24) == 0b11110 {
        return decode_fp(x);
    }
    if bits(x, 28, 24) == 0b11111 {
        return decode_fp_3src(x);
    }
    // Advanced SIMD: everything else in this group.
    let _ = (op0, op1);
    decode_asimd(x)
}

// ------------------------- Scalar floating point -------------------------

fn decode_fp(x: u32) -> Insn {
    // Common fields
    // Note: bit31 is M for the FP-FP data-processing forms but `sf` for the
    // FP<->integer conversions, so it is validated per-subclass, not here.
    if bit(x, 29) {
        return Insn::Undefined; // S must be 0
    }
    let ptype = bits(x, 23, 22) as u8;
    let op21 = bits(x, 21, 21);
    // Distinguish sub-classes by bits 15:10 region.
    // 1. Conversion between FP and integer: bit21==1 && bits 15:10 pattern.
    if op21 == 1 {
        // FP<->integer conversion has bits 15:10 == 000000.
        if bits(x, 15, 10) == 0 {
            let sf = bit(x, 31);
            let rmode = bits(x, 20, 19);
            let opcode = bits(x, 18, 16);
            let rd = bits(x, 4, 0);
            let rn = bits(x, 9, 5);
            return decode_fp_int_conv(x, sf, ptype, rmode, opcode, rd, rn);
        }
        // Otherwise data-processing (1/2 source), compare, or conditional.
        let b1110 = bits(x, 11, 10);
        match b1110 {
            0b00 => {
                // Could be: FCMP (bits 15:10 = xxx000), FP data-proc(2 source)
                // uses bits 11:10 != 00? Actually distinguish by bits 15:12.
                // FP data-processing (2 source): bits 15:12 = opcode, 11:10=10.
                // So b1110==00 here is FCMP/FCCMP? No—use explicit masks below.
                decode_fp_misc00(x)
            }
            0b01 => {
                // FCCMP / FCCMPE
                decode_fp_ccmp(x)
            }
            0b10 => {
                // FP data-processing (2 source)
                decode_fp_2src(x)
            }
            0b11 => {
                // FCSEL
                decode_fp_csel(x)
            }
            _ => Insn::Undefined,
        }
    } else {
        // bit21 == 0: FP<->fixed-point conversions, or FP immediate.
        decode_fp_fixed_or_imm(x)
    }
}

fn decode_fp_misc00(x: u32) -> Insn {
    // bits 11:10 == 00. This covers:
    //  - FP compare (opcode2 bits 15:10): bits 15:14=00, 13:10=1000
    //  - FP conditional compare handled elsewhere (bits11:10==01)
    //  - FP data-processing (1 source): bits 15:10 = opcode 00 ???
    // Use bits 15:10 directly.
    let ftype = bits(x, 23, 22) as u8;
    let b1510 = bits(x, 15, 10);
    // FP compare: bits 15:10 == 0b??1000 with specific opcode2 in 20:16.
    if b1510 & 0b000111 == 0b000000 && bits(x, 14, 10) == 0b01000 {
        // FCMP / FCMPE
        let rm = bits(x, 20, 16);
        let rn = bits(x, 9, 5);
        let opc = bits(x, 4, 3); // opcode2 low bits select zero/E
        let zero = bit(x, 3);
        let signal = bit(x, 4);
        let _ = opc;
        return Insn::FpCmp { ftype, rn, rm, zero, signal };
    }
    // FP data-processing (1 source): bits 15:10 = opcode, with bits 20:15 form.
    // Encoding: ptype, 1, opcode(6) at bits 20:15, 10000 at 14:10.
    if bits(x, 14, 10) == 0b10000 {
        return decode_fp_1src(x);
    }
    Insn::Undefined
}

fn decode_fp_1src(x: u32) -> Insn {
    let ftype = bits(x, 23, 22) as u8;
    let opcode = bits(x, 20, 15);
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    let op = match opcode {
        0b000000 => Fp1Op::Mov,
        0b000001 => Fp1Op::Abs,
        0b000010 => Fp1Op::Neg,
        0b000011 => Fp1Op::Sqrt,
        0b000100 | 0b000101 | 0b000111 => {
            // FCVT to another precision: opcode 0001xx, target in low 2 bits
            let to = match opcode & 0b11 {
                0b00 => 0u8, // S
                0b01 => 1,   // D
                0b11 => 2,   // H
                _ => return Insn::Undefined,
            };
            return Insn::Fp1 { ftype, op: Fp1Op::Cvt, to, rd, rn };
        }
        0b001000 => Fp1Op::RintN,
        0b001001 => Fp1Op::RintP,
        0b001010 => Fp1Op::RintM,
        0b001011 => Fp1Op::RintZ,
        0b001100 => Fp1Op::RintA,
        0b001110 => Fp1Op::RintX,
        0b001111 => Fp1Op::RintI,
        0b010000 => Fp1Op::Rint32Z,
        0b010001 => Fp1Op::Rint32X,
        0b010010 => Fp1Op::Rint64Z,
        0b010011 => Fp1Op::Rint64X,
        0b011111 => Fp1Op::Recpx, // BFCVT occupies 0b000110 (not advertised)
        _ => return Insn::Undefined,
    };
    Insn::Fp1 { ftype, op, to: ftype, rd, rn }
}

fn decode_fp_2src(x: u32) -> Insn {
    let ftype = bits(x, 23, 22) as u8;
    let rm = bits(x, 20, 16);
    let opcode = bits(x, 15, 12);
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    let op = match opcode {
        0b0000 => Fp2Op::Mul,
        0b0001 => Fp2Op::Div,
        0b0010 => Fp2Op::Add,
        0b0011 => Fp2Op::Sub,
        0b0100 => Fp2Op::Max,
        0b0101 => Fp2Op::Min,
        0b0110 => Fp2Op::MaxNm,
        0b0111 => Fp2Op::MinNm,
        0b1000 => Fp2Op::Nmul,
        _ => return Insn::Undefined,
    };
    Insn::Fp2 { ftype, op, rd, rn, rm }
}

fn decode_fp_3src(x: u32) -> Insn {
    let ftype = bits(x, 23, 22) as u8;
    let o1 = bit(x, 21);
    let rm = bits(x, 20, 16);
    let o0 = bit(x, 15);
    let ra = bits(x, 14, 10);
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    // (o1,o0): 00=FMADD,01=FMSUB,10=FNMADD,11=FNMSUB
    let (neg, sub) = match (o1, o0) {
        (false, false) => (false, false),
        (false, true) => (false, true),
        (true, false) => (true, false),
        (true, true) => (true, true),
    };
    Insn::Fp3 { ftype, neg, sub, rd, rn, rm, ra }
}

fn decode_fp_ccmp(x: u32) -> Insn {
    let ftype = bits(x, 23, 22) as u8;
    let rm = bits(x, 20, 16);
    let cond = bits(x, 15, 12);
    let rn = bits(x, 9, 5);
    let signal = bit(x, 4);
    let nzcv = bits(x, 3, 0);
    Insn::FpCCmp { ftype, rn, rm, nzcv, cond, signal }
}

fn decode_fp_csel(x: u32) -> Insn {
    let ftype = bits(x, 23, 22) as u8;
    let rm = bits(x, 20, 16);
    let cond = bits(x, 15, 12);
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    Insn::FpCSel { ftype, rd, rn, rm, cond }
}

fn decode_fp_fixed_or_imm(x: u32) -> Insn {
    let sf = bit(x, 31);
    let ftype = bits(x, 23, 22) as u8;
    let _b1110 = bits(x, 15, 10);
    // FP immediate: bits 12:10 == 100, bits 9:5 == imm5(zero), imm8 in 20:13.
    if bits(x, 12, 10) == 0b100 {
        let imm8 = bits(x, 20, 13) as u8;
        let rd = bits(x, 4, 0);
        if bits(x, 9, 5) != 0 {
            return Insn::Undefined;
        }
        return Insn::FpImm { ftype, rd, imm8 };
    }
    // FP <-> integer conversions (bit21==0, bits 15:10 pattern 000000 for int,
    // else fixed-point).
    let rmode = bits(x, 20, 19);
    let opcode = bits(x, 18, 16);
    let scale = bits(x, 15, 10);
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    // bit21==0: this is always a fixed-point conversion. fbits = 64 - scale.
    let fbits = 64 - scale;
    let unsigned = bit(x, 16);
    let to_fp = bits(x, 18, 17) == 0b00; // opcode 010/011 = *CVTF, 000/001 = FCVTZ*
    // opcode: 010=SCVTF,011=UCVTF (int->fp), 000=FCVTZS,001=FCVTZU (fp->int)
    let op = match opcode {
        0b010 => FcvtOp::FixedToF { unsigned: false, fbits },
        0b011 => FcvtOp::FixedToF { unsigned: true, fbits },
        0b000 => FcvtOp::FtoFixed { unsigned: false, fbits },
        0b001 => FcvtOp::FtoFixed { unsigned: true, fbits },
        _ => return Insn::Undefined,
    };
    let _ = (unsigned, to_fp, rmode);
    Insn::FpCvt { ftype, sf, op, rd, rn }
}

fn decode_fp_int_conv(x: u32, sf: bool, ftype: u8, rmode: u32, opcode: u32, rd: u32, rn: u32) -> Insn {
    let _ = x;
    // rmode(2) : opcode(3)
    // FCVT[NPMZA][SU], SCVTF/UCVTF, FMOV, FJCVTZS
    let op = match (rmode, opcode) {
        (0b00, 0b000) => FcvtOp::FtoI { round: 0 /*N: tie-even? actually FCVTNS*/, unsigned: false },
        (0b00, 0b001) => FcvtOp::FtoI { round: 0, unsigned: true },
        (0b00, 0b010) => FcvtOp::ItoF { unsigned: false }, // SCVTF
        (0b00, 0b011) => FcvtOp::ItoF { unsigned: true },  // UCVTF
        (0b00, 0b100) => FcvtOp::FtoI { round: 4 /*A*/, unsigned: false },
        (0b00, 0b101) => FcvtOp::FtoI { round: 4, unsigned: true },
        (0b00, 0b110) => FcvtOp::Fmov { to_fp: false, top: false }, // FMOV to GPR
        (0b00, 0b111) => FcvtOp::Fmov { to_fp: true, top: false },  // FMOV from GPR
        (0b01, 0b000) => FcvtOp::FtoI { round: 1 /*P*/, unsigned: false },
        (0b01, 0b001) => FcvtOp::FtoI { round: 1, unsigned: true },
        (0b01, 0b110) => FcvtOp::Fmov { to_fp: false, top: true }, // FMOV Xd, Vn.D[1]
        (0b01, 0b111) => FcvtOp::Fmov { to_fp: true, top: true },  // FMOV Vd.D[1], Xn
        (0b10, 0b000) => FcvtOp::FtoI { round: 2 /*M*/, unsigned: false },
        (0b10, 0b001) => FcvtOp::FtoI { round: 2, unsigned: true },
        (0b11, 0b000) => FcvtOp::FtoI { round: 3 /*Z*/, unsigned: false },
        (0b11, 0b001) => FcvtOp::FtoI { round: 3, unsigned: true },
        (0b11, 0b110) if ftype == 0b01 => FcvtOp::Fjcvt, // FJCVTZS
        _ => return Insn::Undefined,
    };
    Insn::FpCvt { ftype, sf, op, rd, rn }
}

// ------------------------- Advanced SIMD -------------------------

fn decode_asimd(x: u32) -> Insn {
    // Route by high-level pattern. We use the explicit top-level groups.
    let q = bit(x, 30);
    let u = bit(x, 29);

    // --- Advanced SIMD three same (0Q U 01110 size 1 Rm opcode 1 Rn Rd) ---
    if bits(x, 28, 24) == 0b01110 && bit(x, 21) && bit(x, 10) {
        return decode_simd_three_same(x, q, u);
    }
    // --- three different (0Q U 01110 size 1 Rm opcode 00 Rn Rd), bit10==0,bit11==0 ---
    if bits(x, 28, 24) == 0b01110 && bit(x, 21) && bits(x, 11, 10) == 0b00 {
        return decode_simd_three_diff(x, q, u);
    }
    // --- two-register misc (0Q U 01110 size 10000 opcode 10 Rn Rd) ---
    if bits(x, 28, 24) == 0b01110 && bits(x, 21, 17) == 0b10000 && bits(x, 11, 10) == 0b10 {
        return decode_simd_two_misc(x, q, u);
    }
    // --- across lanes (0Q U 01110 size 11000 opcode 10 Rn Rd) ---
    if bits(x, 28, 24) == 0b01110 && bits(x, 21, 17) == 0b11000 && bits(x, 11, 10) == 0b10 {
        return decode_simd_across(x, q, u);
    }
    // --- copy (0Q op 01110000 imm5 0 imm4 1 Rn Rd) ---
    if bits(x, 28, 21) == 0b01110000 && bit(x, 15) == false && bit(x, 10) {
        return decode_simd_copy(x, q, u);
    }
    // --- modified immediate (0Q op 0111100000 abc cmode o1 defgh 1 Rd) ---
    if bits(x, 28, 19) == 0b0111100000 && bit(x, 10) {
        return decode_simd_mod_imm(x, q, u);
    }
    // --- shift by immediate (0Q U 011110 immh immb opcode 1 Rn Rd), immh!=0 ---
    if bits(x, 28, 23) == 0b011110 && bit(x, 10) && bits(x, 22, 19) != 0 {
        return decode_simd_shift_imm(x, q, u, false);
    }
    // --- vector x indexed element (0Q U 01111 size L M Rm opcode H 0 Rn Rd) ---
    if bits(x, 28, 24) == 0b01111 {
        return decode_simd_indexed(x, q, u, false);
    }
    // --- EXT (0Q 101110 00 0 Rm 0 imm4 0 Rn Rd) ---
    if bits(x, 29, 24) == 0b101110 && bits(x, 23, 22) == 0b00 && bit(x, 21) == false && bit(x, 15) == false && bit(x, 10) == false {
        let imm4 = bits(x, 14, 11);
        let rm = bits(x, 20, 16);
        let rn = bits(x, 9, 5);
        let rd = bits(x, 4, 0);
        return Insn::SimdExt { q, imm4, rd, rn, rm };
    }
    // --- permute ZIP/UZP/TRN (0Q 001110 size 0 Rm 0 opcode 10 Rn Rd) ---
    if bits(x, 29, 24) == 0b001110 && bit(x, 21) == false && bit(x, 15) == false && bits(x, 11, 10) == 0b10 {
        let size = bits(x, 23, 22) as u8;
        let opcode = bits(x, 14, 12) as u8;
        let rm = bits(x, 20, 16);
        let rn = bits(x, 9, 5);
        let rd = bits(x, 4, 0);
        return Insn::SimdPermute { q, size, opcode, rd, rn, rm };
    }
    // --- TBL/TBX (0Q 001110 00 0 Rm 0 len op 00 Rn Rd) ---
    if bits(x, 29, 24) == 0b001110 && bits(x, 23, 22) == 0b00 && bit(x, 21) == false && bit(x, 15) == false && bits(x, 11, 10) == 0b00 {
        let len = bits(x, 14, 13) as u8;
        let tbx = bit(x, 12);
        let rm = bits(x, 20, 16);
        let rn = bits(x, 9, 5);
        let rd = bits(x, 4, 0);
        return Insn::SimdTbl { q, len, tbx, rd, rn, rm };
    }

    // ---- Scalar advanced SIMD (bits 28:24 == 11110 / 11111) ----
    if bits(x, 28, 24) == 0b11110 && bit(x, 21) && bit(x, 10) {
        return decode_simd_three_same(x, true, u).scalarize();
    }
    if bits(x, 28, 24) == 0b11110 && bits(x, 21, 17) == 0b10000 && bits(x, 11, 10) == 0b10 {
        return decode_simd_two_misc(x, true, u).scalarize();
    }
    if bits(x, 28, 24) == 0b11110 && bit(x, 21) && bits(x, 11, 10) == 0b00 {
        return decode_simd_three_diff(x, true, u).scalarize();
    }
    if bits(x, 28, 24) == 0b11111 {
        return decode_simd_indexed(x, q, u, true);
    }
    if bits(x, 28, 23) == 0b111110 && bit(x, 10) && bits(x, 22, 19) != 0 {
        return decode_simd_shift_imm(x, q, u, true);
    }
    if bits(x, 28, 21) == 0b11110000 && bit(x, 15) == false && bit(x, 10) {
        // scalar copy (DUP element) — only DUP is valid
        let imm5 = bits(x, 20, 16);
        let rn = bits(x, 9, 5);
        let rd = bits(x, 4, 0);
        if bits(x, 14, 11) == 0 {
            return Insn::SimdScalarCopy { imm5, rd, rn };
        }
        return Insn::Undefined;
    }
    // --- across-lanes scalar (11110 11000) ---
    if bits(x, 28, 24) == 0b11110 && bits(x, 21, 17) == 0b11000 && bits(x, 11, 10) == 0b10 {
        return decode_simd_across(x, true, u);
    }

    // --- Crypto: AES (01001110 00 10100 opcode 10 Rn Rd) ---
    if bits(x, 31, 24) == 0b01001110 && bits(x, 23, 22) == 0b00 && bits(x, 21, 17) == 0b10100 && bits(x, 11, 10) == 0b10 {
        let opcode = bits(x, 16, 12);
        let rn = bits(x, 9, 5);
        let rd = bits(x, 4, 0);
        return match opcode {
            0b00100 => Insn::Aese { rd, rn },
            0b00101 => Insn::Aesd { rd, rn },
            0b00110 => Insn::Aesmc { rd, rn },
            0b00111 => Insn::Aesimc { rd, rn },
            _ => Insn::Undefined,
        };
    }
    // --- SHA1/SHA256 three-reg (01011110 00 0 Rm 0 opcode 00 Rn Rd) ---
    if bits(x, 31, 24) == 0b01011110 && bits(x, 23, 22) == 0b00 && bit(x, 21) == false && bit(x, 15) == false && bits(x, 11, 10) == 0b00 {
        let opcode = bits(x, 14, 12) as u8;
        let rm = bits(x, 20, 16);
        let rn = bits(x, 9, 5);
        let rd = bits(x, 4, 0);
        return Insn::Sha1 { op: opcode, rd, rn, rm };
    }
    if bits(x, 31, 24) == 0b01011110 && bits(x, 23, 22) == 0b00 && bit(x, 21) == false && bit(x, 15) == false && bits(x, 11, 10) == 0b01 {
        // SHA256H/H2/SU1 (bits 11:10 vary); group under Sha256 three-reg
        let opcode = bits(x, 14, 12) as u8;
        let rm = bits(x, 20, 16);
        let rn = bits(x, 9, 5);
        let rd = bits(x, 4, 0);
        return Insn::Sha256 { op: opcode, rd, rn, rm };
    }
    // --- SHA1/SHA256 two-reg (01011110 28:24=10100 ...) ---
    if bits(x, 31, 24) == 0b01011110 && bits(x, 23, 22) == 0b00 && bits(x, 21, 17) == 0b10100 && bits(x, 11, 10) == 0b10 {
        let opcode = bits(x, 16, 12);
        let rn = bits(x, 9, 5);
        let rd = bits(x, 4, 0);
        return match opcode {
            0b00000 => Insn::Sha1 { op: 0b100, rd, rn, rm: 0 }, // SHA1H
            0b00001 => Insn::Sha1 { op: 0b101, rd, rn, rm: 0 }, // SHA1SU1
            0b00010 => Insn::Sha256 { op: 0b100, rd, rn, rm: 0 }, // SHA256SU0
            _ => Insn::Undefined,
        };
    }

    Insn::Undefined
}

// Helper to turn a vector form into its scalar form.
trait Scalarize {
    fn scalarize(self) -> Insn;
}
impl Scalarize for Insn {
    fn scalarize(self) -> Insn {
        match self {
            Insn::SimdThree { q, u, size, op, rd, rn, rm, .. } => {
                Insn::SimdThree { q, u, size, op, rd, rn, rm, scalar: true }
            }
            Insn::SimdMisc { q, u, size, op, rd, rn, .. } => {
                Insn::SimdMisc { q, u, size, op, rd, rn, scalar: true }
            }
            other => other,
        }
    }
}

include!("decode_simd2.rs");
include!("decode_simd_ldst.rs");
