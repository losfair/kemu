// SPDX-License-Identifier: GPL-2.0
// Data processing -- Scalar Floating-Point and Advanced SIMD. Included by
// decode.rs.
//
// The dispatch mirrors the A64 encoding index ("simd_dp" group) of the Arm
// A64 ISA XML; each class decoder accepts exactly the encodings allocated
// for the advertised feature set (FP, AdvSIMD, AES, PMULL, SHA1, SHA256,
// RDM, DotProd, JSCVT, FRINTTS) and applies the ASL decode-time UNDEFINED
// checks. FP16 arithmetic, BF16, FHM, FCMA, I8MM, SHA3/SHA512/SM3/SM4 and
// FP8 encodings decode as `Undefined`.

/// Parse a 32-character bit pattern ('0', '1', anything else = don't care;
/// spaces and '_' ignored) into (mask, value) at compile time.
const fn pat(s: &[u8]) -> (u32, u32) {
    let mut m = 0u32;
    let mut v = 0u32;
    let mut i = 0;
    let mut n = 0;
    while i < s.len() {
        let c = s[i];
        i += 1;
        if c == b' ' || c == b'_' {
            continue;
        }
        m <<= 1;
        v <<= 1;
        if c == b'0' {
            m |= 1;
        } else if c == b'1' {
            m |= 1;
            v |= 1;
        }
        n += 1;
    }
    assert!(n == 32);
    (m, v)
}

macro_rules! is {
    ($x:expr, $p:literal) => {{
        const P: (u32, u32) = pat($p);
        ($x & P.0) == P.1
    }};
}

fn decode_simd_fp(x: u32) -> Insn {
    // op0 = 31:28, op1 = 24:23, op2 = 22:19, op3 = 18:10.
    // Scalar floating point: op0 == x0x1.
    if is!(x, b"x0x1 xxxx xxxx xxxx xxxx xxxx xxxx xxxx") {
        return decode_fp(x);
    }
    if bit(x, 31) {
        // 10x0, 1100 (SHA3/SHA512/SM3/SM4: not advertised), 1110, 11x1.
        return Insn::Undefined;
    }
    let q = bit(x, 30);
    let u = bit(x, 29);
    // Cryptographic AES: 0100, op1=0x, op2=x101, op3=00xxxxx10
    if is!(x, b"0100 xxx 0x x101 00xxxxx10 xxxxxxxxxx") {
        return decode_crypto_aes(x);
    }
    // Cryptographic three-register SHA: 0101, 0x, x0xx, xxx0xxx00
    if is!(x, b"0101 xxx 0x x0xx xxx0xxx00 xxxxxxxxxx") {
        return decode_crypto_sha3(x);
    }
    // Cryptographic two-register SHA: 0101, 0x, x101, 00xxxxx10
    if is!(x, b"0101 xxx 0x x101 00xxxxx10 xxxxxxxxxx") {
        return decode_crypto_sha2(x);
    }
    if bit(x, 28) {
        // ---- Advanced SIMD scalar: op0 = 01x1 ----
        if !q {
            return Insn::Undefined; // 00x1 is scalar FP (handled above)
        }
        if is!(x, b"01x1 xxx 00 00xx xxx0xxxx1 xxxxxxxxxx") {
            // scalar copy (DUP element)
            if bits(x, 14, 11) != 0 || bits(x, 19, 16) == 0 || u {
                return Insn::Undefined;
            }
            return Insn::SimdScalarCopy { imm5: bits(x, 20, 16), rd: bits(x, 4, 0), rn: bits(x, 9, 5) };
        }
        if is!(x, b"01x1 xxx 0x x0xx xxx1xxxx1 xxxxxxxxxx") {
            return decode_simd_same2(x, true);
        }
        if is!(x, b"01x1 xxx 0x x100 00xxxxx10 xxxxxxxxxx") {
            return decode_simd_misc(x, true);
        }
        if is!(x, b"01x1 xxx 0x x110 00xxxxx10 xxxxxxxxxx") {
            return decode_simd_pair(x);
        }
        if is!(x, b"01x1 xxx 0x x1xx xxxxxxx00 xxxxxxxxxx") {
            return decode_simd_diff(x, true);
        }
        if is!(x, b"01x1 xxx 0x x1xx xxxxxxxx1 xxxxxxxxxx") {
            return decode_simd_same(x, true);
        }
        if is!(x, b"01x1 xxx 10 xxxx xxxxxxxx1 xxxxxxxxxx") {
            return decode_simd_shift(x, true);
        }
        if is!(x, b"01x1 xxx 1x xxxx xxxxxxxx0 xxxxxxxxxx") {
            return decode_simd_elem(x, true);
        }
        return Insn::Undefined;
    }
    // ---- Advanced SIMD vector: op0 = 0xx0 ----
    if is!(x, b"0x00 xxx 0x x0xx xxx0xxx00 xxxxxxxxxx") {
        // table lookup
        if bits(x, 23, 22) != 0 {
            return Insn::Undefined; // LUTI2/LUTI4 (FEAT_LUT)
        }
        return Insn::SimdTbl {
            q,
            len: bits(x, 14, 13) as u8,
            tbx: bit(x, 12),
            rd: bits(x, 4, 0),
            rn: bits(x, 9, 5),
            rm: bits(x, 20, 16),
        };
    }
    if is!(x, b"0x00 xxx 0x x0xx xxx0xxx10 xxxxxxxxxx") {
        // permute
        let size = bits(x, 23, 22) as u8;
        let opcode = bits(x, 14, 12) as u8;
        if opcode & 3 == 0 || (size == 3 && !q) {
            return Insn::Undefined;
        }
        return Insn::SimdPermute { q, size, opcode, rd: bits(x, 4, 0), rn: bits(x, 9, 5), rm: bits(x, 20, 16) };
    }
    if is!(x, b"0x10 xxx 0x x0xx xxx0xxxx0 xxxxxxxxxx") {
        // extract
        let imm4 = bits(x, 14, 11);
        if bits(x, 23, 22) != 0 || (!q && imm4 & 8 != 0) {
            return Insn::Undefined;
        }
        return Insn::SimdExt { q, imm4, rd: bits(x, 4, 0), rn: bits(x, 9, 5), rm: bits(x, 20, 16) };
    }
    if is!(x, b"0xx0 xxx 00 00xx xxx0xxxx1 xxxxxxxxxx") {
        return decode_simd_copy(x, q, u);
    }
    if is!(x, b"0xx0 xxx 0x x0xx xxx1xxxx1 xxxxxxxxxx") {
        return decode_simd_same2(x, false);
    }
    if is!(x, b"0xx0 xxx 0x x100 00xxxxx10 xxxxxxxxxx") {
        return decode_simd_misc(x, false);
    }
    if is!(x, b"0xx0 xxx 0x x110 00xxxxx10 xxxxxxxxxx") {
        return decode_simd_across(x);
    }
    if is!(x, b"0xx0 xxx 0x x1xx xxxxxxx00 xxxxxxxxxx") {
        return decode_simd_diff(x, false);
    }
    if is!(x, b"0xx0 xxx 0x x1xx xxxxxxxx1 xxxxxxxxxx") {
        return decode_simd_same(x, false);
    }
    if is!(x, b"0xx0 xxx 10 0000 xxxxxxxx1 xxxxxxxxxx") {
        return decode_simd_mod_imm(x, q, u);
    }
    if is!(x, b"0xx0 xxx 10 xxxx xxxxxxxx1 xxxxxxxxxx") {
        return decode_simd_shift(x, false);
    }
    if is!(x, b"0xx0 xxx 1x xxxx xxxxxxxx0 xxxxxxxxxx") {
        return decode_simd_elem(x, false);
    }
    Insn::Undefined
}

// ------------------------- Scalar floating point -------------------------

fn decode_fp(x: u32) -> Insn {
    let ftype = bits(x, 23, 22) as u8;
    let rd = bits(x, 4, 0);
    let rn = bits(x, 9, 5);
    let rm = bits(x, 20, 16);
    if bit(x, 29) {
        return Insn::Undefined; // S == 1
    }
    if bit(x, 24) {
        // FP data-processing (3 source)
        if bit(x, 31) || ftype > 1 {
            return Insn::Undefined;
        }
        return Insn::Fp3 { ftype, neg: bit(x, 21), sub: bit(x, 15), rd, rn, rm, ra: bits(x, 14, 10) };
    }
    if !bit(x, 21) {
        return decode_fp_fixed(x);
    }
    if bits(x, 15, 10) == 0 {
        return decode_fp_int(x);
    }
    // The remaining classes all have M (bit 31) == 0.
    if bit(x, 31) || ftype > 1 {
        if !bit(x, 31) && bits(x, 14, 10) == 0b10000 && ftype == 3 {
            // FCVT from half precision is part of base FP.
            return decode_fp_1src(x);
        }
        return Insn::Undefined;
    }
    if bits(x, 15, 10) == 0b100000 {
        return Insn::Undefined;
    }
    if bits(x, 14, 10) == 0b10000 {
        return decode_fp_1src(x);
    }
    if bits(x, 13, 10) == 0b1000 {
        // FP compare: op (15:14) == 00, opcode2<2:0> == 000
        if bits(x, 15, 14) != 0 || bits(x, 2, 0) != 0 {
            return Insn::Undefined;
        }
        return Insn::FpCmp { ftype, rn, rm, zero: bit(x, 3), signal: bit(x, 4) };
    }
    if bits(x, 12, 10) == 0b100 {
        // FP immediate: imm5 == 00000
        if bits(x, 9, 5) != 0 {
            return Insn::Undefined;
        }
        return Insn::FpImm { ftype, rd, imm8: bits(x, 20, 13) as u8 };
    }
    match bits(x, 11, 10) {
        0b01 => Insn::FpCCmp { ftype, rn, rm, nzcv: bits(x, 3, 0), cond: bits(x, 15, 12), signal: bit(x, 4) },
        0b10 => {
            let op = match bits(x, 15, 12) {
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
        0b11 => Insn::FpCSel { ftype, rd, rn, rm, cond: bits(x, 15, 12) },
        _ => Insn::Undefined,
    }
}

fn decode_fp_1src(x: u32) -> Insn {
    let ftype = bits(x, 23, 22) as u8;
    let opcode = bits(x, 20, 15);
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    if opcode & 0b111100 == 0b000100 {
        // FCVT: opc = opcode<1:0> is the destination type.
        let opc = (opcode & 3) as u8;
        if opc == ftype || opc == 2 || ftype == 2 {
            return Insn::Undefined;
        }
        let to = match opc {
            0 => 0u8, // S
            1 => 1,   // D
            _ => 2,   // H
        };
        return Insn::Fp1 { ftype, op: Fp1Op::Cvt, to, rd, rn };
    }
    if ftype > 1 {
        return Insn::Undefined; // half precision arithmetic needs FEAT_FP16
    }
    let op = match opcode {
        0b000000 => Fp1Op::Mov,
        0b000001 => Fp1Op::Abs,
        0b000010 => Fp1Op::Neg,
        0b000011 => Fp1Op::Sqrt,
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
        _ => return Insn::Undefined,
    };
    Insn::Fp1 { ftype, op, to: ftype, rd, rn }
}

/// Conversion between floating-point and fixed-point (bit 21 == 0).
fn decode_fp_fixed(x: u32) -> Insn {
    let sf = bit(x, 31);
    let ftype = bits(x, 23, 22) as u8;
    let scale = bits(x, 15, 10);
    if ftype > 1 || (!sf && scale & 0b100000 == 0) {
        return Insn::Undefined;
    }
    let fbits = 64 - scale;
    let op = match bits(x, 20, 16) {
        0b00010 => FcvtOp::FixedToF { unsigned: false, fbits },
        0b00011 => FcvtOp::FixedToF { unsigned: true, fbits },
        0b11000 => FcvtOp::FtoFixed { unsigned: false, fbits },
        0b11001 => FcvtOp::FtoFixed { unsigned: true, fbits },
        _ => return Insn::Undefined,
    };
    Insn::FpCvt { ftype, sf, op, rd: bits(x, 4, 0), rn: bits(x, 9, 5) }
}

/// Conversion between floating-point and integer (bit 21 == 1, 15:10 == 0).
fn decode_fp_int(x: u32) -> Insn {
    let sf = bit(x, 31);
    let ftype = bits(x, 23, 22) as u8;
    let rmode = bits(x, 20, 19);
    let opcode = bits(x, 18, 16);
    let rd = bits(x, 4, 0);
    let rn = bits(x, 9, 5);
    if opcode & 0b110 == 0b110 {
        // FMOV (general) and FJCVTZS
        let to_fp = opcode & 1 != 0;
        return match (rmode, sf, ftype) {
            (0b00, false, 0b00) | (0b00, true, 0b01) => {
                Insn::FpCvt { ftype, sf, op: FcvtOp::Fmov { to_fp, top: false }, rd, rn }
            }
            (0b01, true, 0b10) => Insn::FpCvt { ftype, sf, op: FcvtOp::Fmov { to_fp, top: true }, rd, rn },
            (0b11, false, 0b01) if !to_fp => Insn::FpCvt { ftype, sf, op: FcvtOp::Fjcvt, rd, rn },
            _ => Insn::Undefined,
        };
    }
    if ftype > 1 {
        return Insn::Undefined;
    }
    let unsigned = opcode & 1 != 0;
    let op = match (rmode, opcode) {
        (0b00, 0b000) | (0b00, 0b001) => FcvtOp::FtoI { round: 0, unsigned },
        (0b00, 0b010) | (0b00, 0b011) => FcvtOp::ItoF { unsigned },
        (0b00, 0b100) | (0b00, 0b101) => FcvtOp::FtoI { round: 4, unsigned },
        (0b01, 0b000) | (0b01, 0b001) => FcvtOp::FtoI { round: 1, unsigned },
        (0b10, 0b000) | (0b10, 0b001) => FcvtOp::FtoI { round: 2, unsigned },
        (0b11, 0b000) | (0b11, 0b001) => FcvtOp::FtoI { round: 3, unsigned },
        _ => return Insn::Undefined,
    };
    Insn::FpCvt { ftype, sf, op, rd, rn }
}

// ------------------------- Cryptographic -------------------------

fn decode_crypto_aes(x: u32) -> Insn {
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    if bits(x, 23, 22) != 0 {
        return Insn::Undefined;
    }
    match bits(x, 16, 12) {
        0b00100 => Insn::Aese { rd, rn },
        0b00101 => Insn::Aesd { rd, rn },
        0b00110 => Insn::Aesmc { rd, rn },
        0b00111 => Insn::Aesimc { rd, rn },
        _ => Insn::Undefined,
    }
}

fn decode_crypto_sha3(x: u32) -> Insn {
    let rm = bits(x, 20, 16);
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    if bits(x, 23, 22) != 0 {
        return Insn::Undefined;
    }
    let opcode = bits(x, 14, 12) as u8;
    match opcode {
        0..=3 => Insn::Sha1 { op: opcode, rd, rn, rm },
        4..=6 => Insn::Sha256 { op: opcode, rd, rn, rm },
        _ => Insn::Undefined,
    }
}

fn decode_crypto_sha2(x: u32) -> Insn {
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    if bits(x, 23, 22) != 0 {
        return Insn::Undefined;
    }
    match bits(x, 16, 12) {
        0b00000 => Insn::Sha1 { op: 0b100, rd, rn, rm: 0 },  // SHA1H
        0b00001 => Insn::Sha1 { op: 0b101, rd, rn, rm: 0 },  // SHA1SU1
        0b00010 => Insn::Sha256 { op: 0x10, rd, rn, rm: 0 }, // SHA256SU0
        _ => Insn::Undefined,
    }
}

include!("decode_simd2.rs");
include!("decode_simd_ldst.rs");
