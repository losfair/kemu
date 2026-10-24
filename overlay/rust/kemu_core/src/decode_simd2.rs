// SPDX-License-Identifier: GPL-2.0
// Advanced SIMD class decoders. Included by decode_simd.rs.
//
// Conventions for the decoded forms:
//  * Scalar forms set `scalar: true` and `q: true`.
//  * Integer ops carry the raw `size` field (element size, log2 bytes).
//  * FP ops carry `size` = 2 + sz (2 = single, 3 = double).

/// Advanced SIMD (scalar) three same.
fn decode_simd_same(x: u32, scalar: bool) -> Insn {
    let q = scalar || bit(x, 30);
    let u = bit(x, 29);
    let size = bits(x, 23, 22) as u8;
    let opcode = bits(x, 15, 11);
    let rm = bits(x, 20, 16);
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    if opcode >= 0b11000 {
        let a = size >> 1 != 0;
        let sz = size & 1;
        if !scalar && sz == 1 && !q {
            return Insn::Undefined;
        }
        use SimdOp::*;
        let op = match (u, a, opcode) {
            (false, false, 0b11000) if !scalar => FMaxNm,
            (false, false, 0b11001) if !scalar => FMla,
            (false, false, 0b11010) if !scalar => FAdd,
            (false, false, 0b11011) => FMulx,
            (false, false, 0b11100) => FCmEq,
            (false, false, 0b11110) if !scalar => FMax,
            (false, false, 0b11111) => FRecps,
            (false, true, 0b11000) if !scalar => FMinNm,
            (false, true, 0b11001) if !scalar => FMls,
            (false, true, 0b11010) if !scalar => FSub,
            (false, true, 0b11110) if !scalar => FMin,
            (false, true, 0b11111) => FRsqrts,
            (true, false, 0b11000) if !scalar => FMaxNmP,
            (true, false, 0b11010) if !scalar => FAddP,
            (true, false, 0b11011) if !scalar => FMul,
            (true, false, 0b11100) => FCmGe,
            (true, false, 0b11101) => FAcGe,
            (true, false, 0b11110) if !scalar => FMaxP,
            (true, false, 0b11111) if !scalar => FDiv,
            (true, true, 0b11000) if !scalar => FMinNmP,
            (true, true, 0b11010) => FAbd,
            (true, true, 0b11100) => FCmGt,
            (true, true, 0b11101) => FAcGt,
            (true, true, 0b11110) if !scalar => FMinP,
            _ => return Insn::Undefined,
        };
        return Insn::SimdThree { q, u, size: 2 + sz, op, rd, rn, rm, scalar };
    }
    use SimdOp::*;
    // Size restrictions: 0 = any (but .1D vector forms reserved),
    // 1 = size != 11, 2 = size in {01, 10}, 3 = scalar needs size == 11.
    let (op, restr) = match (u, opcode) {
        (false, 0b00000) => (SHAdd, 1),
        (true, 0b00000) => (UHAdd, 1),
        (false, 0b00001) => (SQAdd, 0),
        (true, 0b00001) => (UQAdd, 0),
        (false, 0b00010) => (SRHAdd, 1),
        (true, 0b00010) => (URHAdd, 1),
        (false, 0b00011) => (
            match size {
                0b00 => And,
                0b01 => Bic,
                0b10 => Orr,
                _ => Orn,
            },
            4,
        ),
        (true, 0b00011) => (
            match size {
                0b00 => Eor,
                0b01 => Bsl,
                0b10 => Bit,
                _ => Bif,
            },
            4,
        ),
        (false, 0b00100) => (SHSub, 1),
        (true, 0b00100) => (UHSub, 1),
        (false, 0b00101) => (SQSub, 0),
        (true, 0b00101) => (UQSub, 0),
        (false, 0b00110) => (CmGt, 3),
        (true, 0b00110) => (CmHi, 3),
        (false, 0b00111) => (CmGe, 3),
        (true, 0b00111) => (CmHs, 3),
        (false, 0b01000) => (SShl, 3),
        (true, 0b01000) => (UShl, 3),
        (false, 0b01001) => (SQShl, 0),
        (true, 0b01001) => (UQShl, 0),
        (false, 0b01010) => (SRShl, 3),
        (true, 0b01010) => (URShl, 3),
        (false, 0b01011) => (SQRShl, 0),
        (true, 0b01011) => (UQRShl, 0),
        (false, 0b01100) => (SMax, 1),
        (true, 0b01100) => (UMax, 1),
        (false, 0b01101) => (SMin, 1),
        (true, 0b01101) => (UMin, 1),
        (false, 0b01110) => (SAbd, 1),
        (true, 0b01110) => (UAbd, 1),
        (false, 0b01111) => (SAba, 1),
        (true, 0b01111) => (UAba, 1),
        (false, 0b10000) => (Add, 3),
        (true, 0b10000) => (Sub, 3),
        (false, 0b10001) => (CmTst, 3),
        (true, 0b10001) => (CmEq, 3),
        (false, 0b10010) => (Mla, 1),
        (true, 0b10010) => (Mls, 1),
        (false, 0b10011) => (Mul, 1),
        (true, 0b10011) => (PMul, 5),
        (false, 0b10100) => (SMaxP, 1),
        (true, 0b10100) => (UMaxP, 1),
        (false, 0b10101) => (SMinP, 1),
        (true, 0b10101) => (UMinP, 1),
        (false, 0b10110) => (SQDMulh, 2),
        (true, 0b10110) => (SQRDMulh, 2),
        (false, 0b10111) => (AddP, 0),
        _ => return Insn::Undefined,
    };
    let ok = if scalar {
        match restr {
            0 => !matches!(op, AddP),
            2 => size == 1 || size == 2,
            3 => size == 3,
            _ => false,
        }
    } else {
        match restr {
            0 | 3 => !(size == 3 && !q),
            1 => size != 3,
            2 => size == 1 || size == 2,
            4 => true,
            _ => size == 0, // PMUL
        }
    };
    if !ok {
        return Insn::Undefined;
    }
    Insn::SimdThree { q, u, size, op, rd, rn, rm, scalar }
}

/// Advanced SIMD (scalar) three same extra / three-register extension.
fn decode_simd_same2(x: u32, scalar: bool) -> Insn {
    let q = scalar || bit(x, 30);
    let u = bit(x, 29);
    let size = bits(x, 23, 22) as u8;
    let rm = bits(x, 20, 16);
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    let op = match (u, bits(x, 14, 11)) {
        (true, 0b0000) if size == 1 || size == 2 => SimdOp::SQRDMlah,
        (true, 0b0001) if size == 1 || size == 2 => SimdOp::SQRDMlsh,
        (false, 0b0010) if !scalar && size == 2 => SimdOp::SDot,
        (true, 0b0010) if !scalar && size == 2 => SimdOp::UDot,
        _ => return Insn::Undefined,
    };
    Insn::SimdThree { q, u, size, op, rd, rn, rm, scalar }
}

/// Advanced SIMD (scalar) three different.
fn decode_simd_diff(x: u32, scalar: bool) -> Insn {
    let q = scalar || bit(x, 30);
    let u = bit(x, 29);
    let size = bits(x, 23, 22) as u8;
    let rm = bits(x, 20, 16);
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    use SimdOp::*;
    let s2 = |a: SimdOp, b: SimdOp| if q && !scalar { b } else { a };
    let opcode = bits(x, 15, 12);
    if scalar {
        let op = match (u, opcode) {
            (false, 0b1001) => SQDMlaL,
            (false, 0b1011) => SQDMlsL,
            (false, 0b1101) => SQDMull,
            _ => return Insn::Undefined,
        };
        if size != 1 && size != 2 {
            return Insn::Undefined;
        }
        return Insn::SimdThree { q, u, size, op, rd, rn, rm, scalar };
    }
    let op = match (u, opcode) {
        (false, 0b0000) => s2(SAddL, SAddL2),
        (true, 0b0000) => s2(UAddL, UAddL2),
        (false, 0b0001) => s2(SAddW, SAddW2),
        (true, 0b0001) => s2(UAddW, UAddW2),
        (false, 0b0010) => s2(SSubL, SSubL2),
        (true, 0b0010) => s2(USubL, USubL2),
        (false, 0b0011) => s2(SSubW, SSubW2),
        (true, 0b0011) => s2(USubW, USubW2),
        (false, 0b0100) => s2(AddHn, AddHn2),
        (true, 0b0100) => s2(RAddHn, RAddHn2),
        (false, 0b0101) => s2(SAbaL, SAbaL2),
        (true, 0b0101) => s2(UAbaL, UAbaL2),
        (false, 0b0110) => s2(SubHn, SubHn2),
        (true, 0b0110) => s2(RSubHn, RSubHn2),
        (false, 0b0111) => s2(SAbdL, SAbdL2),
        (true, 0b0111) => s2(UAbdL, UAbdL2),
        (false, 0b1000) => s2(SMlaL, SMlaL2),
        (true, 0b1000) => s2(UMlaL, UMlaL2),
        (false, 0b1001) => s2(SQDMlaL, SQDMlaL2),
        (false, 0b1010) => s2(SMlsL, SMlsL2),
        (true, 0b1010) => s2(UMlsL, UMlsL2),
        (false, 0b1011) => s2(SQDMlsL, SQDMlsL2),
        (false, 0b1100) => s2(SMullL, SMullL2),
        (true, 0b1100) => s2(UMullL, UMullL2),
        (false, 0b1101) => s2(SQDMull, SQDMull2),
        (false, 0b1110) => s2(PMull, PMull2),
        _ => return Insn::Undefined,
    };
    let ok = match op {
        SQDMlaL | SQDMlaL2 | SQDMlsL | SQDMlsL2 | SQDMull | SQDMull2 => size == 1 || size == 2,
        PMull | PMull2 => size == 0 || size == 3,
        _ => size != 3,
    };
    if !ok {
        return Insn::Undefined;
    }
    Insn::SimdThree { q, u, size, op, rd, rn, rm, scalar }
}

/// Advanced SIMD (scalar) two-register miscellaneous.
fn decode_simd_misc(x: u32, scalar: bool) -> Insn {
    let q = scalar || bit(x, 30);
    let u = bit(x, 29);
    let size = bits(x, 23, 22) as u8;
    let a = size >> 1 != 0;
    let sz = size & 1;
    let opcode = bits(x, 16, 12);
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    use Simd2Op::*;
    // FP ops (opcode 01100..01111 with a=1, and 11000..11111) use sz.
    let fp = |op: Simd2Op| -> Insn {
        if !scalar && sz == 1 && !q {
            return Insn::Undefined;
        }
        Insn::SimdMisc { q, u, size: 2 + sz, op, rd, rn, scalar }
    };
    let int = |op: Simd2Op, ok: bool| -> Insn {
        if !ok {
            return Insn::Undefined;
        }
        Insn::SimdMisc { q, u, size, op, rd, rn, scalar }
    };
    // Vector-only reserved-arrangement check (size:Q == 110).
    let not_1d = size != 3 || q;
    if scalar {
        return match (u, opcode) {
            (false, 0b00011) => int(SuqAdd, true),
            (true, 0b00011) => int(UsqAdd, true),
            (false, 0b00111) => int(SqAbs, true),
            (true, 0b00111) => int(SqNeg, true),
            (false, 0b01000) => int(CmGt0, size == 3),
            (true, 0b01000) => int(CmGe0, size == 3),
            (false, 0b01001) => int(CmEq0, size == 3),
            (true, 0b01001) => int(CmLe0, size == 3),
            (false, 0b01010) => int(CmLt0, size == 3),
            (false, 0b01011) => int(Abs, size == 3),
            (true, 0b01011) => int(Neg, size == 3),
            (false, 0b01100) if a => fp(FCmGt0),
            (true, 0b01100) if a => fp(FCmGe0),
            (false, 0b01101) if a => fp(FCmEq0),
            (true, 0b01101) if a => fp(FCmLe0),
            (false, 0b01110) if a => fp(FCmLt0),
            (false, 0b10100) => int(SqXtn, size != 3),
            (true, 0b10010) => int(SqXtun, size != 3),
            (true, 0b10100) => int(UqXtn, size != 3),
            (true, 0b10110) if size == 1 => Insn::SimdMisc { q, u, size: 2, op: FcvtXn, rd, rn, scalar },
            (false, 0b11010) => fp(if a { Fcvtps } else { Fcvtns }),
            (true, 0b11010) => fp(if a { Fcvtpu } else { Fcvtnu }),
            (false, 0b11011) => fp(if a { Fcvtzs } else { Fcvtms }),
            (true, 0b11011) => fp(if a { Fcvtzu } else { Fcvtmu }),
            (false, 0b11100) if !a => fp(Fcvtas),
            (true, 0b11100) if !a => fp(Fcvtau),
            (false, 0b11101) => fp(if a { Frecpe } else { Scvtf }),
            (true, 0b11101) => fp(if a { Frsqrte } else { Ucvtf }),
            (false, 0b11111) if a => fp(Frecpx),
            _ => Insn::Undefined,
        };
    }
    match (u, opcode) {
        (false, 0b00000) => int(Rev64, size != 3),
        (false, 0b00001) => int(Rev16, size == 0),
        (true, 0b00000) => int(Rev32, size < 2),
        (false, 0b00010) => int(SaddLp, size != 3),
        (true, 0b00010) => int(UaddLp, size != 3),
        (false, 0b00011) => int(SuqAdd, not_1d),
        (true, 0b00011) => int(UsqAdd, not_1d),
        (false, 0b00100) => int(Cls, size != 3),
        (true, 0b00100) => int(Clz, size != 3),
        (false, 0b00101) => int(Cnt, size == 0),
        // NOT/RBIT: size selects the op; elements are always bytes.
        (true, 0b00101) => match size {
            0 => Insn::SimdMisc { q, u, size: 0, op: Not, rd, rn, scalar },
            1 => Insn::SimdMisc { q, u, size: 0, op: Rbit, rd, rn, scalar },
            _ => Insn::Undefined,
        },
        (false, 0b00110) => int(SadaLp, size != 3),
        (true, 0b00110) => int(UadaLp, size != 3),
        (false, 0b00111) => int(SqAbs, not_1d),
        (true, 0b00111) => int(SqNeg, not_1d),
        (false, 0b01000) => int(CmGt0, not_1d),
        (true, 0b01000) => int(CmGe0, not_1d),
        (false, 0b01001) => int(CmEq0, not_1d),
        (true, 0b01001) => int(CmLe0, not_1d),
        (false, 0b01010) => int(CmLt0, not_1d),
        (false, 0b01011) => int(Abs, not_1d),
        (true, 0b01011) => int(Neg, not_1d),
        (false, 0b01100) if a => fp(FCmGt0),
        (true, 0b01100) if a => fp(FCmGe0),
        (false, 0b01101) if a => fp(FCmEq0),
        (true, 0b01101) if a => fp(FCmLe0),
        (false, 0b01110) if a => fp(FCmLt0),
        (false, 0b01111) if a => fp(Fabs),
        (true, 0b01111) if a => fp(Fneg),
        (false, 0b10010) => int(if q { Xtn2 } else { Xtn }, size != 3),
        (true, 0b10010) => int(if q { SqXtun2 } else { SqXtun }, size != 3),
        (true, 0b10011) => int(if q { Shll2 } else { Shll }, size != 3),
        (false, 0b10100) => int(if q { SqXtn2 } else { SqXtn }, size != 3),
        (true, 0b10100) => int(if q { UqXtn2 } else { UqXtn }, size != 3),
        // FCVTN/FCVTL: size = narrow element size (1 = H, 2 = S).
        (false, 0b10110) if !a => Insn::SimdMisc { q, u, size: 1 + sz, op: if q { FcvtN2 } else { FcvtN }, rd, rn, scalar },
        (false, 0b10111) if !a => Insn::SimdMisc { q, u, size: 1 + sz, op: if q { FcvtL2 } else { FcvtL }, rd, rn, scalar },
        (true, 0b10110) if size == 1 => Insn::SimdMisc { q, u, size: 2, op: if q { FcvtXn2 } else { FcvtXn }, rd, rn, scalar },
        (false, 0b11000) => fp(if a { FrintP } else { FrintN }),
        (false, 0b11001) => fp(if a { FrintZ } else { FrintM }),
        (false, 0b11010) => fp(if a { Fcvtps } else { Fcvtns }),
        (false, 0b11011) => fp(if a { Fcvtzs } else { Fcvtms }),
        (false, 0b11100) => {
            if a {
                if sz != 0 {
                    return Insn::Undefined;
                }
                Insn::SimdMisc { q, u, size: 2, op: Urecpe, rd, rn, scalar }
            } else {
                fp(Fcvtas)
            }
        }
        (false, 0b11101) => fp(if a { Frecpe } else { Scvtf }),
        (false, 0b11110) if !a => fp(Frint32Z),
        (false, 0b11111) if !a => fp(Frint64Z),
        (true, 0b11000) if !a => fp(FrintA),
        (true, 0b11001) => fp(if a { FrintI } else { FrintX }),
        (true, 0b11010) => fp(if a { Fcvtpu } else { Fcvtnu }),
        (true, 0b11011) => fp(if a { Fcvtzu } else { Fcvtmu }),
        (true, 0b11100) => {
            if a {
                if sz != 0 {
                    return Insn::Undefined;
                }
                Insn::SimdMisc { q, u, size: 2, op: Ursqrte, rd, rn, scalar }
            } else {
                fp(Fcvtau)
            }
        }
        (true, 0b11101) => fp(if a { Frsqrte } else { Ucvtf }),
        (true, 0b11110) if !a => fp(Frint32X),
        (true, 0b11111) => fp(if a { Fsqrt } else { Frint64X }),
        _ => Insn::Undefined,
    }
}

/// Advanced SIMD scalar pairwise.
fn decode_simd_pair(x: u32) -> Insn {
    let u = bit(x, 29);
    let size = bits(x, 23, 22) as u8;
    let a = size >> 1 != 0;
    let sz = size & 1;
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    let opcode = bits(x, 16, 12);
    if !u {
        if opcode == 0b11011 && size == 3 {
            return Insn::SimdAcross { q: true, size: 3, op: AcrossOp::AddP, rd, rn };
        }
        return Insn::Undefined; // FP16 pairwise forms
    }
    let op = match (opcode, a) {
        (0b01100, false) => AcrossOp::FMaxNmP,
        (0b01100, true) => AcrossOp::FMinNmP,
        (0b01101, false) => AcrossOp::FAddP,
        (0b01111, false) => AcrossOp::FMaxP,
        (0b01111, true) => AcrossOp::FMinP,
        _ => return Insn::Undefined,
    };
    // Two elements of 32 or 64 bits.
    Insn::SimdAcross { q: sz == 1, size: 2 + sz, op, rd, rn }
}

/// Advanced SIMD across lanes.
fn decode_simd_across(x: u32) -> Insn {
    let q = bit(x, 30);
    let u = bit(x, 29);
    let size = bits(x, 23, 22) as u8;
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    let opcode = bits(x, 16, 12);
    use AcrossOp::*;
    let int = |op: AcrossOp| -> Insn {
        if size == 3 || (size == 2 && !q) {
            return Insn::Undefined;
        }
        Insn::SimdAcross { q, size, op, rd, rn }
    };
    match (u, opcode) {
        (false, 0b00011) => int(SAddLV),
        (true, 0b00011) => int(UAddLV),
        (false, 0b01010) => int(SMaxV),
        (true, 0b01010) => int(UMaxV),
        (false, 0b11010) => int(SMinV),
        (true, 0b11010) => int(UMinV),
        (false, 0b11011) => int(AddV),
        (true, 0b01100) | (true, 0b01111) => {
            // FP: .4S only (sz:Q == 01).
            if size & 1 != 0 || !q {
                return Insn::Undefined;
            }
            let op = match (opcode, size >> 1) {
                (0b01100, 0) => FMaxNmV,
                (0b01100, _) => FMinNmV,
                (_, 0) => FMaxV,
                _ => FMinV,
            };
            Insn::SimdAcross { q, size: 2, op, rd, rn }
        }
        _ => Insn::Undefined,
    }
}

/// Advanced SIMD copy.
fn decode_simd_copy(x: u32, q: bool, op: bool) -> Insn {
    let imm5 = bits(x, 20, 16);
    let imm4 = bits(x, 14, 11);
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    if imm5 & 0xf == 0 {
        return Insn::Undefined;
    }
    if op {
        if !q {
            return Insn::Undefined;
        }
        return Insn::SimdInsElt { imm5, imm4, rd, rn };
    }
    let esize = imm5.trailing_zeros(); // 0..3
    match imm4 {
        0b0000 | 0b0001 => {
            if esize == 3 && !q {
                return Insn::Undefined;
            }
            Insn::SimdDup { q, imm5, rd, rn, from_gpr: imm4 == 1 }
        }
        0b0011 if q => Insn::SimdInsGpr { imm5, rd, rn },
        0b0101 => {
            // SMOV: W form B/H, X form B/H/S.
            let ok = if q { esize < 3 } else { esize < 2 };
            if !ok {
                return Insn::Undefined;
            }
            Insn::SimdSmov { q, imm5, rd, rn }
        }
        0b0111 => {
            // UMOV: W form B/H/S, X form D only.
            let ok = if q { esize == 3 } else { esize < 3 };
            if !ok {
                return Insn::Undefined;
            }
            Insn::SimdUmov { q, imm5, rd, rn }
        }
        _ => Insn::Undefined,
    }
}

/// Advanced SIMD modified immediate.
fn decode_simd_mod_imm(x: u32, q: bool, u: bool) -> Insn {
    let cmode = bits(x, 15, 12) as u8;
    let o2 = bit(x, 11);
    let rd = bits(x, 4, 0);
    if o2 {
        return Insn::Undefined; // FMOV (vector, immediate) half-precision
    }
    if u && cmode == 0b1111 && !q {
        return Insn::Undefined;
    }
    let imm8 = (bits(x, 18, 16) << 5) | bits(x, 9, 5);
    let op = u as u8;
    let (imm, fp) = adv_simd_expand_imm(op, cmode, imm8 as u64);
    Insn::SimdModImm { q, op, cmode, rd, imm, fp }
}

/// Advanced SIMD (scalar) shift by immediate. The raw fields are kept; this
/// only validates the encoding.
fn decode_simd_shift(x: u32, scalar: bool) -> Insn {
    let q = scalar || bit(x, 30);
    let u = bit(x, 29);
    let immh = bits(x, 22, 19);
    let immb = bits(x, 18, 16);
    let opcode = bits(x, 15, 11) as u8;
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    if immh == 0 {
        return Insn::Undefined;
    }
    let h3 = immh & 8 != 0;
    // kind: 0 = same-size, 1 = narrowing, 2 = long, 3 = fixed-point convert
    let kind = match (u, opcode) {
        (_, 0b00000) | (_, 0b00010) | (_, 0b00100) | (_, 0b00110) => 0,
        (true, 0b01000) => 0,  // SRI
        (_, 0b01010) => 0,     // SHL / SLI
        (true, 0b01100) => 4,  // SQSHLU
        (_, 0b01110) => 4,     // SQSHL / UQSHL
        (false, 0b10000) | (false, 0b10001) => 5, // SHRN / RSHRN (vector only)
        (true, 0b10000) | (true, 0b10001) => 1,   // SQSHRUN / SQRSHRUN
        (_, 0b10010) | (_, 0b10011) => 1,         // SQSHRN / UQSHRN / ..R..
        (_, 0b10100) => 2,     // SSHLL / USHLL (vector only)
        (_, 0b11100) | (_, 0b11111) => 3,
        _ => return Insn::Undefined,
    };
    let ok = if scalar {
        match kind {
            0 => h3,          // D only
            4 => true,
            1 => !h3,
            3 => immh & 0b1100 != 0,
            _ => false,
        }
    } else {
        match kind {
            0 | 4 => !(h3 && !q),
            1 | 2 | 5 => !h3,
            _ => immh & 0b1100 != 0 && !(h3 && !q),
        }
    };
    if !ok {
        return Insn::Undefined;
    }
    Insn::SimdShift { q, u, immh, immb, opcode, rd, rn, scalar }
}

/// Advanced SIMD (scalar) x indexed element. `opcode` is bits 15:12; for FP
/// ops `size` is 2 + sz. `index`/`rm` are fully decoded.
fn decode_simd_elem(x: u32, scalar: bool) -> Insn {
    let q = scalar || bit(x, 30);
    let u = bit(x, 29);
    let size = bits(x, 23, 22) as u8;
    let l = bit(x, 21) as u32;
    let m = bit(x, 20) as u32;
    let h = bit(x, 11) as u32;
    let rmlo = bits(x, 19, 16);
    let opcode = bits(x, 15, 12) as u8;
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    // class: 0 = integer H/S, 1 = FP S/D, 2 = dot product (S only)
    let class = match (u, opcode) {
        (false, 0b0001) | (false, 0b0101) | (false, 0b1001) | (true, 0b1001) => 1,
        (false, 0b1110) | (true, 0b1110) => {
            if scalar {
                return Insn::Undefined;
            }
            2
        }
        (false, 0b0011) | (false, 0b0111) | (false, 0b1011) | (false, 0b1100) | (false, 0b1101) => 0,
        (true, 0b1101) | (true, 0b1111) => 0, // SQRDMLAH / SQRDMLSH
        (false, 0b0010) | (false, 0b0110) | (false, 0b1000) | (false, 0b1010) | (true, 0b0000) | (true, 0b0010)
        | (true, 0b0100) | (true, 0b0110) | (true, 0b1010) => {
            if scalar {
                return Insn::Undefined;
            }
            0
        }
        _ => return Insn::Undefined,
    };
    match class {
        1 => {
            if size < 2 {
                return Insn::Undefined; // FP16 (size 00) / reserved (01)
            }
            let sz = size & 1;
            if sz == 1 && l == 1 {
                return Insn::Undefined;
            }
            if !scalar && sz == 1 && !q {
                return Insn::Undefined;
            }
            let index = if sz == 0 { (h << 1) | l } else { h };
            Insn::SimdIndexed { q, u, size: 2 + sz, opcode, rd, rn, rm: (m << 4) | rmlo, index, scalar }
        }
        2 => {
            if size != 2 {
                return Insn::Undefined;
            }
            Insn::SimdIndexed { q, u, size, opcode, rd, rn, rm: (m << 4) | rmlo, index: (h << 1) | l, scalar }
        }
        _ => {
            let (index, rm) = match size {
                1 => ((h << 2) | (l << 1) | m, rmlo),
                2 => ((h << 1) | l, (m << 4) | rmlo),
                _ => return Insn::Undefined,
            };
            Insn::SimdIndexed { q, u, size, opcode, rd, rn, rm, index, scalar }
        }
    }
}
