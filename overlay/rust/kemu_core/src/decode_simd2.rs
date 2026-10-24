// SPDX-License-Identifier: GPL-2.0
// Advanced SIMD sub-decoders. Included by decode_simd.rs.

fn decode_simd_three_same(x: u32, q: bool, u: bool) -> Insn {
    let size = bits(x, 23, 22) as u8;
    let opcode = bits(x, 15, 11);
    let rm = bits(x, 20, 16);
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    if opcode >= 0b11000 {
        let a = bit(x, 23);
        let esize = if bit(x, 22) { 3u8 } else { 2u8 };
        let op = match (u, a, opcode) {
            (false, false, 0b11000) => SimdOp::FMaxNm,
            (false, true, 0b11000) => SimdOp::FMinNm,
            (true, false, 0b11000) => SimdOp::FMaxNmP,
            (true, true, 0b11000) => SimdOp::FMinNmP,
            (false, false, 0b11001) => SimdOp::FMla,
            (false, true, 0b11001) => SimdOp::FMls,
            (false, false, 0b11010) => SimdOp::FAdd,
            (false, true, 0b11010) => SimdOp::FSub,
            (true, false, 0b11010) => SimdOp::FAddP,
            (true, true, 0b11010) => SimdOp::FAbd,
            (false, false, 0b11011) => SimdOp::FMulx,
            (true, false, 0b11011) => SimdOp::FMul,
            (false, false, 0b11100) => SimdOp::FCmEq,
            (true, false, 0b11100) => SimdOp::FCmGe,
            (true, true, 0b11100) => SimdOp::FCmGt,
            (true, false, 0b11101) => SimdOp::FAcGe,
            (true, true, 0b11101) => SimdOp::FAcGt,
            (false, false, 0b11110) => SimdOp::FMax,
            (false, true, 0b11110) => SimdOp::FMin,
            (true, false, 0b11110) => SimdOp::FMaxP,
            (true, true, 0b11110) => SimdOp::FMinP,
            (false, false, 0b11111) => SimdOp::FRecps,
            (false, true, 0b11111) => SimdOp::FRsqrts,
            (true, false, 0b11111) => SimdOp::FDiv,
            _ => return Insn::Undefined,
        };
        return Insn::SimdThree { q, u, size: esize, op, rd, rn, rm, scalar: false };
    }
    let op = match (u, opcode) {
        (false, 0b00000) => SimdOp::SHAdd,
        (true, 0b00000) => SimdOp::UHAdd,
        (false, 0b00001) => SimdOp::SQAdd,
        (true, 0b00001) => SimdOp::UQAdd,
        (false, 0b00010) => SimdOp::SRHAdd,
        (true, 0b00010) => SimdOp::URHAdd,
        (false, 0b00011) => match size {
            0b00 => SimdOp::And,
            0b01 => SimdOp::Bic,
            0b10 => SimdOp::Orr,
            _ => SimdOp::Orn,
        },
        (true, 0b00011) => match size {
            0b00 => SimdOp::Eor,
            0b01 => SimdOp::Bsl,
            0b10 => SimdOp::Bit,
            _ => SimdOp::Bif,
        },
        (false, 0b00100) => SimdOp::SHSub,
        (true, 0b00100) => SimdOp::UHSub,
        (false, 0b00101) => SimdOp::SQSub,
        (true, 0b00101) => SimdOp::UQSub,
        (false, 0b00110) => SimdOp::CmGt,
        (true, 0b00110) => SimdOp::CmHi,
        (false, 0b00111) => SimdOp::CmGe,
        (true, 0b00111) => SimdOp::CmHs,
        (false, 0b01000) => SimdOp::SShl,
        (true, 0b01000) => SimdOp::UShl,
        (false, 0b01001) => SimdOp::SQShl,
        (true, 0b01001) => SimdOp::UQShl,
        (false, 0b01010) => SimdOp::SRShl,
        (true, 0b01010) => SimdOp::URShl,
        (false, 0b01011) => SimdOp::SQRShl,
        (true, 0b01011) => SimdOp::UQRShl,
        (false, 0b01100) => SimdOp::SMax,
        (true, 0b01100) => SimdOp::UMax,
        (false, 0b01101) => SimdOp::SMin,
        (true, 0b01101) => SimdOp::UMin,
        (false, 0b01110) => SimdOp::SAbd,
        (true, 0b01110) => SimdOp::UAbd,
        (false, 0b01111) => SimdOp::SAba,
        (true, 0b01111) => SimdOp::UAba,
        (false, 0b10000) => SimdOp::Add,
        (true, 0b10000) => SimdOp::Sub,
        (false, 0b10001) => SimdOp::CmTst,
        (true, 0b10001) => SimdOp::CmEq,
        (false, 0b10010) => SimdOp::Mla,
        (true, 0b10010) => SimdOp::Mls,
        (false, 0b10011) => SimdOp::Mul,
        (true, 0b10011) => SimdOp::PMul,
        (false, 0b10100) => SimdOp::SMaxP,
        (true, 0b10100) => SimdOp::UMaxP,
        (false, 0b10101) => SimdOp::SMinP,
        (true, 0b10101) => SimdOp::UMinP,
        (false, 0b10110) => SimdOp::SQDMulh,
        (true, 0b10110) => SimdOp::SQRDMulh,
        (false, 0b10111) => SimdOp::AddP,
        _ => return Insn::Undefined,
    };
    Insn::SimdThree { q, u, size, op, rd, rn, rm, scalar: false }
}

fn decode_simd_three_diff(x: u32, q: bool, u: bool) -> Insn {
    let size = bits(x, 23, 22) as u8;
    let opcode = bits(x, 15, 12);
    let rm = bits(x, 20, 16);
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    let s2 = |a: SimdOp, b: SimdOp| if q { b } else { a };
    let op = match (u, opcode) {
        (false, 0b0000) => s2(SimdOp::SAddL, SimdOp::SAddL2),
        (true, 0b0000) => s2(SimdOp::UAddL, SimdOp::UAddL2),
        (false, 0b0001) => s2(SimdOp::SAddW, SimdOp::SAddW2),
        (true, 0b0001) => s2(SimdOp::UAddW, SimdOp::UAddW2),
        (false, 0b0010) => s2(SimdOp::SSubL, SimdOp::SSubL2),
        (true, 0b0010) => s2(SimdOp::USubL, SimdOp::USubL2),
        (false, 0b0011) => s2(SimdOp::SSubW, SimdOp::SSubW2),
        (true, 0b0011) => s2(SimdOp::USubW, SimdOp::USubW2),
        (false, 0b0100) => s2(SimdOp::AddHn, SimdOp::AddHn2),
        (true, 0b0100) => s2(SimdOp::RAddHn, SimdOp::RAddHn2),
        (false, 0b0101) => s2(SimdOp::SAbaL, SimdOp::SAbaL2),
        (true, 0b0101) => s2(SimdOp::UAbaL, SimdOp::UAbaL2),
        (false, 0b0110) => s2(SimdOp::SubHn, SimdOp::SubHn2),
        (true, 0b0110) => s2(SimdOp::RSubHn, SimdOp::RSubHn2),
        (false, 0b0111) => s2(SimdOp::SAbdL, SimdOp::SAbdL2),
        (true, 0b0111) => s2(SimdOp::UAbdL, SimdOp::UAbdL2),
        (false, 0b1000) => s2(SimdOp::SMlaL, SimdOp::SMlaL2),
        (true, 0b1000) => s2(SimdOp::UMlaL, SimdOp::UMlaL2),
        (false, 0b1001) => s2(SimdOp::SQDMlaL, SimdOp::SQDMlaL2),
        (false, 0b1010) => s2(SimdOp::SMlsL, SimdOp::SMlsL2),
        (true, 0b1010) => s2(SimdOp::UMlsL, SimdOp::UMlsL2),
        (false, 0b1011) => s2(SimdOp::SQDMlsL, SimdOp::SQDMlsL2),
        (false, 0b1100) => s2(SimdOp::SMullL, SimdOp::SMullL2),
        (true, 0b1100) => s2(SimdOp::UMullL, SimdOp::UMullL2),
        (false, 0b1101) => s2(SimdOp::SQDMull, SimdOp::SQDMull2),
        (false, 0b1110) => s2(SimdOp::PMull, SimdOp::PMull2),
        _ => return Insn::Undefined,
    };
    Insn::SimdThree { q, u, size, op, rd, rn, rm, scalar: false }
}

fn decode_simd_two_misc(x: u32, q: bool, u: bool) -> Insn {
    let size = bits(x, 23, 22) as u8;
    let opcode = bits(x, 16, 12);
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    let sz1 = size & 1 != 0;
    let op = match (u, opcode) {
        (false, 0b00000) => Simd2Op::Rev64,
        (false, 0b00001) => Simd2Op::Rev16,
        (true, 0b00000) => Simd2Op::Rev32,
        (false, 0b00010) => Simd2Op::SaddLp,
        (true, 0b00010) => Simd2Op::UaddLp,
        (false, 0b00011) => Simd2Op::SuqAdd,
        (true, 0b00011) => Simd2Op::UsqAdd,
        (false, 0b00100) => Simd2Op::Cls,
        (true, 0b00100) => Simd2Op::Clz,
        (false, 0b00101) => Simd2Op::Cnt,
        (true, 0b00101) => {
            if size == 0b00 {
                Simd2Op::Not
            } else {
                Simd2Op::Rbit
            }
        }
        (false, 0b00110) => Simd2Op::SadaLp,
        (true, 0b00110) => Simd2Op::UadaLp,
        (false, 0b00111) => Simd2Op::SqAbs,
        (true, 0b00111) => Simd2Op::SqNeg,
        (false, 0b01000) => Simd2Op::CmGt0,
        (true, 0b01000) => Simd2Op::CmGe0,
        (false, 0b01001) => Simd2Op::CmEq0,
        (true, 0b01001) => Simd2Op::CmLe0,
        (false, 0b01010) => Simd2Op::CmLt0,
        (false, 0b01011) => Simd2Op::Abs,
        (true, 0b01011) => Simd2Op::Neg,
        (false, 0b10010) => {
            if q {
                Simd2Op::Xtn2
            } else {
                Simd2Op::Xtn
            }
        }
        (true, 0b10010) => {
            if q {
                Simd2Op::SqXtun2
            } else {
                Simd2Op::SqXtun
            }
        }
        (false, 0b10100) => {
            if q {
                Simd2Op::SqXtn2
            } else {
                Simd2Op::SqXtn
            }
        }
        (true, 0b10100) => {
            if q {
                Simd2Op::UqXtn2
            } else {
                Simd2Op::UqXtn
            }
        }
        (true, 0b10011) => {
            if q {
                Simd2Op::Shll2
            } else {
                Simd2Op::Shll
            }
        }
        (false, 0b10110) => {
            if q {
                Simd2Op::FcvtN2
            } else {
                Simd2Op::FcvtN
            }
        }
        (false, 0b10111) => {
            if q {
                Simd2Op::FcvtL2
            } else {
                Simd2Op::FcvtL
            }
        }
        (true, 0b10110) => {
            if q {
                Simd2Op::FcvtXn2
            } else {
                Simd2Op::FcvtXn
            }
        }
        // FP two-misc (sz selects S/D)
        (false, 0b11000) => if sz1 { Simd2Op::FrintP } else { Simd2Op::FrintN },
        (false, 0b11001) => if sz1 { Simd2Op::FrintZ } else { Simd2Op::FrintM },
        (false, 0b11010) => if sz1 { Simd2Op::Fcvtps } else { Simd2Op::Fcvtns },
        (false, 0b11011) => if sz1 { Simd2Op::Fcvtzs } else { Simd2Op::Fcvtms },
        (false, 0b11100) => if sz1 { Simd2Op::Fcvtzs } else { Simd2Op::Fcvtas },
        (false, 0b11101) => if sz1 { Simd2Op::Fcvtzs } else { Simd2Op::Scvtf },
        (true, 0b11000) => if sz1 { Simd2Op::FrintX } else { Simd2Op::FrintA },
        (true, 0b11001) => if sz1 { Simd2Op::FrintI } else { Simd2Op::Frint32X },
        (true, 0b11010) => if sz1 { Simd2Op::Fcvtpu } else { Simd2Op::Fcvtnu },
        (true, 0b11011) => if sz1 { Simd2Op::Fcvtzu } else { Simd2Op::Fcvtmu },
        (true, 0b11100) => if sz1 { Simd2Op::Fcvtzu } else { Simd2Op::Fcvtau },
        (true, 0b11101) => if sz1 { Simd2Op::Fcvtzu } else { Simd2Op::Ucvtf },
        (false, 0b01100) => if sz1 { Simd2Op::FCmGe0 } else { Simd2Op::FCmGt0 },
        (false, 0b01101) => if sz1 { Simd2Op::FCmLe0 } else { Simd2Op::FCmEq0 },
        (false, 0b01110) => Simd2Op::FCmLt0,
        (false, 0b01111) => Simd2Op::Fabs,
        (true, 0b01100) => if sz1 { Simd2Op::FCmGe0 } else { Simd2Op::FCmGe0 },
        (true, 0b01101) => Simd2Op::FCmLe0,
        (true, 0b01111) => Simd2Op::Fneg,
        (false, 0b11111) => Simd2Op::Fsqrt,
        (true, 0b11111) => Simd2Op::Fsqrt,
        (false, 0b11110) => if sz1 { Simd2Op::Frint64Z } else { Simd2Op::Frecpe },
        _ => return Insn::Undefined,
    };
    Insn::SimdMisc { q, u, size, op, rd, rn, scalar: false }
}

fn decode_simd_across(x: u32, q: bool, u: bool) -> Insn {
    let size = bits(x, 23, 22) as u8;
    let opcode = bits(x, 16, 12);
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    let sz1 = size & 1 != 0;
    let op = match (u, opcode) {
        (false, 0b00011) => AcrossOp::SAddLV,
        (true, 0b00011) => AcrossOp::UAddLV,
        (false, 0b11011) => AcrossOp::AddV,
        (false, 0b01010) => AcrossOp::SMaxV,
        (false, 0b11010) => AcrossOp::SMinV,
        (true, 0b01010) => AcrossOp::UMaxV,
        (true, 0b11010) => AcrossOp::UMinV,
        (true, 0b01100) => {
            if sz1 {
                AcrossOp::FMinNmV
            } else {
                AcrossOp::FMaxNmV
            }
        }
        (true, 0b01111) => {
            if sz1 {
                AcrossOp::FMinV
            } else {
                AcrossOp::FMaxV
            }
        }
        _ => return Insn::Undefined,
    };
    Insn::SimdAcross { q, size, op, rd, rn }
}

fn decode_simd_copy(x: u32, q: bool, u: bool) -> Insn {
    let imm5 = bits(x, 20, 16);
    let imm4 = bits(x, 14, 11);
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    if u {
        // INS (element)
        return Insn::SimdInsElt { imm5, imm4, rd, rn };
    }
    match imm4 {
        0b0000 => Insn::SimdDup { q, imm5, rd, rn, from_gpr: false }, // DUP (element)
        0b0001 => Insn::SimdDup { q, imm5, rd, rn, from_gpr: true },  // DUP (general)
        0b0011 => Insn::SimdInsGpr { imm5, rd, rn },                  // INS (general)
        0b0101 => Insn::SimdSmov { q, imm5, rd, rn },                 // SMOV
        0b0111 => Insn::SimdUmov { q, imm5, rd, rn },                 // UMOV
        _ => Insn::Undefined,
    }
}

fn decode_simd_mod_imm(x: u32, q: bool, u: bool) -> Insn {
    let abc = bits(x, 18, 16);
    let cmode = bits(x, 15, 12) as u8;
    let o2 = bit(x, 11);
    let defgh = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    if o2 {
        return Insn::Undefined;
    }
    let imm8 = (abc << 5) | defgh;
    let op = u as u8;
    let (imm, fp) = adv_simd_expand_imm(op, cmode, imm8 as u64);
    Insn::SimdModImm { q, op, cmode, rd, imm, fp }
}

fn decode_simd_shift_imm(x: u32, q: bool, u: bool, scalar: bool) -> Insn {
    let immh = bits(x, 22, 19);
    let immb = bits(x, 18, 16);
    let opcode = bits(x, 15, 11) as u8;
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    Insn::SimdShift { q, u, immh, immb, opcode, rd, rn, scalar }
}

fn decode_simd_indexed(x: u32, q: bool, u: bool, scalar: bool) -> Insn {
    let size = bits(x, 23, 22) as u8;
    let l = bit(x, 21);
    let m = bit(x, 20);
    let rmlo = bits(x, 19, 16);
    let opcode = bits(x, 15, 12) as u8;
    let h = bit(x, 11);
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    // Index and Rm depend on element size.
    let (index, rm) = match size {
        0b01 => (((h as u32) << 2) | ((l as u32) << 1) | (m as u32), rmlo),
        0b10 => (((h as u32) << 1) | (l as u32), (m as u32) << 4 | rmlo),
        0b11 => ((h as u32), (m as u32) << 4 | rmlo),
        _ => (((h as u32) << 2) | ((l as u32) << 1) | (m as u32), rmlo),
    };
    Insn::SimdIndexed { q, u, size, opcode, rd, rn, rm, index, scalar }
}
