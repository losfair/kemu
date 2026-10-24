// SPDX-License-Identifier: GPL-2.0
// Data processing (register). Included by decode.rs.

fn decode_dp_reg(x: u32) -> Insn {
    let op1 = bit(x, 28);
    let op2 = bits(x, 24, 21);
    if !op1 {
        if !bit(x, 24) {
            return decode_logical_shift(x);
        }
        if bit(x, 21) {
            return decode_addsub_ext(x);
        }
        return decode_addsub_shift(x);
    }
    match op2 {
        0b0000 => {
            let b1510 = bits(x, 15, 10);
            if b1510 == 0 {
                decode_addsub_carry(x)
            } else if bits(x, 14, 10) == 0b00001 {
                decode_rmif(x)
            } else if bits(x, 13, 10) == 0b0010 {
                decode_setf(x)
            } else {
                Insn::Undefined
            }
        }
        0b0010 => decode_cond_cmp(x),
        0b0100 => decode_cond_sel(x),
        0b0110 => {
            if bit(x, 30) {
                decode_dp1(x)
            } else {
                decode_dp2(x)
            }
        }
        0b1000..=0b1111 => decode_dp3(x),
        _ => Insn::Undefined,
    }
}

fn decode_addsub_carry(x: u32) -> Insn {
    let sf = bit(x, 31);
    let sub = bit(x, 30);
    let setflags = bit(x, 29);
    let rm = bits(x, 20, 16);
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    if bits(x, 15, 10) != 0 {
        return Insn::Undefined;
    }
    Insn::AddSubCarry { sf, sub, setflags, rd, rn, rm }
}

fn decode_rmif(x: u32) -> Insn {
    // RMIF: sf=1, S=0, imm6 in 20:15, Rn in 9:5, mask in 3:0
    if !bit(x, 31) || bit(x, 29) {
        return Insn::Undefined;
    }
    let lsb = bits(x, 20, 15);
    let rn = bits(x, 9, 5);
    let mask = bits(x, 3, 0);
    Insn::Rmif { rn, lsb, mask }
}

fn decode_setf(x: u32) -> Insn {
    // SETF8/SETF16: sz = bit 14
    if !bit(x, 31) == false { /* sf must be 0 */ }
    if bit(x, 31) || bit(x, 29) {
        return Insn::Undefined;
    }
    let sz = bit(x, 14) as u8; // 0 => 8-bit, 1 => 16-bit
    let rn = bits(x, 9, 5);
    Insn::SetfFlags { sz, rn }
}

fn decode_cond_cmp(x: u32) -> Insn {
    let sf = bit(x, 31);
    let sub = bit(x, 30); // op: 0 => CCMN (add), 1 => CCMP (sub)
    let reg = bits(x, 11, 10) == 0b00; // bit11:10==00 register, ==10 immediate? check
    // Encoding: bit 11 selects imm(1)/reg(0). We used reg field below.
    let is_imm = bit(x, 11);
    let cond = bits(x, 15, 12);
    let rn = bits(x, 9, 5);
    let nzcv = bits(x, 3, 0);
    if bit(x, 10) || bit(x, 4) {
        return Insn::Undefined;
    }
    let imm_or_rm = bits(x, 20, 16);
    let _ = reg;
    Insn::CondCmp { sf, sub, reg: !is_imm, rn, imm_or_rm, nzcv, cond }
}

fn decode_cond_sel(x: u32) -> Insn {
    let sf = bit(x, 31);
    let op = bit(x, 30);
    let s = bit(x, 29);
    let rm = bits(x, 20, 16);
    let cond = bits(x, 15, 12);
    let op2 = bits(x, 11, 10);
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    if s {
        return Insn::Undefined;
    }
    let csel = match (op, op2) {
        (false, 0b00) => CselOp::Csel,
        (false, 0b01) => CselOp::Csinc,
        (true, 0b00) => CselOp::Csinv,
        (true, 0b01) => CselOp::Csneg,
        _ => return Insn::Undefined,
    };
    Insn::CondSel { sf, op: csel, rd, rn, rm, cond }
}

fn decode_logical_shift(x: u32) -> Insn {
    let sf = bit(x, 31);
    let opc = bits(x, 30, 29);
    let shift = Shift::from2(bits(x, 23, 22));
    let n = bit(x, 21);
    let rm = bits(x, 20, 16);
    let amount = bits(x, 15, 10);
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    if !sf && amount >= 32 {
        return Insn::Undefined;
    }
    let (op, negate) = match (opc, n) {
        (0b00, false) => (LogicOp::And, false),
        (0b00, true) => (LogicOp::And, true), // BIC
        (0b01, false) => (LogicOp::Orr, false),
        (0b01, true) => (LogicOp::Orr, true), // ORN
        (0b10, false) => (LogicOp::Eor, false),
        (0b10, true) => (LogicOp::Eor, true), // EON
        (0b11, false) => (LogicOp::Ands, false),
        (0b11, true) => (LogicOp::Ands, true), // BICS
        _ => return Insn::Undefined,
    };
    Insn::LogicShift { sf, op, negate, shift, amount, rd, rn, rm }
}

fn decode_addsub_shift(x: u32) -> Insn {
    let sf = bit(x, 31);
    let sub = bit(x, 30);
    let setflags = bit(x, 29);
    let sh = bits(x, 23, 22);
    let rm = bits(x, 20, 16);
    let amount = bits(x, 15, 10);
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    if sh == 0b11 || (!sf && amount >= 32) {
        return Insn::Undefined;
    }
    let shift = Shift::from2(sh);
    Insn::AddSubShift { sf, sub, setflags, shift, amount, rd, rn, rm }
}

fn decode_addsub_ext(x: u32) -> Insn {
    let sf = bit(x, 31);
    let sub = bit(x, 30);
    let setflags = bit(x, 29);
    let rm = bits(x, 20, 16);
    let option = bits(x, 15, 13);
    let imm3 = bits(x, 12, 10);
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    if imm3 > 4 || bits(x, 23, 22) != 0 {
        return Insn::Undefined;
    }
    let ext = Ext::from_option(option);
    Insn::AddSubExt { sf, sub, setflags, ext, amount: imm3, rd, rn, rm }
}

fn decode_dp1(x: u32) -> Insn {
    let sf = bit(x, 31);
    let s = bit(x, 29);
    let opcode2 = bits(x, 20, 16);
    let opcode = bits(x, 15, 10);
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    if s || opcode2 != 0 {
        return Insn::Undefined;
    }
    let op = match opcode {
        0b000000 => Dp1Op::Rbit,
        0b000001 => Dp1Op::Rev16,
        0b000010 => {
            if sf {
                Dp1Op::Rev32
            } else {
                Dp1Op::Rev
            }
        }
        0b000011 if sf => Dp1Op::Rev,
        0b000100 => Dp1Op::Clz,
        0b000101 => Dp1Op::Cls,
        _ => return Insn::Undefined,
    };
    Insn::Dp1 { sf, op, rd, rn }
}

fn decode_dp2(x: u32) -> Insn {
    let sf = bit(x, 31);
    let s = bit(x, 29);
    let rm = bits(x, 20, 16);
    let opcode = bits(x, 15, 10);
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    if s {
        return Insn::Undefined;
    }
    let (op, crc_sz) = match opcode {
        0b000010 => (Dp2Op::Udiv, 0),
        0b000011 => (Dp2Op::Sdiv, 0),
        0b001000 => (Dp2Op::Lslv, 0),
        0b001001 => (Dp2Op::Lsrv, 0),
        0b001010 => (Dp2Op::Asrv, 0),
        0b001011 => (Dp2Op::Rorv, 0),
        0b010000 => (Dp2Op::Crc32, 0),
        0b010001 => (Dp2Op::Crc32, 1),
        0b010010 => (Dp2Op::Crc32, 2),
        0b010011 => (Dp2Op::Crc32, 3),
        0b010100 => (Dp2Op::Crc32c, 0),
        0b010101 => (Dp2Op::Crc32c, 1),
        0b010110 => (Dp2Op::Crc32c, 2),
        0b010111 => (Dp2Op::Crc32c, 3),
        _ => return Insn::Undefined,
    };
    // CRC32X (size 3) requires sf==1; CRC32 w-variants require sf==0 except X.
    Insn::Dp2 { sf, op, rd, rn, rm, crc_sz }
}

fn decode_dp3(x: u32) -> Insn {
    let sf = bit(x, 31);
    let op54 = bits(x, 30, 29);
    let op31 = bits(x, 23, 21);
    let rm = bits(x, 20, 16);
    let o0 = bit(x, 15);
    let ra = bits(x, 14, 10);
    let rn = bits(x, 9, 5);
    let rd = bits(x, 4, 0);
    if op54 != 0 {
        return Insn::Undefined;
    }
    let op = match (op31, o0) {
        (0b000, false) => MulOp::Madd,
        (0b000, true) => MulOp::Msub,
        (0b001, false) => MulOp::Smaddl,
        (0b001, true) => MulOp::Smsubl,
        (0b010, false) => MulOp::Smulh,
        (0b101, false) => MulOp::Umaddl,
        (0b101, true) => MulOp::Umsubl,
        (0b110, false) => MulOp::Umulh,
        _ => return Insn::Undefined,
    };
    // SMULH/UMULH require sf==1 and ra==31.
    Insn::Mul { op, rd, rn, rm, ra }
}
