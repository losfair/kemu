// SPDX-License-Identifier: GPL-2.0
// Loads and stores. Included by decode.rs.

fn decode_ldst(x: u32) -> Insn {
    let op0 = bits(x, 31, 28);
    let op1 = bit(x, 26); // SIMD&FP select for some forms
    let _ = op1;
    // Advanced SIMD load/store multiple & single structures.
    if bits(x, 31, 30) == 0b00 && bit(x, 29) == false && bits(x, 28, 24) == 0b01100 {
        return decode_simd_ldst(x);
    }
    // Compare-and-swap / exclusives / LSE atomics / general load-store.
    let op2 = bits(x, 25, 23);
    // Load/store exclusive & ordered: op0 == x0 0010/0011 patterns
    if bits(x, 29, 28) == 0b00 && bits(x, 26, 24) == 0b000 {
        return decode_ldst_excl(x);
    }
    // LDR literal (load register, literal)
    if bits(x, 29, 27) == 0b011 && bits(x, 25, 24) == 0b00 {
        return decode_ldr_literal(x);
    }
    // Load/store register (various)
    if bits(x, 29, 27) == 0b111 {
        // op2 bits 25:23
        if bit(x, 24) {
            return decode_ldst_unsigned_imm(x);
        }
        // bit24 == 0: register offset / unscaled / unpriv / post / pre / atomic
        let op4 = bits(x, 11, 10);
        if bit(x, 21) {
            if op4 == 0b10 {
                return decode_ldst_reg_offset(x);
            }
            // Atomic memory ops / CAS / LDAPR (op4 == 00)
            return decode_ldst_atomic(x);
        }
        return match op4 {
            0b00 => decode_ldst_unscaled(x),  // LDUR/STUR + LDAPUR/STLUR
            0b01 => decode_ldst_imm_post(x),
            0b11 => decode_ldst_imm_pre(x),
            0b10 => decode_ldst_unpriv(x),
            _ => Insn::Undefined,
        };
    }
    // Load/store pair
    if bits(x, 29, 27) == 0b101 {
        return decode_ldst_pair(x);
    }
    let _ = (op0, op2);
    Insn::Undefined
}

/// Map (size, opc, V) to (load, sign_ext, is_prefetch). opc is bits 23:22.
fn ldst_kind(size: u32, opc: u32, fp: bool) -> Option<(bool, u8, bool)> {
    if fp {
        // SIMD&FP: opc<0> is the load bit. size+opc<1> gives width (handled by caller).
        let load = opc & 1 != 0;
        return Some((load, 0, false));
    }
    match opc {
        0b00 => Some((false, 0, false)), // STR
        0b01 => Some((true, 0, false)),  // LDR (zero-extend)
        0b10 => {
            if size == 0b11 {
                Some((false, 0, true)) // PRFM
            } else {
                Some((true, 64, false)) // LDRS* to 64-bit
            }
        }
        0b11 => {
            if size == 0b11 {
                Insn_none()
            } else {
                Some((true, 32, false)) // LDRS* to 32-bit
            }
        }
        _ => None,
    }
}

#[inline]
fn Insn_none() -> Option<(bool, u8, bool)> {
    None
}

fn decode_ldst_unsigned_imm(x: u32) -> Insn {
    let size = bits(x, 31, 30);
    let fp = bit(x, 26);
    let opc = bits(x, 23, 22);
    let imm12 = bits(x, 21, 10) as i64;
    let rn = bits(x, 9, 5);
    let rt = bits(x, 4, 0);
    // FP access size can be 128 bits (size=00, opc=1x).
    let (load, sign_ext, prefetch) = match ldst_kind(size, opc, fp) {
        Some(v) => v,
        None => return Insn::Undefined,
    };
    if prefetch {
        return Insn::Prfm;
    }
    let acc_size = if fp { fp_acc_size(size, opc) } else { size as u8 };
    if acc_size > 4 {
        return Insn::Undefined;
    }
    let offset = imm12 << acc_size;
    Insn::LdSt {
        load,
        fp,
        size: acc_size,
        sign_ext,
        index: Index::Unsigned,
        order: Order::None,
        rt,
        rn,
        offset,
    }
}

/// For SIMD&FP loads/stores, the access size is size:opc<1> -> 0..4 (B..Q).
fn fp_acc_size(size: u32, opc: u32) -> u8 {
    (((opc & 2) << 1) | size) as u8
}

fn decode_ldst_unscaled(x: u32) -> Insn {
    let size = bits(x, 31, 30);
    let fp = bit(x, 26);
    let opc = bits(x, 23, 22);
    let imm9 = sx(bits(x, 20, 12), 9);
    let rn = bits(x, 9, 5);
    let rt = bits(x, 4, 0);
    let (load, sign_ext, prefetch) = match ldst_kind(size, opc, fp) {
        Some(v) => v,
        None => return Insn::Undefined,
    };
    if prefetch {
        return Insn::Prfm;
    }
    let acc_size = if fp { fp_acc_size(size, opc) } else { size as u8 };
    if acc_size > 4 {
        return Insn::Undefined;
    }
    Insn::LdSt {
        load,
        fp,
        size: acc_size,
        sign_ext,
        index: Index::Signed,
        order: Order::None,
        rt,
        rn,
        offset: imm9,
    }
}

fn decode_ldst_imm_post(x: u32) -> Insn {
    decode_ldst_imm_wb(x, Index::Post)
}
fn decode_ldst_imm_pre(x: u32) -> Insn {
    decode_ldst_imm_wb(x, Index::Pre)
}
fn decode_ldst_imm_wb(x: u32, index: Index) -> Insn {
    let size = bits(x, 31, 30);
    let fp = bit(x, 26);
    let opc = bits(x, 23, 22);
    let imm9 = sx(bits(x, 20, 12), 9);
    let rn = bits(x, 9, 5);
    let rt = bits(x, 4, 0);
    let (load, sign_ext, prefetch) = match ldst_kind(size, opc, fp) {
        Some(v) => v,
        None => return Insn::Undefined,
    };
    if prefetch {
        return Insn::Undefined;
    }
    let acc_size = if fp { fp_acc_size(size, opc) } else { size as u8 };
    if acc_size > 4 {
        return Insn::Undefined;
    }
    Insn::LdSt { load, fp, size: acc_size, sign_ext, index, order: Order::None, rt, rn, offset: imm9 }
}

fn decode_ldst_unpriv(x: u32) -> Insn {
    // LDTR/STTR behave like unscaled for EL0 (no privilege difference).
    let size = bits(x, 31, 30);
    let opc = bits(x, 23, 22);
    let imm9 = sx(bits(x, 20, 12), 9);
    let rn = bits(x, 9, 5);
    let rt = bits(x, 4, 0);
    let (load, sign_ext, prefetch) = match ldst_kind(size, opc, false) {
        Some(v) => v,
        None => return Insn::Undefined,
    };
    if prefetch {
        return Insn::Undefined;
    }
    Insn::LdSt {
        load,
        fp: false,
        size: size as u8,
        sign_ext,
        index: Index::Signed,
        order: Order::None,
        rt,
        rn,
        offset: imm9,
    }
}

fn decode_ldst_reg_offset(x: u32) -> Insn {
    let size = bits(x, 31, 30);
    let fp = bit(x, 26);
    let opc = bits(x, 23, 22);
    let rm = bits(x, 20, 16);
    let option = bits(x, 15, 13);
    let s = bit(x, 12);
    let rn = bits(x, 9, 5);
    let rt = bits(x, 4, 0);
    if option & 0b010 == 0 {
        return Insn::Undefined; // option must allow 64-bit index (X or W with extend)
    }
    let (load, sign_ext, prefetch) = match ldst_kind(size, opc, fp) {
        Some(v) => v,
        None => return Insn::Undefined,
    };
    if prefetch {
        return Insn::Prfm;
    }
    let acc_size = if fp { fp_acc_size(size, opc) } else { size as u8 };
    if acc_size > 4 {
        return Insn::Undefined;
    }
    let ext = Ext::from_option(option);
    let shift = if s { acc_size as u32 } else { 0 };
    Insn::LdStReg { load, fp, size: acc_size, sign_ext, ext, shift, rt, rn, rm }
}

fn decode_ldr_literal(x: u32) -> Insn {
    let opc = bits(x, 31, 30);
    let fp = bit(x, 26);
    let imm = sx(bits(x, 23, 5), 19) * 4;
    let rt = bits(x, 4, 0);
    if fp {
        let size = match opc {
            0 => 2u8,
            1 => 3,
            2 => 4,
            _ => return Insn::Undefined,
        };
        // Represent as PC-relative: use Adr-like via LdSt from a synthetic base.
        // We encode literal loads as LdSt with rn=31(PC marker) is ambiguous,
        // so give them their own simple form via offset from PC in interp.
        return Insn::LdStLiteral { fp: true, size, sign_ext: 0, rt, imm };
    }
    let (size, sign_ext) = match opc {
        0 => (2u8, 0),
        1 => (3, 0),
        2 => (2, 64), // LDRSW literal
        _ => return Insn::Prfm, // PRFM literal
    };
    Insn::LdStLiteral { fp: false, size, sign_ext, rt, imm }
}

fn decode_ldst_pair(x: u32) -> Insn {
    let opc = bits(x, 31, 30);
    let fp = bit(x, 26);
    let load = bit(x, 22);
    let kind = bits(x, 24, 23); // 00=no-alloc,01=post,10=offset,11=pre
    let imm7 = sx(bits(x, 21, 15), 7);
    let rt2 = bits(x, 14, 10);
    let rn = bits(x, 9, 5);
    let rt = bits(x, 4, 0);
    let (size, signed): (u8, bool) = if fp {
        match opc {
            0 => (2, false),
            1 => (3, false),
            2 => (4, false),
            _ => return Insn::Undefined,
        }
    } else {
        match opc {
            0 => (2, false),
            1 => (2, true), // LDPSW
            2 => (3, false),
            _ => return Insn::Undefined,
        }
    };
    if !fp && opc == 1 && !load {
        return Insn::Undefined; // STGP-ish / reserved
    }
    let index = match kind {
        0b00 => Index::Signed, // STNP/LDNP (no writeback)
        0b01 => Index::Post,
        0b10 => Index::Signed,
        0b11 => Index::Pre,
        _ => return Insn::Undefined,
    };
    let no_alloc = kind == 0b00;
    let offset = imm7 << size;
    Insn::LdStPair { load, fp, size, signed, index, no_alloc, rt, rt2, rn, offset }
}

fn decode_ldst_excl(x: u32) -> Insn {
    let size = bits(x, 31, 30);
    let o2 = bit(x, 23);
    let l = bit(x, 22);
    let o1 = bit(x, 21);
    let rs = bits(x, 20, 16);
    let o0 = bit(x, 15);
    let rt2 = bits(x, 14, 10);
    let rn = bits(x, 9, 5);
    let rt = bits(x, 4, 0);

    if !o2 && !o1 {
        // Single exclusive: STXR/LDXR/STLXR/LDAXR.
        let order = if o0 { Order::AcqRel } else { Order::None };
        return Insn::LdStExcl { load: l, pair: false, size: size as u8, order, rs, rt, rt2, rn };
    }
    if !o2 && o1 {
        if bit(x, 31) {
            // Pair exclusive: STXP/LDXP (size bit30 selects 32/64).
            let sz = 2 + bits(x, 30, 30) as u8;
            let order = if o0 { Order::AcqRel } else { Order::None };
            return Insn::LdStExcl { load: l, pair: true, size: sz, order, rs, rt, rt2, rn };
        } else {
            // CASP: bit31=0, bit30 selects 32/64-bit pair.
            let sz = 2 + bits(x, 30, 30) as u8;
            return Insn::Cas { pair: true, size: sz, acquire: l, release: o0, rs, rt, rn };
        }
    }
    if o2 && o1 {
        // CAS/CASB/CASH (size gives width).
        return Insn::Cas { pair: false, size: size as u8, acquire: l, release: o0, rs, rt, rn };
    }
    // o2 && !o1: STLR / LDAR (ordered, non-exclusive).
    let order = if o0 { Order::AcqRel } else { Order::AcqPc };
    Insn::LdSt {
        load: l,
        fp: false,
        size: size as u8,
        sign_ext: 0,
        index: Index::Signed,
        order,
        rt,
        rn,
        offset: 0,
    }
}

fn decode_ldst_atomic(x: u32) -> Insn {
    let size = bits(x, 31, 30) as u8;
    let fp = bit(x, 26);
    if fp {
        return Insn::Undefined;
    }
    let a = bit(x, 23);
    let r = bit(x, 22);
    let rs = bits(x, 20, 16);
    let o3 = bit(x, 15);
    let opc = bits(x, 14, 12);
    let rn = bits(x, 9, 5);
    let rt = bits(x, 4, 0);
    // CAS: handled in the compare-and-swap group (bit21=1, bit15=1, opc=...)
    // Here: o3==0 => LSE atomic RMW; special forms for SWP/LDAPR/STLR.
    if !o3 {
        let op = match opc {
            0b000 => RmwOp::Add,
            0b001 => RmwOp::Clr,
            0b010 => RmwOp::Eor,
            0b011 => RmwOp::Set,
            0b100 => RmwOp::Smax,
            0b101 => RmwOp::Smin,
            0b110 => RmwOp::Umax,
            0b111 => RmwOp::Umin,
            _ => return Insn::Undefined,
        };
        return Insn::Atomic { op, size, acquire: a, release: r, rs, rt, rn };
    } else {
        // o3==1
        match opc {
            0b000 => {
                // SWP
                Insn::Atomic { op: RmwOp::Swp, size, acquire: a, release: r, rs, rt, rn }
            }
            0b100 => {
                // LDAPR (rs==11111, a=1,r=0) : RCpc load
                if rs == 0b11111 {
                    Insn::LdSt {
                        load: true,
                        fp: false,
                        size,
                        sign_ext: 0,
                        index: Index::Signed,
                        order: Order::AcqPc,
                        rt,
                        rn,
                        offset: 0,
                    }
                } else {
                    Insn::Undefined
                }
            }
            _ => Insn::Undefined,
        }
    }
}
