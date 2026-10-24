// SPDX-License-Identifier: GPL-2.0
// Loads and stores. Included by decode.rs.
//
// Dispatch follows the "ldst" group of the A64 encoding index:
// op0 = bits 31:28, op1 = bit 26 (V), op2 = bits 24:10.

fn decode_ldst(x: u32) -> Insn {
    let v = bit(x, 26);
    match bits(x, 29, 28) {
        0b00 => {
            if v {
                // Advanced SIMD structure loads/stores (op0 = 0x00).
                if bit(x, 31) {
                    return Insn::Undefined;
                }
                return decode_simd_ldst(x);
            }
            if bit(x, 24) {
                // unprivileged exclusives/CAS (LSUI), MTE tags: not advertised
                return Insn::Undefined;
            }
            decode_ldst_excl(x)
        }
        0b01 => {
            if !bit(x, 24) {
                return decode_ldr_literal(x);
            }
            // Load/store ordered (unscaled immediate): LDAPUR/STLUR (LRCPC2).
            if !v && !bit(x, 21) && bits(x, 11, 10) == 0 {
                return decode_ldapstl_unscaled(x);
            }
            Insn::Undefined
        }
        0b10 => decode_ldst_pair(x),
        _ => {
            if bit(x, 24) {
                return decode_ldst_unsigned_imm(x);
            }
            let op4 = bits(x, 11, 10);
            if bit(x, 21) {
                return match op4 {
                    0b10 => decode_ldst_reg_offset(x),
                    0b00 => decode_ldst_atomic(x),
                    _ => Insn::Undefined, // LDRAA/LDRAB (PAuth)
                };
            }
            match op4 {
                0b00 => decode_ldst_unscaled(x),
                0b01 => decode_ldst_imm_wb(x, Index::Post),
                0b11 => decode_ldst_imm_wb(x, Index::Pre),
                _ => decode_ldst_unpriv(x),
            }
        }
    }
}

/// Map (size, opc, V) to (load, sign_ext, is_prefetch). opc is bits 23:22.
fn ldst_kind(size: u32, opc: u32, fp: bool) -> Option<(bool, u8, bool)> {
    if fp {
        // SIMD&FP: opc<0> is the load bit; size:opc<1> gives the width.
        if size != 0 && opc & 2 != 0 {
            return None;
        }
        return Some((opc & 1 != 0, 0, false));
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
        _ => {
            // LDRS* to 32-bit exists only for byte/halfword.
            if size >= 0b10 {
                None
            } else {
                Some((true, 32, false))
            }
        }
    }
}

/// For SIMD&FP loads/stores, the access size is opc<1>:size -> 0..4 (B..Q).
fn fp_acc_size(size: u32, opc: u32) -> u8 {
    (((opc & 2) << 1) | size) as u8
}

fn decode_ldst_unsigned_imm(x: u32) -> Insn {
    let size = bits(x, 31, 30);
    let fp = bit(x, 26);
    let opc = bits(x, 23, 22);
    let imm12 = bits(x, 21, 10) as i64;
    let (load, sign_ext, prefetch) = match ldst_kind(size, opc, fp) {
        Some(v) => v,
        None => return Insn::Undefined,
    };
    if prefetch {
        return Insn::Prfm;
    }
    let acc_size = if fp { fp_acc_size(size, opc) } else { size as u8 };
    Insn::LdSt {
        load,
        fp,
        size: acc_size,
        sign_ext,
        index: Index::Unsigned,
        order: Order::None,
        rt: bits(x, 4, 0),
        rn: bits(x, 9, 5),
        offset: imm12 << acc_size,
    }
}

fn decode_ldst_unscaled(x: u32) -> Insn {
    let size = bits(x, 31, 30);
    let fp = bit(x, 26);
    let opc = bits(x, 23, 22);
    let (load, sign_ext, prefetch) = match ldst_kind(size, opc, fp) {
        Some(v) => v,
        None => return Insn::Undefined,
    };
    if prefetch {
        return Insn::Prfm; // PRFUM
    }
    let acc_size = if fp { fp_acc_size(size, opc) } else { size as u8 };
    Insn::LdSt {
        load,
        fp,
        size: acc_size,
        sign_ext,
        index: Index::Signed,
        order: Order::None,
        rt: bits(x, 4, 0),
        rn: bits(x, 9, 5),
        offset: sx(bits(x, 20, 12), 9),
    }
}

fn decode_ldst_imm_wb(x: u32, index: Index) -> Insn {
    let size = bits(x, 31, 30);
    let fp = bit(x, 26);
    let opc = bits(x, 23, 22);
    let (load, sign_ext, prefetch) = match ldst_kind(size, opc, fp) {
        Some(v) => v,
        None => return Insn::Undefined,
    };
    if prefetch {
        return Insn::Undefined;
    }
    let acc_size = if fp { fp_acc_size(size, opc) } else { size as u8 };
    Insn::LdSt {
        load,
        fp,
        size: acc_size,
        sign_ext,
        index,
        order: Order::None,
        rt: bits(x, 4, 0),
        rn: bits(x, 9, 5),
        offset: sx(bits(x, 20, 12), 9),
    }
}

fn decode_ldst_unpriv(x: u32) -> Insn {
    // LDTR/STTR behave like LDUR/STUR at EL0. No SIMD&FP forms.
    if bit(x, 26) {
        return Insn::Undefined;
    }
    let size = bits(x, 31, 30);
    let opc = bits(x, 23, 22);
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
        rt: bits(x, 4, 0),
        rn: bits(x, 9, 5),
        offset: sx(bits(x, 20, 12), 9),
    }
}

fn decode_ldst_reg_offset(x: u32) -> Insn {
    let size = bits(x, 31, 30);
    let fp = bit(x, 26);
    let opc = bits(x, 23, 22);
    let option = bits(x, 15, 13);
    if option & 0b010 == 0 {
        return Insn::Undefined;
    }
    let (load, sign_ext, prefetch) = match ldst_kind(size, opc, fp) {
        Some(v) => v,
        None => return Insn::Undefined,
    };
    if prefetch {
        return Insn::Prfm; // PRFM (register) and RPRFM: hints
    }
    let acc_size = if fp { fp_acc_size(size, opc) } else { size as u8 };
    let shift = if bit(x, 12) { acc_size as u32 } else { 0 };
    Insn::LdStReg {
        load,
        fp,
        size: acc_size,
        sign_ext,
        ext: Ext::from_option(option),
        shift,
        rt: bits(x, 4, 0),
        rn: bits(x, 9, 5),
        rm: bits(x, 20, 16),
    }
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
        return Insn::LdStLiteral { fp: true, size, sign_ext: 0, rt, imm };
    }
    let (size, sign_ext) = match opc {
        0 => (2u8, 0),
        1 => (3, 0),
        2 => (2, 64), // LDRSW literal
        _ => return Insn::Prfm,
    };
    Insn::LdStLiteral { fp: false, size, sign_ext, rt, imm }
}

fn decode_ldst_pair(x: u32) -> Insn {
    let opc = bits(x, 31, 30);
    let fp = bit(x, 26);
    let load = bit(x, 22);
    let kind = bits(x, 24, 23); // 00=no-alloc,01=post,10=offset,11=pre
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
            1 if load && kind != 0 => (2, true), // LDPSW (no LDNPSW; STGP is MTE)
            2 => (3, false),
            _ => return Insn::Undefined,
        }
    };
    let index = match kind {
        0b01 => Index::Post,
        0b11 => Index::Pre,
        _ => Index::Signed,
    };
    let offset = sx(bits(x, 21, 15), 7) << size;
    Insn::LdStPair {
        load,
        fp,
        size,
        signed,
        index,
        no_alloc: kind == 0,
        rt: bits(x, 4, 0),
        rt2: bits(x, 14, 10),
        rn: bits(x, 9, 5),
        offset,
    }
}

/// Load/store exclusive (register/pair), ordered, and compare-and-swap
/// (bits 29:24 == 001000).
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
    match (o2, o1) {
        (false, false) => {
            // STXR/STLXR/LDXR/LDAXR (Rt2, and Rs for loads, are SBO).
            let order = if o0 { Order::AcqRel } else { Order::None };
            Insn::LdStExcl { load: l, pair: false, size: size as u8, order, rs, rt, rt2, rn }
        }
        (false, true) => {
            if bit(x, 31) {
                // STXP/STLXP/LDXP/LDAXP
                let sz = 2 + bit(x, 30) as u8;
                let order = if o0 { Order::AcqRel } else { Order::None };
                Insn::LdStExcl { load: l, pair: true, size: sz, order, rs, rt, rt2, rn }
            } else {
                // CASP{A}{L}: Rt2 == 11111, Rs and Rt even.
                if rt2 != 0b11111 || rs & 1 != 0 || rt & 1 != 0 {
                    return Insn::Undefined;
                }
                let sz = 2 + bit(x, 30) as u8;
                Insn::Cas { pair: true, size: sz, acquire: l, release: o0, rs, rt, rn }
            }
        }
        (true, true) => {
            // CAS{A}{L}{B,H}: Rt2 == 11111.
            if rt2 != 0b11111 {
                return Insn::Undefined;
            }
            Insn::Cas { pair: false, size: size as u8, acquire: l, release: o0, rs, rt, rn }
        }
        (true, false) => {
            // LDAR/STLR (o0 = 1). LDLAR/STLLR (o0 = 0) need FEAT_LOR.
            if !o0 {
                return Insn::Undefined;
            }
            Insn::LdSt {
                load: l,
                fp: false,
                size: size as u8,
                sign_ext: 0,
                index: Index::Signed,
                order: Order::AcqRel,
                rt,
                rn,
                offset: 0,
            }
        }
    }
}

/// LDAPUR*/STLUR* (FEAT_LRCPC2).
fn decode_ldapstl_unscaled(x: u32) -> Insn {
    let size = bits(x, 31, 30) as u8;
    let opc = bits(x, 23, 22);
    let (load, sign_ext) = match (size, opc) {
        (_, 0b00) => (false, 0u8),
        (_, 0b01) => (true, 0),
        (0..=2, 0b10) => (true, 64),
        (0..=1, 0b11) => (true, 32),
        _ => return Insn::Undefined,
    };
    Insn::LdSt {
        load,
        fp: false,
        size,
        sign_ext,
        index: Index::Signed,
        order: if load { Order::AcqPc } else { Order::AcqRel },
        rt: bits(x, 4, 0),
        rn: bits(x, 9, 5),
        offset: sx(bits(x, 20, 12), 9),
    }
}

/// Atomic memory operations (bit 21 == 1, bits 11:10 == 00).
fn decode_ldst_atomic(x: u32) -> Insn {
    if bit(x, 26) {
        return Insn::Undefined; // FP atomics (LSFE)
    }
    let size = bits(x, 31, 30) as u8;
    let a = bit(x, 23);
    let r = bit(x, 22);
    let rs = bits(x, 20, 16);
    let o3 = bit(x, 15);
    let opc = bits(x, 14, 12);
    let rn = bits(x, 9, 5);
    let rt = bits(x, 4, 0);
    if !o3 {
        let op = match opc {
            0b000 => RmwOp::Add,
            0b001 => RmwOp::Clr,
            0b010 => RmwOp::Eor,
            0b011 => RmwOp::Set,
            0b100 => RmwOp::Smax,
            0b101 => RmwOp::Smin,
            0b110 => RmwOp::Umax,
            _ => RmwOp::Umin,
        };
        return Insn::Atomic { op, size, acquire: a, release: r, rs, rt, rn };
    }
    match opc {
        0b000 => Insn::Atomic { op: RmwOp::Swp, size, acquire: a, release: r, rs, rt, rn },
        0b100 if a && !r && rs == 0b11111 => Insn::LdSt {
            // LDAPR{B,H}: RCpc load-acquire
            load: true,
            fp: false,
            size,
            sign_ext: 0,
            index: Index::Signed,
            order: Order::AcqPc,
            rt,
            rn,
            offset: 0,
        },
        _ => Insn::Undefined, // LS64 / RCW
    }
}
