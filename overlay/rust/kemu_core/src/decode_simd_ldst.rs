// SPDX-License-Identifier: GPL-2.0
// Advanced SIMD load/store multiple & single structures. Included by
// decode_simd.rs. Called for bit31 == 0, bits 29:25 == 0b00110.

fn decode_simd_ldst(x: u32) -> Insn {
    let q = bit(x, 30);
    let post = bit(x, 23);
    let load = bit(x, 22);
    let rm = bits(x, 20, 16);
    let rn = bits(x, 9, 5);
    let rt = bits(x, 4, 0);
    let size = bits(x, 11, 10) as u8;
    if !bit(x, 24) {
        // Multiple structures: bit 21 == 0; without post-index Rm == 0.
        if bit(x, 21) || (!post && rm != 0) {
            return Insn::Undefined;
        }
        let opcode = bits(x, 15, 12) as u8;
        // (selem) per opcode; the LD1/ST1 multi-register forms (selem = 1,
        // rpt = 2..4) are told apart by `opcode` in the interpreter.
        let selem = match opcode {
            0b0000 => 4, // LD4/ST4
            0b0010 => 1, // LD1/ST1 (4 registers)
            0b0100 => 3, // LD3/ST3
            0b0110 => 1, // LD1/ST1 (3 registers)
            0b0111 => 1, // LD1/ST1 (1 register)
            0b1000 => 2, // LD2/ST2
            0b1010 => 1, // LD1/ST1 (2 registers)
            _ => return Insn::Undefined,
        };
        if selem != 1 && size == 3 && !q {
            return Insn::Undefined;
        }
        return Insn::SimdLdSt { load, q, size, opcode, rt, rn, rm, single: false, index: 0, replicate: false, selem, post };
    }
    // Single structure: without post-index Rm == 0.
    if !post && rm != 0 {
        return Insn::Undefined;
    }
    let opcode = bits(x, 15, 13) as u8;
    let s = bit(x, 12) as u32;
    let r = bit(x, 21) as u8;
    let selem = (((opcode & 1) << 1) | r) + 1;
    let qb = q as u32;
    let (esize, index, replicate) = match opcode >> 1 {
        0b00 => (0u8, (qb << 3) | (s << 2) | size as u32, false),
        0b01 => {
            if size & 1 != 0 {
                return Insn::Undefined;
            }
            (1u8, (qb << 2) | (s << 1) | (size as u32 >> 1), false)
        }
        0b10 => match size {
            0b00 => (2u8, (qb << 1) | s, false),
            0b01 if s == 0 => (3u8, qb, false),
            _ => return Insn::Undefined,
        },
        _ => {
            if !load || s != 0 {
                return Insn::Undefined;
            }
            (size, 0, true)
        }
    };
    Insn::SimdLdSt { load, q, size: esize, opcode, rt, rn, rm, single: true, index, replicate, selem, post }
}
