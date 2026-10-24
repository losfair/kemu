// SPDX-License-Identifier: GPL-2.0
// Advanced SIMD load/store multiple & single structures. Included by decode_simd.rs.

fn decode_simd_ldst(x: u32) -> Insn {
    let q = bit(x, 30);
    let load = bit(x, 22);
    let post = bit(x, 23); // post-indexed forms set bit23
    let rm = bits(x, 20, 16);
    let rn = bits(x, 9, 5);
    let rt = bits(x, 4, 0);
    let single = bit(x, 24); // 0 = multiple structures, 1 = single structure
    if !single {
        // LD/ST multiple structures
        let opcode = bits(x, 15, 12) as u8;
        let size = bits(x, 11, 10) as u8;
        let selem = match opcode {
            0b0000 => 4, // LD/ST4 (4 regs)
            0b0010 => 4, // LD/ST1 4 regs
            0b0100 => 3, // LD/ST3
            0b0110 => 3, // LD/ST1 3 regs
            0b0111 => 1, // LD/ST1 1 reg
            0b1000 => 2, // LD/ST2
            0b1010 => 2, // LD/ST1 2 regs
            _ => return Insn::Undefined,
        };
        return Insn::SimdLdSt {
            load,
            q,
            size,
            opcode,
            rt,
            rn,
            rm,
            single: false,
            index: 0,
            replicate: false,
            selem,
            post,
        };
    }
    // LD/ST single structure (and replicate for loads)
    let opcode = bits(x, 15, 13) as u8;
    let s = bit(x, 12);
    let size = bits(x, 11, 10) as u8;
    let r = bit(x, 21); // selem low bit
    let replicate = opcode == 0b110;
    // selem = (opcode<0> << 1 | R) + 1 ... follow the standard formula.
    let selem = (((opcode & 1) << 1) | r as u8) + 1;
    // Element size and index depend on opcode[2:1]:
    let (esize, index) = match opcode >> 1 {
        0b00 => (0u8, ((q as u32) << 3) | ((s as u32) << 2) | size as u32), // B
        0b01 => (1u8, ((q as u32) << 2) | ((s as u32) << 1) | (size as u32 >> 1)), // H
        0b10 => {
            if size & 1 == 0 {
                (2u8, ((q as u32) << 1) | (s as u32)) // S
            } else {
                (3u8, q as u32) // D
            }
        }
        _ => (size, 0),
    };
    let _ = esize;
    Insn::SimdLdSt {
        load,
        q,
        size: if replicate { size } else { (opcode >> 1).min(3) },
        opcode,
        rt,
        rn,
        rm,
        single: true,
        index,
        replicate,
        selem,
        post,
    }
}
