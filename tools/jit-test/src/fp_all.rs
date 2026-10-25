// SPDX-License-Identifier: GPL-2.0
//! Exhaustive decoded FP form catalog: ordinary inputs must run without
//! helpers; edge cases compare every register and FPSR bit with softfloat.
use super::*;
use kemu_core::decode::{FcvtOp, Simd2Op};

pub fn case(it: u64, r: &mut Rng, init: &mut CpuState) -> Vec<u32> {
    let catalog: Vec<_> = include_str!("fp-catalog.txt").lines().collect();
    let line = catalog[(it as usize / 2) % catalog.len()];
    let mut word = u32::from_str_radix(&line[..8], 16).unwrap();
    let insn = decode(word);
    assert!(!matches!(insn, Insn::Undefined), "{line}");
    let size;
    let mut integer = false;
    let mut fixed = false;
    match insn {
        Insn::Fp1 { ftype, .. } | Insn::FpCCmp { ftype, .. } => {
            size = match ftype {
                3 => 1,
                _ => ftype + 2,
            }
        }
        Insn::FpCvt { ftype, op, .. } => {
            size = if ftype == 1 { 3 } else { 2 };
            integer = matches!(op, FcvtOp::ItoF { .. } | FcvtOp::FixedToF { .. });
            fixed = matches!(op, FcvtOp::FtoFixed { .. });
        }
        Insn::SimdMisc { size: s, op, .. } => {
            size = s + matches!(op, Simd2Op::FcvtN | Simd2Op::FcvtN2 | Simd2Op::FcvtXn | Simd2Op::FcvtXn2) as u8;
            integer = matches!(op, Simd2Op::Scvtf | Simd2Op::Ucvtf);
        }
        Insn::SimdThree { size: s, .. } | Insn::SimdAcross { size: s, .. } | Insn::SimdIndexed { size: s, .. } => size = s,
        Insn::SimdShift { immh, opcode, .. } => {
            size = (31 - immh.leading_zeros()) as u8;
            integer = opcode == 28;
            fixed = opcode == 31;
        }
        _ => panic!("unexpected form {insn:?}"),
    }
    let edge = it & 1 != 0;
    let round = ((it / (2 * catalog.len() as u64)) % 4) as u32;
    init.fpcr = round << 22;
    if edge {
        init.fpcr |= (r.below(4) == 0) as u32 * (1 << 24);
        init.fpcr |= (r.below(2) as u32) << 25;
        init.fpcr |= (r.below(4) == 0) as u32 * (1 << 26);
    }
    init.fpsr = if edge && r.below(2) == 0 {
        r.next() as u32 & 0x0800_009f
    } else {
        0
    };
    let values: &[u64] = match size {
        1 => &[
            0, 0x8000, 1, 0x3ff, 0x400, 0x3c00, 0x3e00, 0xbe00, 0x7bff, 0x7c00, 0xfc00, 0x7e01, 0x7c01,
        ],
        2 => &[
            0, 0x80000000, 1, 0x7fffff, 0x800000, 0x3f000000, 0x3fc00000, 0xbfc00000, 0x7f800000, 0xff800000, 0x7fc01234, 0x7f800001,
            0x4f000000, 0xcf000000, 0x4f800000, 0x5f000000, 0x5f800000, 0x477ff000, 0x38800000, 0x3f800001, 0x7f7fffff,
        ],
        _ => &[
            0,
            1 << 63,
            1,
            0xfffffffffffff,
            0x10000000000000,
            0x3fe0000000000000,
            0x3ff8000000000000,
            0xbff8000000000000,
            0x7ff0000000000000,
            0xfff0000000000000,
            0x7ff8000000001234,
            0x7ff0000000000001,
            0x41e0000000000000,
            0xc1e0000000000000,
            0x43e0000000000000,
            0x43f0000000000000,
            0x3ff0000000000001,
            0x7fefffffffffffff,
        ],
    };
    for v in &mut init.v {
        let mut bits = 0u128;
        for lane in 0..(16 >> size) {
            let x = if edge && r.below(2) == 0 {
                r.next()
            } else if edge {
                values[r.below(values.len() as u64) as usize]
            } else if integer {
                1234567 + r.below(100)
            } else if !fixed {
                match size {
                    1 => 0x3800 + r.below(0xc00),
                    2 => 0x3f000000 + r.below(0x1800000),
                    _ => 0x3fe0000000000000 + r.below(0x30000000000000),
                }
            } else {
                match (size, fixed) {
                    (1, _) => 0x3d00,
                    (2, true) => 0x3e800000,
                    (2, false) => 0x3fa00000,
                    (_, true) => 0x3fd0000000000000,
                    _ => 0x3ff4000000000000,
                }
            };
            let width = 8 << size;
            bits |= ((x as u128) & ((1u128 << width) - 1)) << (lane * width);
        }
        *v = [bits as u64, (bits >> 64) as u64];
    }
    if integer {
        init.x[1] = if edge { r.val() } else { 1234567 };
    }
    if edge && line.contains("underflow boundary") {
        init.fpcr = 1 << 22; // round upward across the normal/subnormal boundary
        init.fpsr = 0;
        if size == 2 {
            init.v[1] = [0x007fffff007fffff; 2];
            init.v[2] = [0x3f8000013f800001; 2];
        } else {
            init.v[1] = [0x000fffffffffffff; 2];
            init.v[2] = [0x3ff0000000000001; 2];
        }
    }
    // Alias only edge cases: after the first conversion the source may have
    // a different format and is no longer guaranteed to take the fast path.
    if edge && !line.contains("underflow boundary") && !matches!(insn, Insn::FpCCmp { .. } | Insn::FpCvt { .. }) && r.below(3) == 0 {
        word = (word & !31) | ((word >> 5) & 31);
    }
    vec![0xeb03009f, word, word, word, 0x9a8800e6, 0xd4200000]
}
