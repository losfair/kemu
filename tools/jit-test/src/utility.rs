// SPDX-License-Identifier: GPL-2.0
//! Libc/compiler hot instructions, including live FP status around MSR.
use super::*;

pub fn case(it: u64, r: &mut Rng, init: &mut CpuState) -> Vec<u32> {
    let lines: Vec<_> = include_str!("utility-catalog.txt").lines().collect();
    let line = lines[it as usize % lines.len()];
    let mut word = u32::from_str_radix(&line[..8], 16).unwrap();
    let rd = r.below(24) as u32;
    let rn = if r.below(3) == 0 { rd } else { r.below(32) as u32 };
    let rm = if r.below(3) == 0 { rd } else { r.below(32) as u32 };
    match decode(word) {
        Insn::Dp1 { .. } | Insn::SimdMisc { .. } | Insn::SimdAcross { .. } | Insn::SimdShift { .. } => word = (word & !0x3ff) | rn << 5 | rd,
        Insn::SimdThree { .. } => word = (word & !0x1f03ff) | rm << 16 | rn << 5 | rd,
        Insn::SimdIndexed { size, .. } => {
            let mask = if size == 1 { 15 } else { 31 };
            word = (word & !(mask << 16 | 0x3ff)) | (rm & mask) << 16 | rn << 5 | rd;
        }
        Insn::SimdModImm { .. } => word = (word & !31) | rd,
        Insn::Mrs { .. } | Insn::MsrReg { .. } => word = (word & !31) | (if it % 7 == 0 { 31 } else { rd }),
        _ => panic!("unexpected utility form: {line}"),
    }
    for v in &mut init.v { *v = [r.val(), r.val()]; }
    init.v[28] = [1.0f64.to_bits(), r.val()];
    init.v[29] = [if it & 1 == 0 { 0 } else { 3.0f64.to_bits() }, r.val()];
    init.fpcr = (r.next() as u32) & kemu_core::softfloat::FPCR_MASK;
    init.fpsr = (r.next() as u32) & kemu_core::softfloat::FPSR_MASK;
    vec![
        0xeb01_001f, // CMP X0,X1: preserve live NZCV across every operation
        0x1e7d_1b9f, // FDIV D31,D28,D29: live MXCSR DZC/IXC before MSR
        word,
        0xd53b_443a, // MRS X26,FPSR: observe clears before the next FDIV
        0x1e7d_1b9f,
        0xd53b_441b, // MRS X27,FPCR
        0x9a88_00f9 | ((r.below(14) as u32) << 12), // CSEL X25,X7,X8,cond
        0xd420_0000,
    ]
}
