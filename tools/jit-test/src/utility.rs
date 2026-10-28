// SPDX-License-Identifier: GPL-2.0
//! Libc/compiler hot instructions, including live FP status around MSR.
use super::*;

pub fn case(it: u64, r: &mut Rng, init: &mut CpuState) -> Vec<u32> {
    let lines: Vec<_> = include_str!("utility-catalog.txt").lines().collect();
    let line = lines[it as usize % lines.len()];
    let mut word = u32::from_str_radix(&line[..8], 16).unwrap();
    let rd = r.below(24) as u32;
    // Keep the live-FP probes in V28/V29 intact when installing edge inputs.
    let rn = if r.below(3) == 0 { rd } else { r.below(28) as u32 };
    let rm = if r.below(3) == 0 { rd } else { r.below(28) as u32 };
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
    let pass = it / lines.len() as u64;
    match decode(word) {
        Insn::SimdThree { op: SimdOp::UQSub, .. } => {
            // Saturation, equality, no saturation, and saturation confined
            // to inactive upper lanes; also exercise already-sticky QC.
            init.fpsr = (init.fpsr & !(1 << 27)) | ((pass as u32 & 1) << 27);
            let pair = match pass % 5 {
                0 => Some(([0, 0], [0, u64::MAX])),
                1 => Some(([u64::MAX; 2], [0; 2])),
                2 => Some(([0; 2], [u64::MAX; 2])),
                3 => Some(([0xff00_ffff_0000_0100; 2], [0x00ff_0000_ffff_0100; 2])),
                _ => None,
            };
            if let Some((a, b)) = pair { init.v[rn as usize] = a; init.v[rm as usize] = b; }
        }
        Insn::SimdThree { op: SimdOp::CmTst, .. } if pass % 3 != 2 => {
            init.v[rn as usize] = [0xaaaa_aaaa_aaaa_aaaa, 0];
            init.v[rm as usize] = [if pass % 3 == 0 { 0x5555_5555_5555_5555 } else { u64::MAX }, u64::MAX];
        }
        Insn::SimdThree { op: SimdOp::UShl, size: size @ (2 | 3), .. } => {
            const SHIFTS: &[u8] = &[0, 1, 31, 32, 63, 64, 127, 128, 129, 192, 193, 224, 255];
            for lane in 0..(16 >> size) {
                let shift = SHIFTS[(pass as usize + lane) % SHIFTS.len()] as u64;
                let value = (r.next() & !0xff) | shift;
                let slot = &mut init.v[rm as usize][lane >> (3 - size)];
                if size == 3 { *slot = value; } else {
                    let bit = (lane & 1) * 32;
                    *slot = (*slot & !(0xffff_ffff << bit)) | (value & 0xffff_ffff) << bit;
                }
            }
        }
        _ => {}
    }
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
