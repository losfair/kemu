// SPDX-License-Identifier: GPL-2.0
//! Canonical guest-to-host register mapping (DESIGN.md §8.1).
//!
//! At every block boundary, pinned guest registers live in their host
//! registers and all others live in the state page (`gs:[8 * n]`).

use super::x86::*;

/// Guest register number used for SP in the mapping tables.
pub const GUEST_SP: u32 = 32;

/// (guest register, host register) for pinned registers. Index 31 = SP.
pub const PINNED: [(u32, Reg); 13] = [
    (GUEST_SP, RBX),
    (29, RBP),
    (30, RSI),
    (0, RDI),
    (1, RCX),
    (2, R8),
    (3, R9),
    (4, R10),
    (5, R11),
    (19, R12),
    (20, R13),
    (21, R14),
    (9, R15),
];

/// Scratch registers never holding guest state across instructions.
pub const SCRATCH0: Reg = RAX;
pub const SCRATCH1: Reg = RDX;

/// Host register holding guest X[n] (n <= 30) or SP (n == GUEST_SP).
pub const fn host_of(n: u32) -> Option<Reg> {
    match n {
        32 => Some(RBX),
        29 => Some(RBP),
        30 => Some(RSI),
        0 => Some(RDI),
        1 => Some(RCX),
        2 => Some(R8),
        3 => Some(R9),
        4 => Some(R10),
        5 => Some(R11),
        19 => Some(R12),
        20 => Some(R13),
        21 => Some(R14),
        9 => Some(R15),
        _ => None,
    }
}

/// Guest register pinned to host register `r`, if any.
pub const fn guest_of(r: Reg) -> Option<u32> {
    match r {
        RBX => Some(GUEST_SP),
        RBP => Some(29),
        RSI => Some(30),
        RDI => Some(0),
        RCX => Some(1),
        R8 => Some(2),
        R9 => Some(3),
        R10 => Some(4),
        R11 => Some(5),
        R12 => Some(19),
        R13 => Some(20),
        R14 => Some(21),
        R15 => Some(9),
        _ => None,
    }
}

/// State-page offset of guest X[n] / SP.
pub const fn slot_of(n: u32) -> i32 {
    if n == GUEST_SP {
        248
    } else {
        (n as i32) * 8
    }
}

pub const OFF_PC: i32 = 256;
pub const OFF_NZCV: i32 = 264;
pub const OFF_FPCR: i32 = 272;
pub const OFF_FPSR: i32 = 276;
pub const OFF_TPIDR: i32 = 280;
pub const OFF_TPIDRRO: i32 = 288;
pub const OFF_EXCL_ADDR: i32 = 296;
pub const OFF_EXCL_SIZE: i32 = 304;
pub const OFF_EXCL_VAL: i32 = 312;
pub const OFF_EXIT_INFO: i32 = 408;
pub const OFF_FLAGS_X86: i32 = 416;
/// MXCSR image (scratch slot 7), saved/restored by the stubs.
pub const OFF_MXCSR: i32 = 400;
pub const OFF_V: i32 = 512;

/// Spill all pinned registers (and MXCSR) to the state page.
pub fn spill_all(a: &mut Asm<'_>) {
    for (g, h) in PINNED.iter() {
        a.store(Sz::Q, Mem::gs(slot_of(*g)), *h);
    }
    a.vex(1, 0, false, false, 0xae, 3, 0, Rm::M(Mem::gs(OFF_MXCSR))); // vstmxcsr
}

/// Reload all pinned registers (and MXCSR) from the state page.
pub fn reload_all(a: &mut Asm<'_>) {
    for (g, h) in PINNED.iter() {
        a.load(Sz::Q, *h, Mem::gs(slot_of(*g)));
    }
    a.vex(1, 0, false, false, 0xae, 2, 0, Rm::M(Mem::gs(OFF_MXCSR))); // vldmxcsr
}

/// MXCSR for a guest FPCR/FPSR: rounding mode, flush-to-zero, all
/// exceptions masked, and the cumulative flags from FPSR.
pub fn mxcsr_from(fpcr: u32, fpsr: u32) -> u32 {
    let rc = match (fpcr >> 22) & 3 {
        0 => 0, // RN
        1 => 2, // RP -> round up
        2 => 1, // RM -> round down
        _ => 3, // RZ
    };
    let fz = if fpcr & (1 << 24) != 0 { (1 << 15) | (1 << 6) } else { 0 };
    let f = |b: u32| (fpsr >> b) & 1;
    let flags = f(0) | (f(1) << 2) | (f(2) << 3) | (f(3) << 4) | (f(4) << 5);
    0x1f80 | (rc << 13) | fz | flags
}

/// Merge MXCSR exception flags into FPSR's cumulative flags.
pub fn fpsr_merge(fpsr: u32, mxcsr: u32) -> u32 {
    let m = |b: u32| (mxcsr >> b) & 1;
    // IE->IOC, ZE->DZC, OE->OFC, UE->UFC, PE->IXC (DE has no equivalent)
    fpsr | m(0) | (m(2) << 1) | (m(3) << 2) | (m(4) << 3) | (m(5) << 4)
}

/// x86 flags image stored at `OFF_FLAGS_X86` (16 bits): AL = V, AH = lahf
/// byte with CF = C (never inverted), SF = N, ZF = Z.
pub fn nzcv_from_image(img: u64) -> u64 {
    let ah = (img >> 8) & 0xff;
    let n = (ah >> 7) & 1;
    let z = (ah >> 6) & 1;
    let c = ah & 1;
    let v = img & 1;
    (n << 31) | (z << 30) | (c << 29) | (v << 28)
}

pub fn image_from_nzcv(nzcv: u64) -> u64 {
    let n = (nzcv >> 31) & 1;
    let z = (nzcv >> 30) & 1;
    let c = (nzcv >> 29) & 1;
    let v = (nzcv >> 28) & 1;
    // lahf layout: SF ZF 0 AF 0 PF 1 CF
    let ah = (n << 7) | (z << 6) | 0x02 | c;
    (ah << 8) | v
}

/// NZCV from host RFLAGS, where `inverted` means C = !CF.
pub fn nzcv_from_rflags(rflags: u64, inverted: bool) -> u64 {
    let cf = rflags & 1;
    let zf = (rflags >> 6) & 1;
    let sf = (rflags >> 7) & 1;
    let of = (rflags >> 11) & 1;
    let c = if inverted { cf ^ 1 } else { cf };
    (sf << 31) | (zf << 30) | (c << 29) | (of << 28)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_roundtrip() {
        for nzcv in 0..16u64 {
            let v = nzcv << 28;
            assert_eq!(nzcv_from_image(image_from_nzcv(v)), v);
        }
    }

    #[test]
    fn maps_consistent() {
        for (g, h) in PINNED.iter() {
            assert_eq!(host_of(*g), Some(*h));
            assert_eq!(guest_of(*h), Some(*g));
        }
        assert_eq!(guest_of(SCRATCH0), None);
        assert_eq!(guest_of(SCRATCH1), None);
        assert_eq!(guest_of(RSP), None);
    }
}
