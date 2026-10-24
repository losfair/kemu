// SPDX-License-Identifier: GPL-2.0
//! Random instruction and state generation for the differential tester.

use crate::{Arch, Rng};

/// Destination GPR: 2..=30 (x0/x1 are harness scratch).
fn rd(r: &mut Rng) -> u32 {
    2 + r.bits(5) % 29
}
/// Any source GPR 0..=30 (31 would be XZR/SP depending on form).
fn rn(r: &mut Rng) -> u32 {
    r.bits(5) % 31
}
/// Vector register 0..=31.
fn vr(r: &mut Rng) -> u32 {
    r.bits(5)
}

/// A mix of "interesting" and random 64-bit values.
fn interesting(r: &mut Rng) -> u64 {
    match r.bits(4) {
        0 => 0,
        1 => 1,
        2 => u64::MAX,
        3 => 0x8000_0000_0000_0000,
        4 => 0x7fff_ffff_ffff_ffff,
        5 => 0xffff_ffff,
        6 => 0x8000_0000,
        7 => 0x7fff_ffff,
        8 => r.next() & 0xff,
        9 => 1u64 << (r.bits(6)),
        _ => r.next(),
    }
}

/// Interesting FP bit patterns (per 64-bit lane; also used for 32-bit lanes).
fn interesting_fp(r: &mut Rng) -> u64 {
    match r.bits(4) {
        0 => 0,                         // +0
        1 => 0x8000_0000_0000_0000,     // -0
        2 => 0x3ff0_0000_0000_0000,     // 1.0
        3 => 0x7ff0_0000_0000_0000,     // +inf
        4 => 0xfff0_0000_0000_0000,     // -inf
        5 => 0x7ff8_0000_0000_0000,     // qNaN
        6 => 0x7ff0_0000_0000_0001,     // sNaN
        7 => 0x0008_0000_0000_0000,     // denormal
        8 => 0x4009_21fb_5444_2d18,     // ~pi
        9 => 0x3f80_0000_3f80_0000,     // two f32 1.0
        10 => 0x7fc0_0000_7fc0_0000,    // two f32 qNaN
        11 => 0xc000_0000,              // f32 -2.0 in low
        _ => r.next(),
    }
}

pub fn random_state(r: &mut Rng) -> Arch {
    let mut a = Arch::zeroed();
    for x in a.x.iter_mut() {
        *x = interesting(r);
    }
    a.sp = 0x7000_0000 & !0xf; // aligned, benign (not dereferenced)
    a.nzcv = (r.bits(4) as u64) << 28;
    // FPCR: random rounding mode, optional FZ/DN.
    let rmode = r.bits(2);
    let mut fpcr = rmode << 22;
    if r.bits(2) == 0 {
        fpcr |= 1 << 24; // FZ
    }
    if r.bits(2) == 0 {
        fpcr |= 1 << 25; // DN
    }
    a.fpcr = fpcr;
    a.fpsr = 0;
    for v in a.v.iter_mut() {
        *v = [interesting_fp(r), interesting_fp(r)];
    }
    a
}

pub struct Class {
    pub name: &'static str,
    pub gen: fn(&mut Rng) -> u32,
}

pub static CLASSES: &[Class] = &[
    Class { name: "addsub_imm", gen: g_addsub_imm },
    Class { name: "addsub_shift", gen: g_addsub_shift },
    Class { name: "addsub_ext", gen: g_addsub_ext },
    Class { name: "logical_imm", gen: g_logical_imm },
    Class { name: "logical_shift", gen: g_logical_shift },
    Class { name: "movewide", gen: g_movewide },
    Class { name: "bitfield", gen: g_bitfield },
    Class { name: "extract", gen: g_extract },
    Class { name: "condsel", gen: g_condsel },
    Class { name: "condcmp", gen: g_condcmp },
    Class { name: "dp1", gen: g_dp1 },
    Class { name: "dp2", gen: g_dp2 },
    Class { name: "dp3", gen: g_dp3 },
    Class { name: "fp2src", gen: g_fp2src },
    Class { name: "fp1src", gen: g_fp1src },
    Class { name: "fpcvtint", gen: g_fp_cvt_int },
    Class { name: "fpcmp", gen: g_fp_cmp },
    Class { name: "fpcsel", gen: g_fp_csel },
    Class { name: "simd_three", gen: g_simd_three },
    Class { name: "simd_misc", gen: g_simd_misc },
    Class { name: "simd_dup", gen: g_simd_dup },
];

fn sf(r: &mut Rng) -> u32 {
    r.bits(1)
}

fn g_addsub_imm(r: &mut Rng) -> u32 {
    let sf = sf(r);
    let op = r.bits(1); // 0 add, 1 sub
    let s = r.bits(1);
    let sh = r.bits(1);
    let imm = r.bits(12);
    (sf << 31) | (op << 30) | (s << 29) | (0b100010 << 23) | (sh << 22) | (imm << 10) | (rn(r) << 5) | rd(r)
}

fn g_addsub_shift(r: &mut Rng) -> u32 {
    let sf = sf(r);
    let op = r.bits(1);
    let s = r.bits(1);
    let shift = r.bits(2) % 3; // LSL/LSR/ASR
    let amount = if sf == 1 { r.bits(6) } else { r.bits(5) };
    (sf << 31) | (op << 30) | (s << 29) | (0b01011 << 24) | (shift << 22) | (rn(r) << 16) | (amount << 10) | (rn(r) << 5) | rd(r)
}

fn g_addsub_ext(r: &mut Rng) -> u32 {
    let sf = sf(r);
    let op = r.bits(1);
    let s = r.bits(1);
    let opt = r.bits(3);
    let imm3 = r.bits(2); // 0..3 (<=4)
    (sf << 31) | (op << 30) | (s << 29) | (0b01011001 << 21) | (rn(r) << 16) | (opt << 13) | (imm3 << 10) | (rn(r) << 5) | rd(r)
}

fn g_logical_imm(r: &mut Rng) -> u32 {
    let sf = sf(r);
    let opc = r.bits(2);
    // Pick a valid (N,immr,imms); retry until DecodeBitMasks succeeds.
    loop {
        let n = if sf == 1 { r.bits(1) } else { 0 };
        let immr = r.bits(6);
        let imms = r.bits(6);
        if kemu_core::decode::decode_bit_masks(sf == 1, n, imms, immr).is_some() {
            return (sf << 31) | (opc << 29) | (0b100100 << 23) | (n << 22) | (immr << 16) | (imms << 10) | (rn(r) << 5) | rd(r);
        }
    }
}

fn g_logical_shift(r: &mut Rng) -> u32 {
    let sf = sf(r);
    let opc = r.bits(2);
    let shift = r.bits(2);
    let n = r.bits(1);
    let amount = if sf == 1 { r.bits(6) } else { r.bits(5) };
    (sf << 31) | (opc << 29) | (0b01010 << 24) | (shift << 22) | (n << 21) | (rn(r) << 16) | (amount << 10) | (rn(r) << 5) | rd(r)
}

fn g_movewide(r: &mut Rng) -> u32 {
    let sf = sf(r);
    let opc = match r.bits(2) {
        0 => 0b00, // MOVN
        1 => 0b10, // MOVZ
        _ => 0b11, // MOVK
    };
    let hw = if sf == 1 { r.bits(2) } else { r.bits(1) };
    let imm = r.bits(16);
    (sf << 31) | (opc << 29) | (0b100101 << 23) | (hw << 21) | (imm << 5) | rd(r)
}

fn g_bitfield(r: &mut Rng) -> u32 {
    let sf = sf(r);
    let opc = r.bits(2) % 3; // SBFM/BFM/UBFM
    let n = sf;
    let maxv = if sf == 1 { 63 } else { 31 };
    let immr = r.bits(6) % (maxv + 1);
    let imms = r.bits(6) % (maxv + 1);
    (sf << 31) | (opc << 29) | (0b100110 << 23) | (n << 22) | (immr << 16) | (imms << 10) | (rn(r) << 5) | rd(r)
}

fn g_extract(r: &mut Rng) -> u32 {
    let sf = sf(r);
    let n = sf;
    let imms = if sf == 1 { r.bits(6) } else { r.bits(5) };
    (sf << 31) | (0b00100111 << 23) | (n << 22) | (rn(r) << 16) | (imms << 10) | (rn(r) << 5) | rd(r)
}

fn g_condsel(r: &mut Rng) -> u32 {
    let sf = sf(r);
    let op = r.bits(1);
    let op2 = r.bits(1);
    let cond = r.bits(4);
    (sf << 31) | (op << 30) | (0b11010100 << 21) | (rn(r) << 16) | (cond << 12) | (op2 << 10) | (rn(r) << 5) | rd(r)
}

fn g_condcmp(r: &mut Rng) -> u32 {
    let sf = sf(r);
    let op = r.bits(1);
    let imm_mode = r.bits(1);
    let cond = r.bits(4);
    let operand = r.bits(5);
    let nzcv = r.bits(4);
    (sf << 31) | (op << 30) | (1 << 29) | (0b11010010 << 21) | (operand << 16) | (cond << 12) | (imm_mode << 11) | (rn(r) << 5) | nzcv
}

fn g_dp1(r: &mut Rng) -> u32 {
    let sf = sf(r);
    // RBIT/REV16/REV32|REV/REV/CLZ/CLS -> opcode 0..5
    let opcode = r.bits(3) % 6;
    (sf << 31) | (1 << 30) | (0b11010110 << 21) | (opcode << 10) | (rn(r) << 5) | rd(r)
}

fn g_dp2(r: &mut Rng) -> u32 {
    let sf = sf(r);
    // UDIV(2) SDIV(3) LSLV(8) LSRV(9) ASRV(10) RORV(11)
    let opcode = match r.bits(3) % 6 {
        0 => 0b000010,
        1 => 0b000011,
        2 => 0b001000,
        3 => 0b001001,
        4 => 0b001010,
        _ => 0b001011,
    };
    (sf << 31) | (0b0011010110 << 21) | (rn(r) << 16) | (opcode << 10) | (rn(r) << 5) | rd(r)
}

fn g_dp3(r: &mut Rng) -> u32 {
    let sf = sf(r);
    // MADD/MSUB (o0), and the long/high variants with sf=1.
    let kind = r.bits(3);
    let (op31, o0, force_sf) = match kind {
        0 => (0b000, 0, None),       // MADD
        1 => (0b000, 1, None),       // MSUB
        2 => (0b001, 0, Some(1)),    // SMADDL
        3 => (0b001, 1, Some(1)),    // SMSUBL
        4 => (0b101, 0, Some(1)),    // UMADDL
        5 => (0b101, 1, Some(1)),    // UMSUBL
        6 => (0b010, 0, Some(1)),    // SMULH
        _ => (0b110, 0, Some(1)),    // UMULH
    };
    let sf = force_sf.unwrap_or(sf);
    // SMULH/UMULH (op31 010/110) require Ra = 31.
    let ra = if op31 == 0b010 || op31 == 0b110 { 31 } else { rn(r) };
    (sf << 31) | (0b0011011 << 24) | (op31 << 21) | (rn(r) << 16) | (o0 << 15) | (ra << 10) | (rn(r) << 5) | rd(r)
}

fn g_fp2src(r: &mut Rng) -> u32 {
    let ftype = r.bits(1); // 0=S,1=D
    let opcode = r.bits(4) % 9; // MUL..NMUL
    (0b00011110 << 24) | (ftype << 22) | (1 << 21) | (vr(r) << 16) | (opcode << 12) | (0b10 << 10) | (vr(r) << 5) | vr(r)
}

fn g_fp1src(r: &mut Rng) -> u32 {
    let ftype = r.bits(1);
    // FMOV/FABS/FNEG/FSQRT/FRINT*
    let opcode = match r.bits(4) % 11 {
        0 => 0b000000,
        1 => 0b000001,
        2 => 0b000010,
        3 => 0b000011,
        4 => 0b001000,
        5 => 0b001001,
        6 => 0b001010,
        7 => 0b001011,
        8 => 0b001100,
        9 => 0b001110,
        _ => 0b001111,
    };
    (0b00011110 << 24) | (ftype << 22) | (1 << 21) | (opcode << 15) | (0b10000 << 10) | (vr(r) << 5) | vr(r)
}

fn g_fp_cvt_int(r: &mut Rng) -> u32 {
    let sf = sf(r);
    let ftype = r.bits(1);
    // FCVT*/SCVTF/UCVTF/FMOV: rmode:opcode
    let (rmode, opcode) = match r.bits(4) % 8 {
        0 => (0b00, 0b000), // FCVTNS
        1 => (0b00, 0b001), // FCVTNU
        2 => (0b00, 0b010), // SCVTF
        3 => (0b00, 0b011), // UCVTF
        4 => (0b11, 0b000), // FCVTZS
        5 => (0b11, 0b001), // FCVTZU
        6 => (0b00, 0b110), // FMOV to GPR
        _ => (0b00, 0b111), // FMOV from GPR
    };
    (sf << 31) | (0b0011110 << 24) | (ftype << 22) | (1 << 21) | (rmode << 19) | (opcode << 16) | (rn(r) << 5) | rd(r)
}

fn g_fp_cmp(r: &mut Rng) -> u32 {
    let ftype = r.bits(1);
    let opc = r.bits(2) & 0b10; // FCMP / FCMPE (bit3), bit4 signalling
    let zero = r.bits(1);
    let op2 = (opc) | (zero << 3);
    (0b00011110 << 24) | (ftype << 22) | (1 << 21) | (vr(r) << 16) | (0b1000 << 10) | (vr(r) << 5) | op2
}

fn g_fp_csel(r: &mut Rng) -> u32 {
    let ftype = r.bits(1);
    let cond = r.bits(4);
    (0b00011110 << 24) | (ftype << 22) | (1 << 21) | (vr(r) << 16) | (cond << 12) | (0b11 << 10) | (vr(r) << 5) | vr(r)
}

fn g_simd_three(r: &mut Rng) -> u32 {
    let q = r.bits(1);
    let u = r.bits(1);
    let size = r.bits(2);
    let opcode = r.bits(5);
    (q << 30) | (u << 29) | (0b01110 << 24) | (size << 22) | (1 << 21) | (vr(r) << 16) | (opcode << 11) | (1 << 10) | (vr(r) << 5) | vr(r)
}

fn g_simd_misc(r: &mut Rng) -> u32 {
    let q = r.bits(1);
    let u = r.bits(1);
    let size = r.bits(2);
    let opcode = r.bits(5);
    (q << 30) | (u << 29) | (0b01110 << 24) | (size << 22) | (0b10000 << 17) | (opcode << 12) | (0b10 << 10) | (vr(r) << 5) | vr(r)
}

fn g_simd_dup(r: &mut Rng) -> u32 {
    let q = r.bits(1);
    let imm5 = (r.bits(5) | 1) & 0x1f; // ensure a nonzero low bit sometimes
    (q << 30) | (0b001110000 << 21) | (imm5 << 16) | (1 << 10) | (vr(r) << 5) | vr(r)
}
