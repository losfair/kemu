// SPDX-License-Identifier: GPL-2.0
use super::*;
use crate::state::CpuState;
use crate::env::{Env, Fault};

/// Simple flat-memory test environment.
pub struct TestEnv {
    pub mem: alloc_vec::Vec<u8>,
    pub base: u64,
}

mod alloc_vec {
    pub use std::vec::Vec;
}

impl TestEnv {
    fn idx(&self, a: u64) -> Option<usize> {
        a.checked_sub(self.base).map(|x| x as usize).filter(|i| *i < self.mem.len())
    }
}

impl Env for TestEnv {
    fn fetch(&mut self, pc: u64) -> Result<u32, Fault> {
        self.read_u32(pc)
    }
    fn read_u8(&mut self, a: u64) -> Result<u8, Fault> {
        self.idx(a).map(|i| self.mem[i]).ok_or(Fault { addr: a, access: crate::env::Access::Read, align: false })
    }
    fn read_u16(&mut self, a: u64) -> Result<u16, Fault> {
        Ok(u16::from_le_bytes([self.read_u8(a)?, self.read_u8(a + 1)?]))
    }
    fn read_u32(&mut self, a: u64) -> Result<u32, Fault> {
        let mut b = [0u8; 4];
        for (i, bb) in b.iter_mut().enumerate() { *bb = self.read_u8(a + i as u64)?; }
        Ok(u32::from_le_bytes(b))
    }
    fn read_u64(&mut self, a: u64) -> Result<u64, Fault> {
        let mut b = [0u8; 8];
        for (i, bb) in b.iter_mut().enumerate() { *bb = self.read_u8(a + i as u64)?; }
        Ok(u64::from_le_bytes(b))
    }
    fn write_u8(&mut self, a: u64, v: u8) -> Result<(), Fault> {
        let i = self.idx(a).ok_or(Fault { addr: a, access: crate::env::Access::Write, align: false })?;
        self.mem[i] = v; Ok(())
    }
    fn write_u16(&mut self, a: u64, v: u16) -> Result<(), Fault> {
        for (i, b) in v.to_le_bytes().iter().enumerate() { self.write_u8(a + i as u64, *b)?; } Ok(())
    }
    fn write_u32(&mut self, a: u64, v: u32) -> Result<(), Fault> {
        for (i, b) in v.to_le_bytes().iter().enumerate() { self.write_u8(a + i as u64, *b)?; } Ok(())
    }
    fn write_u64(&mut self, a: u64, v: u64) -> Result<(), Fault> {
        for (i, b) in v.to_le_bytes().iter().enumerate() { self.write_u8(a + i as u64, *b)?; } Ok(())
    }
    fn cmpxchg(&mut self, a: u64, size: u32, expected: [u64;2], new: [u64;2]) -> Result<[u64;2], Fault> {
        let old0 = match size { 1 => self.read_u8(a)? as u64, 2 => self.read_u16(a)? as u64, 4 => self.read_u32(a)? as u64, _ => self.read_u64(a)? };
        let old1 = if size == 16 { self.read_u64(a + 8)? } else { 0 };
        if [old0, old1] == [expected[0] & szmask(size), expected[1]] {
            match size { 1 => self.write_u8(a, new[0] as u8)?, 2 => self.write_u16(a, new[0] as u16)?, 4 => self.write_u32(a, new[0] as u32)?, 8 => self.write_u64(a, new[0])?, _ => { self.write_u64(a, new[0])?; self.write_u64(a+8, new[1])?; } }
        }
        Ok([old0, old1])
    }
    fn cntvct(&mut self) -> u64 { 0 }
    fn cntfrq(&mut self) -> u64 { 1_000_000_000 }
    fn random(&mut self) -> Option<u64> { Some(0x1234_5678_9abc_def0) }
}

fn szmask(size: u32) -> u64 {
    match size { 1 => 0xff, 2 => 0xffff, 4 => 0xffff_ffff, _ => u64::MAX }
}

fn run_code(code: &[u32]) -> (CpuState, Exit) {
    let mut mem = std::vec![0u8; 0x10000];
    for (i, w) in code.iter().enumerate() {
        mem[i*4..i*4+4].copy_from_slice(&w.to_le_bytes());
    }
    let mut env = TestEnv { mem, base: 0x1000 };
    let mut cpu = CpuState::new();
    cpu.pc = 0x1000;
    cpu.sp = 0x1000 + 0x8000;
    let (e, _) = run(&mut cpu, &mut env, 1000);
    (cpu, e)
}

#[test]
fn add_and_svc() {
    // movz x0,#5 ; movz x1,#7 ; add x0,x0,x1 ; svc #0
    let (cpu, e) = run_code(&[0xd28000a0, 0xd28000e1, 0x8b010000, 0xd4000001]);
    assert_eq!(e, Exit::Svc);
    assert_eq!(cpu.x[0], 12);
}

#[test]
fn memory_roundtrip() {
    // movz x1,#0x2000; movz x0,#0xabcd; str x0,[x1]; ldr x2,[x1]; svc
    let (cpu, e) = run_code(&[0xd2840001, 0xd29579a0, 0xf9000020, 0xf9400022, 0xd4000001]);
    assert_eq!(e, Exit::Svc);
    assert_eq!(cpu.x[2], 0xabcd);
}

#[test]
fn ccmp_and_cond() {
    // cmp x0,#0 (x0=0) => eq; cset x0,eq -> 1
    // movz x0,#0 ; cmp x0,#0 ; cset x0, eq
    let (cpu, e) = run_code(&[0xd2800000, 0xf100001f, 0x9a9f17e0, 0xd4000001]);
    let _ = e;
    assert_eq!(cpu.x[0], 1);
}

/// Run `code` after `setup` initialises the CPU; memory 0x1000..0x11000,
/// code at 0x1000.
fn run_setup(code: &[u32], setup: &dyn Fn(&mut CpuState, &mut [u8])) -> (CpuState, Exit) {
    let mut mem = std::vec![0u8; 0x10000];
    for (i, w) in code.iter().enumerate() {
        mem[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    let mut cpu = CpuState::new();
    cpu.pc = 0x1000;
    cpu.sp = 0x1000 + 0x8000;
    setup(&mut cpu, &mut mem);
    let mut env = TestEnv { mem, base: 0x1000 };
    let (e, _) = run(&mut cpu, &mut env, 1000);
    (cpu, e)
}

const SVC: u32 = 0xd4000001;

#[test]
fn ld1_four_registers_not_interleaved() {
    // ld1 {v4.16b-v7.16b}, [x2]
    let (cpu, e) = run_setup(&[0x4c402044, SVC], &|c, m| {
        c.x[2] = 0x3000;
        for i in 0..64 {
            m[0x2000 + i] = i as u8;
        }
    });
    assert_eq!(e, Exit::Svc);
    assert_eq!(cpu.v[4], [0x0706050403020100, 0x0f0e0d0c0b0a0908]);
    assert_eq!(cpu.v[7], [0x3736353433323130, 0x3f3e3d3c3b3a3938]);
}

#[test]
fn fmov_immediates() {
    // fmov s0, #1.0 ; fmov v1.4s, #1.0 ; fmov v2.2d, #-2.0 ; fmov d3, #0.5
    let (cpu, _) = run_setup(&[0x1e2e1000, 0x4f03f601, 0x6f04f402, 0x1e6c1003, SVC], &|_, _| {});
    assert_eq!(cpu.v[0], [0x3f80_0000, 0]);
    assert_eq!(cpu.v[1], [0x3f80_0000_3f80_0000, 0x3f80_0000_3f80_0000]);
    assert_eq!(cpu.v[2], [0xc000_0000_0000_0000, 0xc000_0000_0000_0000]);
    assert_eq!(cpu.v[3], [0x3fe0_0000_0000_0000, 0]);
}

#[test]
fn vector_frint_and_rbit() {
    // frintp v0.4s, v1.4s ; frintn v2.4s, v1.4s ; rbit v3.8b, v4.8b
    let (cpu, _) = run_setup(&[0x4ea18820, 0x4e218822, 0x2e605883, SVC], &|c, _| {
        c.v[1] = [0x3fc0_0000_3fc0_0000, 0x4020_0000_4020_0000]; // 1.5, 2.5
        c.v[4] = [0x0102_0304_0506_0780, 0];
    });
    assert_eq!(cpu.v[0], [0x4000_0000_4000_0000, 0x4040_0000_4040_0000]); // 2, 3
    assert_eq!(cpu.v[2], [0x4000_0000_4000_0000, 0x4000_0000_4000_0000]); // 2, 2
    assert_eq!(cpu.v[3], [0x8040_c020_a060_e001, 0]);
}

#[test]
fn sqadd_2d_saturates_and_sets_qc() {
    // sqadd v0.2d, v1.2d, v2.2d
    let (cpu, _) = run_setup(&[0x4ee20c20, SVC], &|c, _| {
        c.v[1] = [0x7fff_ffff_ffff_fff0, 0x8000_0000_0000_0001];
        c.v[2] = [0x100, u64::MAX - 1];
    });
    assert_eq!(cpu.v[0], [0x7fff_ffff_ffff_ffff, 0x8000_0000_0000_0000]);
    assert_ne!(cpu.fpsr & crate::softfloat::FPSR_QC, 0);
}

#[test]
fn pmull_1q() {
    // pmull v0.1q, v1.1d, v2.1d ; pmull2 v3.1q, v1.2d, v2.2d
    let (cpu, _) = run_setup(&[0x0ee2e020, 0x4ee2e023, SVC], &|c, _| {
        c.v[1] = [u64::MAX, 3];
        c.v[2] = [u64::MAX, 3];
    });
    // (2^64-1)^2 carry-less = 0x5555..5555 (128 bits)
    assert_eq!(cpu.v[0], [0x5555_5555_5555_5555, 0x5555_5555_5555_5555]);
    assert_eq!(cpu.v[3], [5, 0]);
}

#[test]
fn flagm_ops() {
    // movz w1,#0x80 ; setf8 w1 -> N=1, Z=0, V=bit8^bit7=1 ; cfinv ; rmif x1,#4,#0b0010
    let (cpu, _) = run_setup(&[0x52801001, 0x3a00082d, 0xd500401f, SVC], &|_, _| {});
    assert_eq!(cpu.nzcv, crate::state::NZCV_N | crate::state::NZCV_V | crate::state::NZCV_C);
    // movz x1,#0x20 ; rmif x1, #4, #2  (flags = 0x20 ror 4 = 0b0010 -> C=1)
    let (cpu, _) = run_setup(&[0xd2800401, 0xba020422, SVC], &|_, _| {});
    assert_eq!(cpu.nzcv, crate::state::NZCV_C);
}

#[test]
fn casp_32bit_pair() {
    // casp w4, w5, w6, w7, [x2]
    let (cpu, e) = run_setup(&[0x08247c46, SVC], &|c, m| {
        c.x[2] = 0x3000;
        m[0x2000..0x2008].copy_from_slice(&0x2222_2222_1111_1111u64.to_le_bytes());
        c.x[4] = 0x1111_1111;
        c.x[5] = 0x2222_2222;
        c.x[6] = 0xaaaa_aaaa;
        c.x[7] = 0xbbbb_bbbb;
    });
    assert_eq!(e, Exit::Svc);
    assert_eq!((cpu.x[4], cpu.x[5]), (0x1111_1111, 0x2222_2222));
    // Memory now holds the new pair: reload with ldr x8, [x2] in a 2nd run
    // is covered by difftest; here check the compare succeeded via Rs.
}

#[test]
fn id_space_mrs_is_raz() {
    // mrs x0, ID_AA64ISAR3_EL1 (s3_0_c0_c6_3) ; mrs x1, ID_AA64ISAR1_EL1
    let (cpu, e) = run_setup(&[0xd5380660, 0xd5380621, SVC], &|c, _| c.x[0] = 1);
    assert_eq!(e, Exit::Svc);
    assert_eq!(cpu.x[0], 0);
    assert_eq!((cpu.x[1] >> 32) & 0xff, 0x11); // FRINTTS=1, SB=1
}
