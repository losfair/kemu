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
