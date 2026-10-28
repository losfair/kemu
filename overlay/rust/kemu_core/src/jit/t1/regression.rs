// SPDX-License-Identifier: GPL-2.0
//! Regression tests for translator/interpreter fixes (kemu audit 2026-10).
//! std-only (needs a Vec-backed environment and boxing).
#![cfg(all(test, feature = "std"))]

extern crate std;
use std::{boxed::Box, vec, vec::Vec};

use crate::env::{Access, Env, Fault};
use crate::jit::stubs::{gen_stubs, ExitMode, StubAddrs};
use crate::jit::t1;

const PC0: u64 = 0x40_0000;

fn stub_addrs() -> StubAddrs {
    let mut page = vec![0u8; 4096];
    let so = gen_stubs(&mut page, ExitMode::Syscall, 0x7f00_0000_0000, 0xfff8).unwrap();
    so.addrs(0x7e00_0000_0000)
}

/// Environment whose word at PC0+4 flips from `first` to `second` after the
/// first fetch (a second thread rewriting guest text mid-translation).
struct Racy {
    words: Vec<u32>,
    flip_at: u64,
    first: u32,
    second: u32,
    seen: bool,
}

impl Env for Racy {
    fn fetch(&mut self, pc: u64) -> Result<u32, Fault> {
        if pc == self.flip_at {
            let w = if self.seen { self.second } else { self.first };
            self.seen = true;
            return Ok(w);
        }
        let i = pc.wrapping_sub(PC0) / 4;
        self.words
            .get(i as usize)
            .copied()
            .ok_or(Fault { addr: pc, access: Access::Exec, align: false })
    }
    fn read_u8(&mut self, a: u64) -> Result<u8, Fault> { Err(f(a)) }
    fn read_u16(&mut self, a: u64) -> Result<u16, Fault> { Err(f(a)) }
    fn read_u32(&mut self, a: u64) -> Result<u32, Fault> { Err(f(a)) }
    fn read_u64(&mut self, a: u64) -> Result<u64, Fault> { Err(f(a)) }
    fn write_u8(&mut self, a: u64, _: u8) -> Result<(), Fault> { Err(f(a)) }
    fn write_u16(&mut self, a: u64, _: u16) -> Result<(), Fault> { Err(f(a)) }
    fn write_u32(&mut self, a: u64, _: u32) -> Result<(), Fault> { Err(f(a)) }
    fn write_u64(&mut self, a: u64, _: u64) -> Result<(), Fault> { Err(f(a)) }
    fn cmpxchg(&mut self, a: u64, _: u32, _: [u64; 2], _: [u64; 2]) -> Result<[u64; 2], Fault> { Err(f(a)) }
    fn cntvct(&mut self) -> u64 { 0 }
    fn cntfrq(&mut self) -> u64 { 1 }
    fn random(&mut self) -> Option<u64> { None }
}

fn f(a: u64) -> Fault {
    Fault { addr: a, access: Access::Read, align: false }
}

fn xlate(env: &mut Racy) -> (Vec<u8>, Vec<u8>) {
    xlate_vectors(env, true)
}

fn xlate_vectors(env: &mut Racy, vector_cache: bool) -> (Vec<u8>, Vec<u8>) {
    let cfg = t1::Cfg { stubs: stub_addrs(), code_uaddr: 0x7e00_0010_0000, reloc: true, tbi: false, vector_cache, crypto: t1::HostCrypto::default() };
    let mut s = Box::new(t1::Scratch::new());
    let mut out = vec![0u8; 1 << 16];
    let r = t1::translate(env, PC0, &mut out, &cfg, &mut s).unwrap();
    out.truncate(r.size);
    let mut blob = vec![0u8; s.xcache_blob_size().unwrap()];
    s.xcache_blob(PC0, 1 << 20, &mut blob).unwrap();
    (out, blob)
}

/// #2: a relocatable translation must read each guest word at most once, so
/// its flag look-ahead can't be steered by a racing writer into producing a
/// block whose dependency records (what the shared cache re-validates) don't
/// match the code that was emitted.
#[test]
fn xcache_fetch_is_memoized_against_a_racing_writer() {
    // subs x0,x0,#1 ; b.eq +0x100 (reads NZCV) ; b -4 (back edge).
    // The look-ahead into the b.eq target re-reads PC0+4.
    let words = vec![0xf100_0400, 0x5400_0800, 0x17ff_ffff];
    let base = Racy { words: words.clone(), flip_at: PC0 + 4, first: 0x5400_0800, second: 0x5400_0800, seen: false };
    let racy = Racy { words, flip_at: PC0 + 4, first: 0x5400_0800, second: 0xf100_003f /* cmp x1,#0 */, seen: false };
    let (hc, hb) = xlate(&mut { base });
    let (rc, rb) = xlate(&mut { racy });
    assert_eq!(hb, rb, "dependency records diverge under a racing writer");
    assert_eq!(hc, rc, "emitted code diverges under a racing writer");
}

/// Once MSR changes live MXCSR, a signal must observe the complete guest
/// register write, even before the following state-page store executes.
#[test]
fn fp_sysreg_recovery_commits_the_loaded_control_or_status() {
    use crate::jit::{meta, regmap};
    use crate::state::CpuState;
    for (word, value, status) in [(0xd51b4400, 1 << 22, false), (0xd51b4420, 0x0800_0080, true)] {
        let mut env = Racy {
            words: vec![word, 0xd65f03c0], flip_at: 0, first: 0, second: 0, seen: false,
        };
        let (code, _) = xlate(&mut env);
        let hdr = meta::Header::read(&code).unwrap();
        let m = &code[hdr.meta_off as usize..(hdr.meta_off + hdr.meta_len) as usize];
        let (np, _) = meta::meta_counts(m).unwrap();
        let p = (0..np).map(|i| meta::read_point(m, i).unwrap())
            .find(|p| p.kind == meta::kind::ROLL_FP).unwrap();
        let mut host = meta::HostRegs::default();
        host.gpr[0] = value as u64;
        let mut state = CpuState::new();
        state.fpsr = 0x1f;
        assert!(meta::recover(&code, p.off, &host, &mut state));
        assert_eq!(state.pc, PC0 + 4);
        if status {
            assert_eq!(state.fpsr, value);
            assert_eq!(regmap::fpsr_merge(state.fpsr, regmap::mxcsr_from(0, value)), value);
        } else {
            assert_eq!(state.fpcr, value);
            assert_eq!(state.fpsr, 0x1f);
        }
    }
}

/// UQSUB commits an aliased vector before FPSR. Recovery must roll QC
/// forward, keep live FP exceptions, and never re-execute the subtraction.
#[test]
fn saturating_vector_recovery_commits_qc_with_the_result() {
    use crate::jit::{meta, regmap};
    use crate::state::CpuState;
    for cache in [false, true] {
        let mut env = Racy {
            // Three uses ensure V0 is cached when the cache is enabled.
            words: vec![0x6e612c00, 0x6e612c00, 0x6e612c00, 0xd65f03c0],
            flip_at: 0, first: 0, second: 0, seen: false,
        };
        let (code, _) = xlate_vectors(&mut env, cache);
        let hdr = meta::Header::read(&code).unwrap();
        let m = &code[hdr.meta_off as usize..(hdr.meta_off + hdr.meta_len) as usize];
        let (np, _) = meta::meta_counts(m).unwrap();
        let p = (0..np).map(|i| meta::read_point(m, i).unwrap())
            .find(|p| p.kind == meta::kind::ROLL_FP).unwrap();
        let result = [0x0000_0123_0000_0456; 2];
        for qc in [0, 1 << 27] {
            let mut host = meta::HostRegs::default();
            host.gpr[p.b as usize] = (qc | 0x10) as u64;
            let mut state = CpuState::new();
            state.fpsr = 0x10;
            state.flags_x86 = regmap::image_from_nzcv(0xa000_0000);
            let slot = m[8..16].iter().position(|&g| g == 0);
            assert_eq!(slot.is_some(), cache);
            if let Some(slot) = slot { host.xmm[slot] = result; }
            else { state.v[0] = result; }
            assert!(meta::recover(&code, p.off, &host, &mut state));
            assert_eq!(state.pc, PC0 + 4);
            assert_eq!(state.v[0], result);
            assert_eq!(state.fpsr, qc | 0x10);
            assert_eq!(state.nzcv, 0xa000_0000);
            // A pending live divide-by-zero exception is merged afterward.
            assert_eq!(regmap::fpsr_merge(state.fpsr, 4), qc | 0x12);
        }
    }
}
