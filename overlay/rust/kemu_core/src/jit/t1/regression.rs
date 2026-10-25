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
    let cfg = t1::Cfg { stubs: stub_addrs(), code_uaddr: 0x7e00_0010_0000, reloc: true, tbi: false, vector_cache: true, crypto: t1::HostCrypto::default() };
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
