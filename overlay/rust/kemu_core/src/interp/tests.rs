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
fn tagged_pointer_tbi() {
    // movz x1,#0x2000; movk x1,#0x5a00,lsl #48 (tag 0x5a); movz x0,#0xabcd;
    // str x0,[x1]; movz x5,#0x2000; ldr x2,[x5]; svc
    let (cpu, e) = run_code(&[0xd2840001, 0xf2eb4001, 0xd29579a0, 0xf9000020, 0xd2840005, 0xf94000a2, 0xd4000001]);
    assert_eq!(e, Exit::Svc);
    assert_eq!(cpu.x[2], 0xabcd);
    // A fault through a tagged pointer reports the untagged address.
    // movz x1,#0xfff0,lsl #16 (0xfff00000); movk x1,#0x3300,lsl #48; ldr x0,[x1]
    let (_, e) = run_code(&[0xd2bffe01, 0xf2e66001, 0xf9400020]);
    match e {
        Exit::Fault(f) => assert_eq!(f.addr, 0xfff0_0000),
        e => panic!("expected fault, got {e:?}"),
    }
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

/// Shared translation cache: a relocatable block validates and relocates
/// against the same code mapped elsewhere, and any change to a word it
/// depends on (including look-ahead into exit targets) is detected.
#[test]
fn xcache_validate_and_relocate() {
    use crate::jit::{stubs, t1, xcache};
    let code: [u32; 10] = [
        0x4ee08400, // add v0.2d, v0.2d, v0.2d (cached vector)
        0x4ee08400,
        0x90000000, // adrp x0, 0
        0xf9400001, // ldr  x1, [x0]
        0xeb02003f, // cmp  x1, x2
        0x54000041, // b.ne +8
        0x94000004, // bl   +16
        0xf1000421, // subs x1, x1, #1
        0xd65f03c0, // ret
        0xd503201f, // nop
    ];
    let mk = |base: u64, patch: Option<(usize, u32)>| {
        let mut mem = std::vec![0u8; 0x2000];
        for (i, w) in code.iter().enumerate() {
            let w = match patch { Some((j, v)) if j == i => v, _ => *w };
            mem[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        TestEnv { mem, base }
    };
    let mut page = std::vec![0u8; 4096];
    let so = stubs::gen_stubs(&mut page, stubs::ExitMode::Syscall, 0x7000_1000_0000, 0xfff8).expect("stubs");
    let cfg = t1::Cfg { stubs: so.addrs(0x7000_0000_0000), code_uaddr: 0x7000_0000_0000 + (1 << 20), reloc: true, tbi: false, vector_cache: true, crypto: t1::HostCrypto::default() };
    let mut s = std::boxed::Box::new(t1::Scratch::new());
    let mut out = std::vec![0u8; 8192];
    let mut env = mk(0x40_0000, None);
    let r = t1::translate(&mut env, 0x40_0000, &mut out, &cfg, &mut s).expect("translate");
    let mut blob = std::vec![0u8; 4096];
    let blen = s.xcache_blob(0x40_0000, 1 << 20, &mut blob).expect("cacheable");
    let blob = &blob[..blen];

    // Same code 1 GiB higher: valid, and relocation equals a fresh translation.
    let base2 = 0x4040_0000;
    let mut env2 = mk(base2, None);
    assert!(xcache::validate(&mut env2, blob, base2));
    let mut copy = out[..r.size].to_vec();
    assert!(xcache::apply(blob, &mut copy, base2, 3 << 20));
    let cfg2 = t1::Cfg { code_uaddr: 0x7000_0000_0000 + (3 << 20), ..cfg };
    let mut out2 = std::vec![0u8; 8192];
    let r2 = t1::translate(&mut env2, base2, &mut out2, &cfg2, &mut s).expect("translate 2");
    assert_eq!(copy, out2[..r2.size].to_vec());

    // Changed instruction inside the block, or at an exit target the
    // flags look-ahead read: rejected. Unaligned delta: rejected.
    assert!(!xcache::validate(&mut mk(base2, Some((3, 0xf9400401))), blob, base2));
    assert!(!xcache::validate(&mut mk(base2, Some((7, 0x8b020021))), blob, base2));
    assert!(!xcache::validate(&mut mk(base2 + 4, None), blob, base2 + 4));
}

/// A thread interrupted in an exit trampoline of a remapped block must be
/// recovered with the canonical register map: every path into the
/// trampolines has run the remap epilogue, even if the block's main code
/// ends in the remapped state (here: a self-loop back-edge).
#[test]
fn recover_in_exit_trampoline_of_remapped_block() {
    use crate::jit::{meta, regmap, stubs, t1};
    let code: [u32; 6] = [
        0x91000718, // add  x24, x24, #1
        0x91000718, // add  x24, x24, #1
        0x91000718, // add  x24, x24, #1
        0xeb09031f, // cmp  x24, x9
        0x54000800, // b.eq +0x100 (exit through a trampoline)
        0x17fffffb, // b    pc0 (back-edge: the main code ends remapped)
    ];
    let mut mem = std::vec![0u8; 0x2000];
    for (i, w) in code.iter().enumerate() {
        mem[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    let mut env = TestEnv { mem, base: 0x40_0000 };
    let mut page = std::vec![0u8; 4096];
    let so = stubs::gen_stubs(&mut page, stubs::ExitMode::Syscall, 0x7000_1000_0000, 0xfff8).expect("stubs");
    let cfg = t1::Cfg { stubs: so.addrs(0x7000_0000_0000), code_uaddr: 0x7000_0000_0000 + (1 << 20), reloc: false, tbi: false, vector_cache: true, crypto: t1::HostCrypto::default() };
    let mut s = std::boxed::Box::new(t1::Scratch::new());
    let mut out = std::vec![0u8; 8192];
    let r = t1::translate(&mut env, 0x40_0000, &mut out, &cfg, &mut s).expect("translate");
    let blk = &out[..r.size];

    // Trampolines: "lea rdx, [rip + site]" right before the jump to the chain stub.
    let mut tramps = std::vec::Vec::new();
    for o in 0..blk.len().saturating_sub(3) {
        if blk[o..o + 3] == [0x48, 0x8d, 0x15] {
            tramps.push(o as u32);
        }
    }
    assert!(!tramps.is_empty(), "no exit trampolines found");

    let mut h = meta::HostRegs { gpr: [0; 16], rflags: 0x202, ..Default::default() };
    for (i, g) in h.gpr.iter_mut().enumerate() {
        *g = 0x1000 + i as u64;
    }
    for off in tramps {
        let mut st = CpuState::new();
        for n in 0..31 {
            st.set_xr(n, 0x9000 + n as u64);
        }
        st.sp = 0x9999;
        assert!(meta::recover(blk, off, &h, &mut st), "recover at {off:#x}");
        // Canonical: pinned registers from their host registers, the rest
        // from the state page.
        for (g, hr) in regmap::PINNED.iter() {
            let want = h.gpr[(*hr & 15) as usize];
            let got = if *g == regmap::GUEST_SP { st.sp } else { st.xr(*g) };
            assert_eq!(got, want, "pinned guest reg {g} at trampoline offset {off:#x}");
        }
        assert_eq!(st.xr(24), 0x9000 + 24, "x24 at trampoline offset {off:#x}");
        assert_eq!(st.xr(9), 0x9000 + 9, "x9 at trampoline offset {off:#x}");
    }
}

/// Cache fills, spills, helper returns and side exits must agree about
/// which copy of V0 is authoritative, including coincident metadata points.
#[test]
fn recover_cached_vectors() {
    use crate::jit::{meta, stubs, t1};
    let code: [u32; 7] = [
        0x4ee08400, // add v0.2d, v0.2d, v0.2d
        0x4ee08400,
        0x4ee08400,
        0x54000800, // b.eq +0x100: conditional side exit
        0x4ee00c00, // sqadd v0.2d, v0.2d, v0.2d: interpreter helper
        0x4ee08400,
        0x17fffffa, // b pc0: retain the cache on the back-edge
    ];
    let mut mem = std::vec![0u8; 0x2000];
    for (i, w) in code.iter().enumerate() {
        mem[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    let mut env = TestEnv { mem, base: 0x40_0000 };
    let mut stubs = std::vec![0u8; 4096];
    let so = stubs::gen_stubs(&mut stubs, stubs::ExitMode::Syscall, 0x7000_1000_0000, 0xfff8).unwrap();
    let mut cfg = t1::Cfg { stubs: so.addrs(0x7000_0000_0000), code_uaddr: 0x7000_0010_0000,
        reloc: false, tbi: false, vector_cache: true, crypto: t1::HostCrypto::default() };
    let mut scratch = std::boxed::Box::new(t1::Scratch::new());
    let mut out = std::vec![0; 16384];
    for enabled in [true, false] {
        cfg.vector_cache = enabled;
        let r = t1::translate(&mut env, 0x40_0000, &mut out, &cfg, &mut scratch).unwrap();
        let blk = &out[..r.size];
        let hdr = meta::Header::read(blk).unwrap();
        let m = &blk[hdr.meta_off as usize..][..hdr.meta_len as usize];
        assert_eq!(&m[8..16], if enabled { &[0, 255, 255, 255, 255, 255, 255, 255] } else { &[255; 8] });
        let mut host = meta::HostRegs::default();
        host.xmm = [[0xabc, 0xdef]; 8];
        let check = |off, live| {
            let mut st = CpuState::new();
            st.v = [[0x123, 0x456]; 32];
            assert!(meta::recover(blk, off, &host, &mut st));
            assert_eq!(st.v[0], if live { host.xmm[0] } else { [0x123, 0x456] }, "at {off:#x}");
            assert!(st.v[1..].iter().all(|v| *v == [0x123, 0x456]));
        };
        check(hdr.main_off, false); // fill has not run yet
        let (np, _) = meta::meta_counts(m).unwrap();
        let mut bodies = 0;
        let mut helpers = 0;
        let mut exits = 0;
        for i in 0..np {
            let p = meta::read_point(m, i).unwrap();
            match p.kind {
                meta::kind::INSN if p.idx == 1 || p.idx == 5 => {
                    check(p.off, enabled); // after a result commit / helper refill
                    bodies += 1;
                }
                meta::kind::DONE if p.idx == 4 => {
                    check(p.off, false); // helper has returned; refill hasn't run
                    helpers += 1;
                }
                meta::kind::EXIT => {
                    check(p.off, false); // trampoline after a live self-loop
                    exits += 1;
                }
                _ => {}
            }
        }
        assert!(bodies >= 2 && (!enabled || helpers > 0) && exits > 0, "enabled={enabled} bodies={bodies} helpers={helpers} exits={exits}");
    }
}

/// Env whose cmpxchg never succeeds: models an atomic word another CPU keeps
/// changing between our load and our store.
struct ContendedEnv {
    mem: std::vec::Vec<u8>,
    base: u64,
    attempts: u32,
}
impl Env for ContendedEnv {
    fn fetch(&mut self, pc: u64) -> Result<u32, Fault> { self.read_u32(pc) }
    fn read_u8(&mut self, a: u64) -> Result<u8, Fault> {
        let i = (a - self.base) as usize;
        self.mem.get(i).copied().ok_or(Fault { addr: a, access: crate::env::Access::Read, align: false })
    }
    fn read_u16(&mut self, a: u64) -> Result<u16, Fault> { Ok(u16::from_le_bytes([self.read_u8(a)?, self.read_u8(a+1)?])) }
    fn read_u32(&mut self, a: u64) -> Result<u32, Fault> { let mut b=[0u8;4]; for (i,x) in b.iter_mut().enumerate(){*x=self.read_u8(a+i as u64)?;} Ok(u32::from_le_bytes(b)) }
    fn read_u64(&mut self, a: u64) -> Result<u64, Fault> { let mut b=[0u8;8]; for (i,x) in b.iter_mut().enumerate(){*x=self.read_u8(a+i as u64)?;} Ok(u64::from_le_bytes(b)) }
    fn write_u8(&mut self, a: u64, v: u8) -> Result<(), Fault> { let i=(a-self.base) as usize; self.mem[i]=v; Ok(()) }
    fn write_u16(&mut self, a: u64, v: u16) -> Result<(), Fault> { for (i,b) in v.to_le_bytes().iter().enumerate(){self.write_u8(a+i as u64,*b)?;} Ok(()) }
    fn write_u32(&mut self, a: u64, v: u32) -> Result<(), Fault> { for (i,b) in v.to_le_bytes().iter().enumerate(){self.write_u8(a+i as u64,*b)?;} Ok(()) }
    fn write_u64(&mut self, a: u64, v: u64) -> Result<(), Fault> { for (i,b) in v.to_le_bytes().iter().enumerate(){self.write_u8(a+i as u64,*b)?;} Ok(()) }
    fn cmpxchg(&mut self, a: u64, size: u32, _e: [u64;2], _n: [u64;2]) -> Result<[u64;2], Fault> {
        // Always report an "old" value that differs from what was expected,
        // so the RMW never commits.
        self.attempts += 1;
        let cur = match size { 1 => self.read_u8(a)? as u64, 2 => self.read_u16(a)? as u64, 4 => self.read_u32(a)? as u64, _ => self.read_u64(a)? };
        Ok([cur ^ 1, 0])
    }
    fn cntvct(&mut self) -> u64 { 0 }
    fn cntfrq(&mut self) -> u64 { 1 }
    fn random(&mut self) -> Option<u64> { None }
}

/// #12: a perpetually-contended LSE atomic must not spin forever in the
/// kernel. The interpreter gives up after a bounded number of tries,
/// returning Exit::Budget with pc left on the instruction so it restarts.
#[test]
fn contended_atomic_is_bounded() {
    // ldadd x0, x1, [x2]  (0xf8200041 decodes to Insn::Atomic Add)
    let base = 0x2000;
    let mut mem = std::vec![0u8; 0x1000];
    mem[..4].copy_from_slice(&0xf820_0041u32.to_le_bytes());
    let mut env = ContendedEnv { mem, base, attempts: 0 };
    let mut cpu = CpuState::new();
    cpu.pc = base;
    cpu.x[0] = 1;              // addend
    cpu.x[2] = base + 0x100;   // aligned data address
    let (e, n) = run(&mut cpu, &mut env, 1000);
    assert_eq!(e, Exit::Budget, "contended atomic should yield, not loop");
    assert_eq!(cpu.pc, base, "pc must stay on the atomic for restart");
    assert_eq!(n, 0, "the atomic did not retire");
    assert!(env.attempts <= super::mem::ATOMIC_RETRIES, "retries not bounded: {}", env.attempts);
}
