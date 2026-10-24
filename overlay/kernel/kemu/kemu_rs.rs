// SPDX-License-Identifier: GPL-2.0
//! kemu: kernel-side Rust glue.
//!
//! Mounts the `kemu_core` sources (which are also built standalone by
//! cargo) as a module tree and exports the C entry points used by the
//! kemu C code. All guest-controlled data is parsed by `kemu_core`; the
//! `unsafe` here is limited to the FFI boundary.

// kemu_core is also a standalone (cargo) crate with its own conventions;
// relax the kernel's documentation lints for it.
#![allow(missing_docs)]

use core::ffi::c_int;

// The crate root of kemu_core, mounted as a module. Its crate-level
// attributes (`#![no_std]`) are redundant here.
#[allow(unused_attributes)]
#[path = "../../rust/kemu_core/src/lib.rs"]
mod kemu_core;

// `kemu_core` modules refer to each other as `crate::<module>`.
pub use kemu_core::*;

use env::{Access, Env, Fault};
use state::CpuState;

const EFAULT: c_int = 14;
const EACCES: c_int = 13;
const EINVAL: c_int = 22;

extern "C" {
    fn kemu_c_fetch(pc: u64, out: *mut u32) -> c_int;
    fn kemu_c_read(addr: u64, buf: *mut u8, len: usize) -> c_int;
    fn kemu_c_write(addr: u64, buf: *const u8, len: usize) -> c_int;
    fn kemu_c_cmpxchg(addr: u64, size: u32, exp: *const u64, new: *const u64, old: *mut u64)
        -> c_int;
    fn kemu_c_cntvct() -> u64;
    fn kemu_c_cntfrq() -> u64;
    fn kemu_c_random(out: *mut u64) -> bool;
}

/// Guest memory accessed through the current task's user address space.
struct KEnv;

impl KEnv {
    fn read<const N: usize>(&mut self, addr: u64) -> Result<[u8; N], Fault> {
        let mut b = [0u8; N];
        // SAFETY: `b` is a valid writable buffer of N bytes; the C helper
        // only accesses user memory through uaccess primitives.
        let r = unsafe { kemu_c_read(addr, b.as_mut_ptr(), N) };
        if r == 0 {
            Ok(b)
        } else {
            Err(Fault { addr, access: Access::Read, align: false })
        }
    }

    fn write(&mut self, addr: u64, b: &[u8]) -> Result<(), Fault> {
        // SAFETY: `b` is a valid readable buffer; see `read`.
        let r = unsafe { kemu_c_write(addr, b.as_ptr(), b.len()) };
        if r == 0 {
            Ok(())
        } else {
            Err(Fault { addr, access: Access::Write, align: false })
        }
    }
}

impl Env for KEnv {
    fn fetch(&mut self, pc: u64) -> Result<u32, Fault> {
        let mut w = 0u32;
        // SAFETY: `w` is a valid u32 out-parameter.
        let r = unsafe { kemu_c_fetch(pc, &mut w) };
        if r == 0 {
            Ok(w)
        } else {
            Err(Fault { addr: pc, access: Access::Exec, align: false })
        }
    }
    fn read_u8(&mut self, a: u64) -> Result<u8, Fault> {
        Ok(u8::from_le_bytes(self.read::<1>(a)?))
    }
    fn read_u16(&mut self, a: u64) -> Result<u16, Fault> {
        Ok(u16::from_le_bytes(self.read::<2>(a)?))
    }
    fn read_u32(&mut self, a: u64) -> Result<u32, Fault> {
        Ok(u32::from_le_bytes(self.read::<4>(a)?))
    }
    fn read_u64(&mut self, a: u64) -> Result<u64, Fault> {
        Ok(u64::from_le_bytes(self.read::<8>(a)?))
    }
    fn write_u8(&mut self, a: u64, v: u8) -> Result<(), Fault> {
        self.write(a, &v.to_le_bytes())
    }
    fn write_u16(&mut self, a: u64, v: u16) -> Result<(), Fault> {
        self.write(a, &v.to_le_bytes())
    }
    fn write_u32(&mut self, a: u64, v: u32) -> Result<(), Fault> {
        self.write(a, &v.to_le_bytes())
    }
    fn write_u64(&mut self, a: u64, v: u64) -> Result<(), Fault> {
        self.write(a, &v.to_le_bytes())
    }
    fn cmpxchg(
        &mut self,
        addr: u64,
        size: u32,
        expected: [u64; 2],
        new: [u64; 2],
    ) -> Result<[u64; 2], Fault> {
        let mut old = [0u64; 2];
        // SAFETY: all pointers reference valid local arrays of two u64.
        let r = unsafe {
            kemu_c_cmpxchg(addr, size, expected.as_ptr(), new.as_ptr(), old.as_mut_ptr())
        };
        match r {
            0 => Ok(old),
            r if r == EINVAL => Err(Fault { addr, access: Access::Write, align: true }),
            _ => Err(Fault { addr, access: Access::Write, align: false }),
        }
    }
    fn cntvct(&mut self) -> u64 {
        // SAFETY: plain C function without preconditions.
        unsafe { kemu_c_cntvct() }
    }
    fn cntfrq(&mut self) -> u64 {
        // SAFETY: plain C function without preconditions.
        unsafe { kemu_c_cntfrq() }
    }
    fn random(&mut self) -> Option<u64> {
        let mut v = 0u64;
        // SAFETY: `v` is a valid out-parameter.
        if unsafe { kemu_c_random(&mut v) } {
            Some(v)
        } else {
            None
        }
    }
}

/// Mirror of `struct kemu_rs_exit`.
#[repr(C)]
pub struct KemuExit {
    kind: u32,
    aux: u32,
    addr: u64,
    retired: u32,
    access: u32,
}

fn access_code(a: Access) -> u32 {
    match a {
        Access::Read => 0,
        Access::Write => 1,
        Access::Exec => 2,
    }
}

/// Interpret guest code from `cpu` (a kernel-private copy of the state).
///
/// # Safety
/// `cpu` and `exit` must be valid, exclusively owned pointers.
#[no_mangle]
pub unsafe extern "C" fn kemu_rs_interp(cpu: *mut CpuState, budget: u32, exit: *mut KemuExit) {
    // SAFETY: guaranteed by the caller.
    let cpu = unsafe { &mut *cpu };
    let mut env = KEnv;
    let (ex, retired) = interp::run(cpu, &mut env, budget);
    let mut out = KemuExit { kind: 0, aux: 0, addr: 0, retired, access: 0 };
    match ex {
        interp::Exit::Budget => out.kind = 0,
        interp::Exit::Svc => out.kind = 1,
        interp::Exit::Brk(imm) => {
            out.kind = 2;
            out.aux = imm as u32;
        }
        interp::Exit::Undefined(w) => {
            out.kind = 3;
            out.aux = w;
        }
        interp::Exit::Fault(f) => {
            out.kind = 4;
            out.addr = f.addr;
            out.aux = f.align as u32;
            out.access = access_code(f.access);
        }
        interp::Exit::IcInvalidate(va) => {
            out.kind = 5;
            out.addr = va;
        }
    }
    // SAFETY: guaranteed by the caller.
    unsafe { exit.write(out) };
}

#[no_mangle]
pub extern "C" fn kemu_rs_hwcap() -> u64 {
    sysregs::HWCAP
}

#[no_mangle]
pub extern "C" fn kemu_rs_hwcap2() -> u64 {
    sysregs::HWCAP2
}

/// # Safety
/// `buf` must point to `len` writable bytes, `cpu` to a valid state.
#[no_mangle]
pub unsafe extern "C" fn kemu_rs_build_ucontext(
    buf: *mut u8,
    len: usize,
    cpu: *const CpuState,
    sigmask: u64,
    ss_sp: u64,
    ss_flags: u32,
    ss_size: u64,
    fault_addr: u64,
    esr: u64,
) -> c_int {
    // SAFETY: guaranteed by the caller.
    let (buf, cpu) = unsafe { (core::slice::from_raw_parts_mut(buf, len), &*cpu) };
    let ss = sigframe::AltStack { sp: ss_sp, flags: ss_flags, size: ss_size };
    match sigframe::build(buf, cpu, sigmask, ss, fault_addr, esr) {
        Ok(()) => 0,
        Err(_) => -EFAULT,
    }
}

/// # Safety
/// `buf` must point to `len` readable bytes; `cpu` and `sigmask` must be
/// valid, exclusively owned pointers.
#[no_mangle]
pub unsafe extern "C" fn kemu_rs_restore_ucontext(
    buf: *const u8,
    len: usize,
    cpu: *mut CpuState,
    sigmask: *mut u64,
) -> c_int {
    // SAFETY: guaranteed by the caller.
    let (buf, cpu) = unsafe { (core::slice::from_raw_parts(buf, len), &mut *cpu) };
    match sigframe::restore(buf, cpu) {
        Ok(mask) => {
            // SAFETY: guaranteed by the caller.
            unsafe { sigmask.write(mask) };
            0
        }
        Err(_) => -EACCES,
    }
}

// ---- JIT ----

use jit::{meta, regmap, stubs, t1};

const ENOSPC: c_int = 28;

/// Mirror of `struct kemu_stubs` (offsets within the stub page).
#[repr(C)]
pub struct KemuStubs {
    pub dispatch: u32,
    pub dispatch_rax: u32,
    pub miss: u32,
    pub chain: u32,
    pub helper: u32,
    pub svc: u32,
    pub interp_svc: u32,
    pub end: u32,
    pub nranges: u32,
    pub ranges: [[u32; 3]; 16],
}

impl KemuStubs {
    fn addrs(&self, base: u64) -> stubs::StubAddrs {
        stubs::StubAddrs {
            dispatch_rax: base + self.dispatch_rax as u64,
            miss: base + self.miss as u64,
            chain: base + self.chain as u64,
            helper: base + self.helper as u64,
            svc: base + self.svc as u64,
        }
    }
}

/// Generate the stub page.
///
/// # Safety
/// `out` must point to `len` writable bytes and `info` to a `KemuStubs`.
#[no_mangle]
pub unsafe extern "C" fn kemu_rs_gen_stubs(
    out: *mut u8,
    len: usize,
    table_base: u64,
    mask8: u32,
    info: *mut KemuStubs,
) -> c_int {
    // SAFETY: guaranteed by the caller.
    let (out, info) = unsafe { (core::slice::from_raw_parts_mut(out, len), &mut *info) };
    let o = match stubs::gen_stubs(out, stubs::ExitMode::Syscall, table_base, mask8) {
        Some(o) => o,
        None => return -ENOSPC,
    };
    info.dispatch = o.dispatch;
    info.dispatch_rax = o.dispatch_rax;
    info.miss = o.miss;
    info.chain = o.chain;
    info.helper = o.helper;
    info.svc = o.svc;
    info.interp_svc = o.interp_svc;
    info.end = o.end;
    info.nranges = o.nranges as u32;
    for (d, s) in info.ranges.iter_mut().zip(o.ranges.iter()) {
        *d = [s.0, s.1, s.2 as u32];
    }
    0
}

#[no_mangle]
pub extern "C" fn kemu_rs_scratch_size() -> usize {
    core::mem::size_of::<t1::Scratch>()
}

/// Mirror of `struct kemu_trans`.
#[repr(C)]
pub struct KemuTrans {
    pub size: u64,
    pub check_off: u32,
    pub main_off: u32,
    pub ninsns: u32,
    pub fault_access: u32,
    pub fault_addr: u64,
}

/// Translate the guest block at `pc` into `out` (user address `code_uaddr`).
///
/// # Safety
/// `scratch` must point to `kemu_rs_scratch_size()` zero-initialized (or
/// previously used) bytes, suitably aligned; `out` to `len` writable bytes;
/// `info` and `res` to valid structures.
#[no_mangle]
pub unsafe extern "C" fn kemu_rs_translate(
    scratch: *mut u8,
    pc: u64,
    out: *mut u8,
    len: usize,
    code_uaddr: u64,
    stubs_base: u64,
    info: *const KemuStubs,
    res: *mut KemuTrans,
) -> c_int {
    // SAFETY: `Scratch` is repr(C) and made only of integers, so any
    // initialized bytes are a valid value; the rest is guaranteed by the
    // caller.
    let (s, out, info, res) = unsafe {
        (
            &mut *(scratch as *mut t1::Scratch),
            core::slice::from_raw_parts_mut(out, len),
            &*info,
            &mut *res,
        )
    };
    let cfg = t1::Cfg { stubs: info.addrs(stubs_base), code_uaddr };
    match t1::translate(&mut KEnv, pc, out, &cfg, s) {
        Ok(r) => {
            res.size = r.size as u64;
            res.check_off = r.check_off;
            res.main_off = r.main_off;
            res.ninsns = r.ninsns;
            0
        }
        Err(t1::TErr::NoSpace) => -ENOSPC,
        Err(t1::TErr::Fault(f)) => {
            res.fault_addr = f.addr;
            res.fault_access = access_code(f.access);
            -EFAULT
        }
    }
}

/// Mirror of `struct kemu_host_regs`.
#[repr(C)]
pub struct KemuHostRegs {
    pub gpr: [u64; 16],
    pub rflags: u64,
}

fn host_regs(h: &KemuHostRegs) -> meta::HostRegs {
    meta::HostRegs { gpr: h.gpr, rflags: h.rflags }
}

/// Rebuild the guest state for a host PC inside a translated block.
///
/// # Safety
/// `blk` must point to `len` readable bytes; `h` and `cpu` must be valid.
#[no_mangle]
pub unsafe extern "C" fn kemu_rs_recover(
    blk: *const u8,
    len: usize,
    host_off: u32,
    h: *const KemuHostRegs,
    cpu: *mut CpuState,
) -> bool {
    // SAFETY: guaranteed by the caller.
    let (blk, h, cpu) = unsafe { (core::slice::from_raw_parts(blk, len), &*h, &mut *cpu) };
    meta::recover(blk, host_off, &host_regs(h), cpu)
}

/// Copy pinned guest registers from host registers.
///
/// # Safety
/// `h` and `cpu` must be valid.
#[no_mangle]
pub unsafe extern "C" fn kemu_rs_pinned_from_host(h: *const KemuHostRegs, cpu: *mut CpuState) {
    // SAFETY: guaranteed by the caller.
    let (h, cpu) = unsafe { (&*h, &mut *cpu) };
    meta::pinned_from_host(cpu, &host_regs(h));
}

/// Validate a block header; returns its size (0 if invalid).
///
/// # Safety
/// `blk` must point to `len` readable bytes; out-params must be valid.
#[no_mangle]
pub unsafe extern "C" fn kemu_rs_block_info(
    blk: *const u8,
    len: usize,
    guest_pc: *mut u64,
    main_off: *mut u32,
) -> usize {
    // SAFETY: guaranteed by the caller.
    let blk = unsafe { core::slice::from_raw_parts(blk, len) };
    match meta::Header::read(blk) {
        Some(h) if h.size() <= len => {
            // SAFETY: guaranteed by the caller.
            unsafe {
                guest_pc.write(h.guest_pc);
                main_off.write(h.main_off);
            }
            h.size()
        }
        _ => 0,
    }
}

/// Is `site_off` a patchable exit of the block? Returns its target.
///
/// # Safety
/// `blk` must point to `len` readable bytes; `target` must be valid.
#[no_mangle]
pub unsafe extern "C" fn kemu_rs_find_exit(
    blk: *const u8,
    len: usize,
    site_off: u32,
    target: *mut u64,
) -> bool {
    // SAFETY: guaranteed by the caller.
    let blk = unsafe { core::slice::from_raw_parts(blk, len) };
    let h = match meta::Header::read(blk) {
        Some(h) => h,
        None => return false,
    };
    let m = match blk.get(h.meta_off as usize..(h.meta_off + h.meta_len) as usize) {
        Some(m) => m,
        None => return false,
    };
    match meta::find_exit_site(m, site_off) {
        Some(e) => {
            // SAFETY: guaranteed by the caller.
            unsafe { target.write(e.target) };
            true
        }
        None => false,
    }
}

#[no_mangle]
pub extern "C" fn kemu_rs_nzcv_from_image(img: u64) -> u64 {
    regmap::nzcv_from_image(img)
}

#[no_mangle]
pub extern "C" fn kemu_rs_image_from_nzcv(nzcv: u64) -> u64 {
    regmap::image_from_nzcv(nzcv)
}
