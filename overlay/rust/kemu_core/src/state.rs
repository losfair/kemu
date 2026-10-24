// SPDX-License-Identifier: GPL-2.0
//! Guest CPU state. Mirrors `include/linux/kemu_abi.h`.

/// Per-thread guest CPU state, stored at the start of the user-mapped state
/// page. All fields are plain integers: the page is guest-writable, so
/// every value must be treated as untrusted.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CpuState {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    /// NZCV in architectural position (bits 31:28).
    pub nzcv: u64,
    pub fpcr: u32,
    pub fpsr: u32,
    pub tpidr: u64,
    pub tpidrro: u64,
    /// Exclusive monitor: address (`u64::MAX` = open), size, observed value.
    pub excl_addr: u64,
    pub excl_size: u64,
    pub excl_val: [u64; 2],
    pub host_rsp: u64,
    pub host_rsp_top: u64,
    pub scratch: [u64; 8],
    pub exit_info: u64,
    pub flags_x86: u64,
    pub _pad0: [u64; 11],
    /// V0..V31, each as (low, high) 64-bit halves.
    pub v: [[u64; 2]; 32],
}

pub const STATE_SIZE: usize = 1024;

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(offset_of!(CpuState, x) == 0);
    assert!(offset_of!(CpuState, sp) == 248);
    assert!(offset_of!(CpuState, pc) == 256);
    assert!(offset_of!(CpuState, nzcv) == 264);
    assert!(offset_of!(CpuState, fpcr) == 272);
    assert!(offset_of!(CpuState, fpsr) == 276);
    assert!(offset_of!(CpuState, tpidr) == 280);
    assert!(offset_of!(CpuState, tpidrro) == 288);
    assert!(offset_of!(CpuState, excl_addr) == 296);
    assert!(offset_of!(CpuState, excl_size) == 304);
    assert!(offset_of!(CpuState, excl_val) == 312);
    assert!(offset_of!(CpuState, host_rsp) == 328);
    assert!(offset_of!(CpuState, host_rsp_top) == 336);
    assert!(offset_of!(CpuState, scratch) == 344);
    assert!(offset_of!(CpuState, exit_info) == 408);
    assert!(offset_of!(CpuState, flags_x86) == 416);
    assert!(offset_of!(CpuState, v) == 512);
    assert!(size_of::<CpuState>() == STATE_SIZE);
};

impl CpuState {
    pub const fn new() -> Self {
        CpuState {
            x: [0; 31],
            sp: 0,
            pc: 0,
            nzcv: 0,
            fpcr: 0,
            fpsr: 0,
            tpidr: 0,
            tpidrro: 0,
            excl_addr: u64::MAX,
            excl_size: 0,
            excl_val: [0; 2],
            host_rsp: 0,
            host_rsp_top: 0,
            scratch: [0; 8],
            exit_info: 0,
            flags_x86: 0,
            _pad0: [0; 11],
            v: [[0; 2]; 32],
        }
    }

    /// Read X[n] with XZR semantics for n == 31.
    #[inline]
    pub fn xr(&self, n: u32) -> u64 {
        match self.x.get(n as usize) {
            Some(v) => *v,
            None => 0,
        }
    }

    /// Read X[n] with SP semantics for n == 31.
    #[inline]
    pub fn xsp(&self, n: u32) -> u64 {
        match self.x.get(n as usize) {
            Some(v) => *v,
            None => self.sp,
        }
    }

    /// Write X[n]; writes to n == 31 (XZR) are discarded.
    #[inline]
    pub fn set_xr(&mut self, n: u32, val: u64) {
        if let Some(r) = self.x.get_mut(n as usize) {
            *r = val;
        }
    }

    /// Write X[n] with SP semantics for n == 31.
    #[inline]
    pub fn set_xsp(&mut self, n: u32, val: u64) {
        match self.x.get_mut(n as usize) {
            Some(r) => *r = val,
            None => self.sp = val,
        }
    }

    #[inline]
    pub fn vreg(&self, n: u32) -> [u64; 2] {
        self.v[(n & 31) as usize]
    }

    #[inline]
    pub fn set_vreg(&mut self, n: u32, val: [u64; 2]) {
        self.v[(n & 31) as usize] = val;
    }
}

impl Default for CpuState {
    fn default() -> Self {
        Self::new()
    }
}

pub const NZCV_N: u64 = 1 << 31;
pub const NZCV_Z: u64 = 1 << 30;
pub const NZCV_C: u64 = 1 << 29;
pub const NZCV_V: u64 = 1 << 28;
