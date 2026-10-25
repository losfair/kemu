// SPDX-License-Identifier: GPL-2.0
//! The interface between the core and its host (kernel or test harness).

/// Kind of memory access that faulted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    Exec,
}

/// A guest memory fault. `addr` is the faulting guest virtual address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault {
    pub addr: u64,
    pub access: Access,
    /// True for alignment faults (SIGBUS/BUS_ADRALN), false for
    /// translation/permission faults (SIGSEGV).
    pub align: bool,
}

/// Host services needed to execute or translate guest code.
///
/// Memory is little-endian guest memory. Implementations must never panic;
/// any inaccessible address returns `Err(Fault)`.
pub trait Env {
    /// Fetch one instruction word from an executable guest mapping.
    fn fetch(&mut self, pc: u64) -> Result<u32, Fault>;

    fn read_u8(&mut self, addr: u64) -> Result<u8, Fault>;
    fn read_u16(&mut self, addr: u64) -> Result<u16, Fault>;
    fn read_u32(&mut self, addr: u64) -> Result<u32, Fault>;
    fn read_u64(&mut self, addr: u64) -> Result<u64, Fault>;
    fn write_u8(&mut self, addr: u64, val: u8) -> Result<(), Fault>;
    fn write_u16(&mut self, addr: u64, val: u16) -> Result<(), Fault>;
    fn write_u32(&mut self, addr: u64, val: u32) -> Result<(), Fault>;
    fn write_u64(&mut self, addr: u64, val: u64) -> Result<(), Fault>;

    /// Atomic compare-and-exchange of `size` bytes (1, 2, 4, 8 or 16).
    /// Values are zero-extended into `[lo, hi]`. Returns the old value;
    /// the exchange happened iff the old value equals `expected`.
    fn cmpxchg(
        &mut self,
        addr: u64,
        size: u32,
        expected: [u64; 2],
        new: [u64; 2],
    ) -> Result<[u64; 2], Fault>;

    /// Virtual counter (CNTVCT_EL0) and its frequency (CNTFRQ_EL0).
    fn cntvct(&mut self) -> u64;
    fn cntfrq(&mut self) -> u64;

    /// Hardware random number for RNDR/RNDRRS; `None` on failure.
    fn random(&mut self) -> Option<u64>;
}

/// Top-byte-ignore for EL0 data addresses, as Linux configures arm64
/// (TCR_EL1.TBI0): bits 63:56 are replaced by bit 55. Linux also reports
/// fault addresses without the tag (unless SA_EXPOSE_TAGBITS).
#[inline]
pub const fn untag(addr: u64) -> u64 {
    ((addr << 8) as i64 >> 8) as u64
}

/// `Env` adapter applying [`untag`] to every data access (not to fetch).
pub struct Tbi<'a, E: Env>(pub &'a mut E);

impl<E: Env> Env for Tbi<'_, E> {
    fn fetch(&mut self, pc: u64) -> Result<u32, Fault> {
        self.0.fetch(pc)
    }
    fn read_u8(&mut self, addr: u64) -> Result<u8, Fault> {
        self.0.read_u8(untag(addr))
    }
    fn read_u16(&mut self, addr: u64) -> Result<u16, Fault> {
        self.0.read_u16(untag(addr))
    }
    fn read_u32(&mut self, addr: u64) -> Result<u32, Fault> {
        self.0.read_u32(untag(addr))
    }
    fn read_u64(&mut self, addr: u64) -> Result<u64, Fault> {
        self.0.read_u64(untag(addr))
    }
    fn write_u8(&mut self, addr: u64, val: u8) -> Result<(), Fault> {
        self.0.write_u8(untag(addr), val)
    }
    fn write_u16(&mut self, addr: u64, val: u16) -> Result<(), Fault> {
        self.0.write_u16(untag(addr), val)
    }
    fn write_u32(&mut self, addr: u64, val: u32) -> Result<(), Fault> {
        self.0.write_u32(untag(addr), val)
    }
    fn write_u64(&mut self, addr: u64, val: u64) -> Result<(), Fault> {
        self.0.write_u64(untag(addr), val)
    }
    fn cmpxchg(&mut self, addr: u64, size: u32, expected: [u64; 2], new: [u64; 2]) -> Result<[u64; 2], Fault> {
        self.0.cmpxchg(untag(addr), size, expected, new)
    }
    fn cntvct(&mut self) -> u64 {
        self.0.cntvct()
    }
    fn cntfrq(&mut self) -> u64 {
        self.0.cntfrq()
    }
    fn random(&mut self) -> Option<u64> {
        self.0.random()
    }
}
