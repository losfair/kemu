// SPDX-License-Identifier: GPL-2.0
//! User-mode stubs placed in the first page of every code region.
//!
//! Translated code enters the stubs for indirect branches, lookup misses,
//! block chaining, single-instruction helpers and guest syscalls. Stubs
//! transfer to the kernel with `syscall` (`%eax` = kemu operation).

use super::regmap::*;
use super::x86::*;

/// kemu operations (include/linux/kemu_abi.h).
pub const OP_SVC: u32 = 0x6b65_6d00;
pub const OP_TRANSLATE: u32 = 0x6b65_6d01;
pub const OP_HELPER: u32 = 0x6b65_6d02;
pub const OP_CHAIN: u32 = 0x6b65_6d03;
pub const OP_STEP: u32 = 0x6b65_6d04;

/// How stubs reach the host runtime.
#[derive(Clone, Copy, Debug)]
pub enum ExitMode {
    /// `syscall` into the kemu kernel.
    Syscall,
    /// `call [rip + slot]` where the slot holds this absolute address
    /// (userspace test harnesses).
    Call(u64),
}

/// Offsets of the stubs within the stub page.
#[derive(Clone, Copy, Debug, Default)]
pub struct StubOffsets {
    pub table_base: u32,
    pub call_slot: u32,
    pub dispatch: u32,
    pub dispatch_rax: u32,
    pub miss: u32,
    pub chain: u32,
    pub helper: u32,
    pub svc: u32,
    pub interp_svc: u32,
    pub step: u32,
    pub end: u32,
    /// Sorted list of (start, end, info) ranges; see `STUB_*`.
    pub ranges: [(u32, u32, u8); 16],
    pub nranges: usize,
}

/// Stub range attributes for state recovery.
pub const STUB_PAGE_STATE: u8 = 0; // guest state fully in the state page
pub const STUB_PINNED_LIVE: u8 = 1; // pinned regs in host regs, pc in page
pub const STUB_PINNED_LIVE_PC_RAX: u8 = 2; // pinned in host regs, pc in %rax

/// Absolute user addresses of the stubs, as needed by the translator.
#[derive(Clone, Copy, Debug, Default)]
pub struct StubAddrs {
    pub dispatch_rax: u64,
    pub miss: u64,
    pub chain: u64,
    pub helper: u64,
    pub svc: u64,
}

impl StubOffsets {
    pub fn addrs(&self, base: u64) -> StubAddrs {
        StubAddrs {
            dispatch_rax: base + self.dispatch_rax as u64,
            miss: base + self.miss as u64,
            chain: base + self.chain as u64,
            helper: base + self.helper as u64,
            svc: base + self.svc as u64,
        }
    }

    /// Range attribute for stub-page offset `off`.
    pub fn info(&self, off: u32) -> u8 {
        for (s, e, i) in self.ranges.iter().take(self.nranges) {
            if off >= *s && off < *e {
                return *i;
            }
        }
        STUB_PAGE_STATE
    }

    fn push(&mut self, s: usize, e: usize, info: u8) {
        if let Some(r) = self.ranges.get_mut(self.nranges) {
            *r = (s as u32, e as u32, info);
            self.nranges += 1;
        }
    }
}

fn exit(a: &mut Asm<'_>, mode: ExitMode, op: u32, slot: usize) {
    a.mov_ri32(RAX, op);
    match mode {
        ExitMode::Syscall => a.syscall(),
        ExitMode::Call(_) => a.call_rm(Rm::M(Mem::rip(slot as i32))),
    }
}

/// Generate the stub page into `out`. `table_base` is the user address of
/// the lookup table, `table_mask8` the byte mask for 8-byte entries.
pub fn gen_stubs(out: &mut [u8], mode: ExitMode, table_base: u64, table_mask8: u32) -> Option<StubOffsets> {
    let mut o = StubOffsets::default();
    let mut a = Asm::new(out);

    o.table_base = a.pos as u32;
    a.u64(table_base);
    o.call_slot = a.pos as u32;
    a.u64(match mode {
        ExitMode::Call(f) => f,
        ExitMode::Syscall => 0,
    });
    let slot = o.call_slot as usize;
    let tb = o.table_base as usize;
    a.align(64);

    // dispatch: resume from the state page.
    o.dispatch = a.pos as u32;
    reload_all(&mut a);
    a.load(Sz::Q, RAX, Mem::gs(OFF_PC));
    let reloaded = a.pos;
    o.push(o.dispatch as usize, reloaded, STUB_PAGE_STATE);

    // dispatch_rax: guest PC in %rax, pinned registers live.
    a.align_nop(16);
    o.dispatch_rax = a.pos as u32;
    let s = a.pos;
    a.store(Sz::Q, Mem::gs(OFF_PC), RAX);
    o.push(reloaded, a.pos, STUB_PINNED_LIVE_PC_RAX);
    let s2 = a.pos;
    a.lea(Sz::D, RDX, Mem::bisd(RAX, RAX, 0, 0));
    a.alu_ri(Alu::And, Sz::D, Rm::R(RDX), table_mask8 as i32);
    a.alu_rm(Alu::Add, Sz::Q, RDX, Rm::M(Mem::rip(tb as i32)));
    a.jmp_rm(Rm::M(Mem::b(RDX)));
    o.push(s2, a.pos, STUB_PINNED_LIVE);
    let _ = s;

    // miss: %rax = guest PC (already stored), pinned live.
    a.align(16);
    o.miss = a.pos as u32;
    let s = a.pos;
    spill_all(&mut a);
    exit(&mut a, mode, OP_TRANSLATE, slot);
    o.push(s, a.pos, STUB_PINNED_LIVE);
    reload_all(&mut a);
    a.jmp_rm(Rm::R(RAX));

    // chain: %rax = target PC, %rdx = patch site.
    a.align(16);
    o.chain = a.pos as u32;
    let s = a.pos;
    a.store(Sz::Q, Mem::gs(OFF_PC), RAX);
    o.push(s, a.pos, STUB_PINNED_LIVE_PC_RAX);
    let s = a.pos;
    a.store(Sz::Q, Mem::gs(OFF_EXIT_INFO), RDX);
    spill_all(&mut a);
    exit(&mut a, mode, OP_CHAIN, slot);
    o.push(s, a.pos, STUB_PINNED_LIVE);
    reload_all(&mut a);
    a.jmp_rm(Rm::R(RAX));

    // helper: called with the guest PC of the instruction in the page.
    a.align(16);
    o.helper = a.pos as u32;
    let s = a.pos;
    spill_all(&mut a);
    exit(&mut a, mode, OP_HELPER, slot);
    o.push(s, a.pos, STUB_PINNED_LIVE);
    reload_all(&mut a);
    a.ret();

    // svc: called with gs:[PC] = svc + 4.
    a.align(16);
    o.svc = a.pos as u32;
    let s = a.pos;
    spill_all(&mut a);
    exit(&mut a, mode, OP_SVC, slot);
    o.push(s, a.pos, STUB_PINNED_LIVE);
    reload_all(&mut a);
    a.ret();

    // interp_svc: interpreter mode; state is in the page.
    a.align(16);
    o.interp_svc = a.pos as u32;
    exit(&mut a, mode, OP_SVC, slot);
    let d = o.dispatch as usize;
    a.jmp(Some(d));

    // step: ptrace single-step; state is in the page.
    a.align(16);
    o.step = a.pos as u32;
    exit(&mut a, mode, OP_STEP, slot);
    a.jmp_rm(Rm::R(RAX));

    a.align(16);
    o.end = a.pos as u32;
    if a.ok() {
        Some(o)
    } else {
        None
    }
}
