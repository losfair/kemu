// SPDX-License-Identifier: GPL-2.0
//! Tier-1 baseline translator: one guest basic block at a time, canonical
//! register map at block boundaries, lazy flags with block-local liveness.
//!
//! Invariants that state recovery (meta.rs) relies on:
//! * A guest instruction's host code is restartable until its last
//!   instruction: a pinned destination that is also a source is written
//!   only by the final host instruction, and stores are idempotent.
//! * Instructions with non-idempotent side effects (atomics, syscalls,
//!   helpers) record ROLL/DONE points right after the side effect.
//! * Guest flags live in host EFLAGS (possibly with inverted carry) or in
//!   the state-page image; every change of location is recorded.
//! * At block exits, flags are in the image and pinned registers live.

use super::meta::{self, kind, Exit, Header, Point, FLAGS_HOST, FLAGS_HOST_INV, FLAGS_MEM};
use super::regmap::*;
use super::stubs::StubAddrs;
use super::x86::*;
use crate::decode::{
    self, BfOp, CselOp, Dp1Op, Dp2Op, Ext, Index, Insn, LogicOp, MulOp, Order, RmwOp,
    Shift as AShift,
};
use crate::env::{Env, Fault};

mod fp;

pub const MAX_INSNS: usize = 64;

/// Debug knob (kemu.jitoff=): disable JIT features to bisect bugs.
/// 1 = helper for all non-control-flow insns, 2 = helper for SIMD/FP,
/// 4 = single-instruction blocks, 32 = no register remapping.
/// (8 = no chaining is handled by the kernel.)
pub static JIT_OFF: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

fn jit_off() -> u32 {
    JIT_OFF.load(core::sync::atomic::Ordering::Relaxed)
}
pub const MAX_POINTS: usize = 640;
pub const MAX_EXITS: usize = 16;

/// Working memory for one translation (provided by the caller so that the
/// translator never allocates and keeps its stack small). Contains only
/// plain integers, so all-zero memory is a valid `Scratch`.
#[repr(C)]
pub struct Scratch {
    words: [u32; MAX_INSNS],
    live_after: [u8; MAX_INSNS],
    points: [Point; MAX_POINTS],
    exits: [Exit; MAX_EXITS],
    /// Direct exit targets at which the guest flags are dead.
    dead: [u64; MAX_DEAD],
    ndead: u32,
}

const MAX_DEAD: usize = 32;

impl Scratch {
    pub const fn new() -> Self {
        Scratch {
            words: [0; MAX_INSNS],
            live_after: [0; MAX_INSNS],
            points: [Point { off: 0, idx: 0, kind: 0, a: 0, b: 0 }; MAX_POINTS],
            exits: [Exit { site: 0, kind: 0, target: 0 }; MAX_EXITS],
            dead: [0; MAX_DEAD],
            ndead: 0,
        }
    }
}

impl Default for Scratch {
    fn default() -> Self {
        Self::new()
    }
}

/// Translation configuration.
#[derive(Clone, Copy, Debug)]
pub struct Cfg {
    pub stubs: StubAddrs,
    /// User address corresponding to `out[0]`.
    pub code_uaddr: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TErr {
    /// Output buffer too small.
    NoSpace,
    /// The first instruction cannot be fetched.
    Fault(Fault),
}

#[derive(Clone, Copy, Debug)]
pub struct TOk {
    /// Bytes used (16-byte aligned), including header and metadata.
    pub size: usize,
    /// Offset of the main entry (used by chaining and the kernel map).
    pub main_off: u32,
    /// Offset of the checking entry (stored in the lookup table).
    pub check_off: u32,
    pub ninsns: u32,
}

#[derive(Clone, Copy)]
struct Flags {
    host: bool,
    inv: bool,
    mem: bool,
}

/// Where a guest GPR lives.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Gp {
    R(Reg),
    M(i32),
    Zero,
}

struct Gen<'s, 'b> {
    a: Asm<'b>,
    cfg: Cfg,
    pc0: u64,
    idx: usize,
    fl: Flags,
    live_after: bool,
    s: &'s mut Scratch,
    np: usize,
    ne: usize,
    overflow: bool,
    /// Operand size of MADD/MSUB (from the instruction's sf bit).
    mul_sz: Sz,
    /// Register remapping for this block: (victim guest, candidate guest).
    /// While `remapped`, each candidate lives in its victim's host
    /// register and each victim lives in the state page.
    remap: [(u32, u32); MAX_REMAP],
    nremap: usize,
    remapped: bool,
    /// Guest flags are live on entry to the block (back-edge targets).
    live_in0: bool,
    /// Loop-body entry (after the remap prologue); self-loops jump here.
    body_off: usize,
}

pub const MAX_REMAP: usize = 4;

fn rd_sp(rd: u32) -> u32 {
    if rd == 31 {
        GUEST_SP
    } else {
        rd
    }
}

impl<'s, 'b> Gen<'s, 'b> {
    fn pc(&self) -> u64 {
        self.pc0.wrapping_add((self.idx as u64) * 4)
    }

    fn point(&mut self, kind: u8, a: u8, b: u8) {
        let p = Point { off: self.a.pos as u32, idx: self.idx as u16, kind, a, b };
        // Collapse points at the same offset (the later one wins).
        // REMAP points are state changes, not resume points: keep them.
        if self.np > 0 && kind != kind::REMAP {
            if let Some(prev) = self.s.points.get_mut(self.np - 1) {
                if prev.off == p.off && prev.kind != kind::REMAP {
                    *prev = p;
                    return;
                }
            }
        }
        match self.s.points.get_mut(self.np) {
            Some(x) => {
                *x = p;
                self.np += 1;
            }
            None => self.overflow = true,
        }
    }

    fn flags_loc(&self) -> u8 {
        // Prefer the image: host EFLAGS may be clobbered later in the
        // instruction while the image stays valid.
        if self.fl.mem {
            FLAGS_MEM
        } else if self.fl.host {
            if self.fl.inv {
                FLAGS_HOST_INV
            } else {
                FLAGS_HOST
            }
        } else {
            FLAGS_MEM
        }
    }

    fn insn_point(&mut self) {
        let loc = self.flags_loc();
        self.point(kind::INSN, loc, 0);
    }

    // ---- flags ----

    /// Make host CF equal to the guest C (non-inverted), recording it.
    fn normalize_carry(&mut self, want_inv: bool) {
        if self.fl.host && self.fl.inv != want_inv {
            self.a.cmc();
            self.fl.inv = want_inv;
            let loc = self.flags_loc();
            self.point(kind::INSN, loc, 0);
        }
    }

    fn flags_to_mem(&mut self) {
        if self.fl.host && !self.fl.mem {
            self.normalize_carry(false);
            self.a.lahf();
            self.a.setcc(Cc::O, RAX);
            self.a.store(Sz::W, Mem::gs(OFF_FLAGS_X86), RAX);
            self.fl.mem = true;
            self.point(kind::FLAGS_MEM, 0, 0);
        }
    }

    /// Guest flags are dead at direct exit target `t` (see flags_dead_at).
    fn dead_at(&self, t: u64) -> bool {
        self.s.dead.iter().take(self.s.ndead as usize).any(|&d| d == t)
    }

    /// Write the flags image before exiting to `t`, unless dead there.
    fn flags_for_exit(&mut self, t: u64) {
        if !self.dead_at(t) {
            self.flags_to_mem();
        }
    }

    fn flags_to_host(&mut self) {
        if !self.fl.host {
            self.a.movzx(Sz::W, RAX, Rm::M(Mem::gs(OFF_FLAGS_X86)));
            self.a.alu_ri(Alu::Add, Sz::B, Rm::R(RAX), 0x7f);
            self.a.sahf();
            self.fl.host = true;
            self.fl.inv = false;
        }
    }

    /// About to emit host code that clobbers EFLAGS.
    fn clobber(&mut self) {
        if self.fl.host && !self.fl.mem && self.live_after {
            self.flags_to_mem();
        }
        self.fl.host = false;
    }

    /// The current instruction defined the guest flags in host EFLAGS.
    fn defined_flags(&mut self, inv: bool) {
        self.fl = Flags { host: true, inv, mem: false };
    }

    /// x86 condition for guest condition `cond`, normalizing the carry
    /// polarity if needed. Flags must be in host EFLAGS. None = always.
    fn cond_cc(&mut self, cond: u32) -> Option<Cc> {
        let c = cond & 15;
        match c {
            0 => Some(Cc::E),
            1 => Some(Cc::Ne),
            2 => Some(if self.fl.inv { Cc::Ae } else { Cc::B }),
            3 => Some(if self.fl.inv { Cc::B } else { Cc::Ae }),
            4 => Some(Cc::S),
            5 => Some(Cc::Ns),
            6 => Some(Cc::O),
            7 => Some(Cc::No),
            8 | 9 => {
                self.normalize_carry(true);
                Some(if c == 8 { Cc::A } else { Cc::Be })
            }
            10 => Some(Cc::Ge),
            11 => Some(Cc::L),
            12 => Some(Cc::G),
            13 => Some(Cc::Le),
            _ => None,
        }
    }

    // ---- registers ----

    fn gp(&self, n: u32, sp: bool) -> Gp {
        let n = if n == 31 {
            if sp {
                GUEST_SP
            } else {
                return Gp::Zero;
            }
        } else {
            n
        };
        if self.remapped {
            for &(v, c) in self.remap.iter().take(self.nremap) {
                if n == c {
                    if let Some(r) = host_of(v) {
                        return Gp::R(r);
                    }
                }
                if n == v {
                    return Gp::M(slot_of(v));
                }
            }
        }
        match host_of(n) {
            Some(r) => Gp::R(r),
            None => Gp::M(slot_of(n)),
        }
    }

    /// Establish the block's register remapping (canonical -> remapped).
    fn remap_prologue(&mut self) {
        if self.nremap == 0 || self.remapped {
            return;
        }
        for &(v, _) in self.remap.iter().take(self.nremap) {
            if let Some(r) = host_of(v) {
                self.a.store(Sz::Q, Mem::gs(slot_of(v)), r);
            }
        }
        self.point(kind::REMAP, 1, 0);
        for &(v, c) in self.remap.iter().take(self.nremap) {
            if let Some(r) = host_of(v) {
                self.a.load(Sz::Q, r, Mem::gs(slot_of(c)));
            }
        }
        self.remapped = true;
        self.point(kind::REMAP, 2, 0);
    }

    /// Return to the canonical register map (remapped -> canonical).
    fn remap_epilogue(&mut self) {
        if !self.remapped {
            return;
        }
        for &(v, c) in self.remap.iter().take(self.nremap) {
            if let Some(r) = host_of(v) {
                self.a.store(Sz::Q, Mem::gs(slot_of(c)), r);
            }
        }
        self.remapped = false;
        self.point(kind::REMAP, 1, 0);
        for &(v, _) in self.remap.iter().take(self.nremap) {
            if let Some(r) = host_of(v) {
                self.a.load(Sz::Q, r, Mem::gs(slot_of(v)));
            }
        }
        self.point(kind::REMAP, 0, 0);
    }

    /// `mov` an immediate without touching flags.
    fn mov_imm(&mut self, dst: Reg, imm: u64) {
        if imm <= u32::MAX as u64 {
            self.a.mov_ri32(dst, imm as u32);
        } else {
            self.a.mov_ri(dst, imm);
        }
    }

    /// Value of guest register `n` in a host register (pinned, or loaded
    /// into `tmp`).
    fn get(&mut self, n: u32, sp: bool, tmp: Reg) -> Reg {
        match self.gp(n, sp) {
            Gp::R(r) => r,
            Gp::M(off) => {
                self.a.load(Sz::Q, tmp, Mem::gs(off));
                tmp
            }
            Gp::Zero => {
                self.a.mov_ri32(tmp, 0);
                tmp
            }
        }
    }

    /// Copy guest register `n` into exactly `dst`.
    fn get_into(&mut self, n: u32, sp: bool, sz: Sz, dst: Reg) {
        match self.gp(n, sp) {
            Gp::R(r) => {
                if r != dst || sz == Sz::D {
                    self.a.mov_rr(sz, dst, r);
                }
            }
            Gp::M(off) => self.a.load(sz, dst, Mem::gs(off)),
            Gp::Zero => self.a.mov_ri32(dst, 0),
        }
    }

    /// Operand form of guest register `n` (no code emitted for R/M).
    fn rm(&mut self, n: u32, sp: bool, tmp: Reg) -> Rm {
        match self.gp(n, sp) {
            Gp::R(r) => Rm::R(r),
            Gp::M(off) => Rm::M(Mem::gs(off)),
            Gp::Zero => {
                self.a.mov_ri32(tmp, 0);
                Rm::R(tmp)
            }
        }
    }

    /// Write `src` (already width-correct) to guest register `n`.
    fn put(&mut self, n: u32, sp: bool, src: Reg) {
        match self.gp(n, sp) {
            Gp::R(r) => {
                if r != src {
                    self.a.mov_rr(Sz::Q, r, src);
                }
            }
            Gp::M(off) => self.a.store(Sz::Q, Mem::gs(off), src),
            Gp::Zero => {}
        }
    }

    // ---- control flow helpers ----

    fn rel_abs(&mut self, at: usize, uaddr: u64) {
        let from = self.cfg.code_uaddr.wrapping_add(at as u64 + 4);
        let rel = uaddr.wrapping_sub(from) as i64;
        if rel < i32::MIN as i64 || rel > i32::MAX as i64 {
            self.overflow = true;
        }
        self.a.patch_u32(at, rel as i32 as u32);
    }

    fn jmp_abs(&mut self, uaddr: u64) {
        let at = self.a.jmp(None);
        self.rel_abs(at, uaddr);
    }

    fn call_abs(&mut self, uaddr: u64) {
        let at = self.a.call(None);
        self.rel_abs(at, uaddr);
    }

    fn pad_for_rel32(&mut self, opcode_len: usize) {
        while (self.a.pos + opcode_len) % 4 != 0 {
            self.a.byte(0x90);
        }
    }

    fn add_exit(&mut self, site: u32, target: u64) {
        match self.s.exits.get_mut(self.ne) {
            Some(e) => {
                *e = Exit { site, kind: meta::EXIT_DIRECT, target };
                self.ne += 1;
            }
            None => self.overflow = true,
        }
    }

    /// Unconditional exit to guest `target`. Flags must be in memory.
    fn exit_to(&mut self, target: u64, main_off: usize) {
        if target == self.pc0 {
            let t = if self.remapped { self.body_off } else { main_off };
            self.a.jmp(Some(t));
            return;
        }
        self.remap_epilogue();
        self.pad_for_rel32(1);
        let at = self.a.jmp(None);
        self.add_exit(at as u32, target);
    }

    /// Conditional exit to guest `target` if `cc`.
    fn exit_if(&mut self, cc: Cc, target: u64, main_off: usize) {
        if target == self.pc0 {
            let t = if self.remapped { self.body_off } else { main_off };
            self.a.jcc(cc, Some(t));
            return;
        }
        if self.remapped {
            // Out-of-line exit with the epilogue; fall through stays remapped.
            let skip = self.a.jcc(cc.invert(), None);
            self.remap_epilogue();
            self.pad_for_rel32(1);
            let at = self.a.jmp(None);
            self.add_exit(at as u32, target);
            self.a.bind32(skip);
            self.remapped = true;
            self.point(kind::REMAP, 2, 0);
            return;
        }
        self.pad_for_rel32(2);
        let at = self.a.jcc(cc, None);
        self.add_exit(at as u32, target);
    }

    /// B.cond with the flags in host EFLAGS: the flags image is written
    /// only on the taken path (or not at all for a back-edge into a block
    /// that doesn't read flags before defining them). Returns false if the
    /// condition is "always" (caller emits an unconditional exit).
    /// Note: writing the image may flip the carry polarity (cmc), so the
    /// host condition is computed after any inline save.
    fn bcond_exit(&mut self, cond: u32, target: u64, main_off: usize) -> bool {
        let dead = if target == self.pc0 { !self.live_in0 } else { self.dead_at(target) };
        let inline_save = !dead && (target == self.pc0 || !self.fl.host || self.fl.mem);
        if inline_save {
            self.flags_to_mem();
        }
        let cc = match self.cond_cc(cond) {
            Some(cc) => cc,
            None => return false,
        };
        if dead || target == self.pc0 || !self.fl.host || self.fl.mem {
            self.exit_if(cc, target, main_off);
            return true;
        }
        let saved = self.fl;
        let was_remapped = self.remapped;
        let skip = self.a.jcc(cc.invert(), None);
        self.flags_to_mem();
        self.remap_epilogue();
        self.pad_for_rel32(1);
        let at = self.a.jmp(None);
        self.add_exit(at as u32, target);
        self.a.bind32(skip);
        self.fl = saved;
        self.remapped = was_remapped;
        if was_remapped {
            self.point(kind::REMAP, 2, 0);
        }
        // Fall-through: the instruction can restart with flags in EFLAGS.
        self.insn_point();
        true
    }

    /// Indirect exit: target guest PC in %rax.
    fn exit_rax(&mut self) {
        self.remap_epilogue();
        self.point(kind::EXIT_RAX, 0, 0);
        self.jmp_abs(self.cfg.stubs.dispatch_rax);
    }

    /// Indirect jump through a per-site inline cache (target PC in %rax).
    fn exit_ic(&mut self) {
        self.remap_epilogue();
        self.point(kind::EXIT_RAX, 0, 0);
        self.pad_for_rel32(1);
        let at = self.a.jmp(None);
        match self.s.exits.get_mut(self.ne) {
            Some(e) => {
                *e = Exit { site: at as u32, kind: meta::EXIT_IC, target: 0 };
                self.ne += 1;
            }
            None => self.overflow = true,
        }
    }

    /// Guest call: host `call` so the matching guest RET is predicted by
    /// the CPU's return stack. `target` None = indirect (in %rax).
    fn call_to(&mut self, target: Option<u64>, next: u64, main_off: usize) {
        self.remap_epilogue();
        self.mov_imm(RSI, next);
        match target {
            Some(t) if t == self.pc0 => {
                self.a.call(Some(main_off));
            }
            Some(t) => {
                self.pad_for_rel32(1);
                let at = self.a.call(None);
                self.add_exit(at as u32, t);
            }
            None => {
                // Indirect call through a per-site inline cache.
                self.point(kind::EXIT_RAX, 0, 0);
                self.pad_for_rel32(1);
                let at = self.a.call(None);
                match self.s.exits.get_mut(self.ne) {
                    Some(e) => {
                        *e = Exit { site: at as u32, kind: meta::EXIT_IC, target: 0 };
                        self.ne += 1;
                    }
                    None => self.overflow = true,
                }
            }
        }
        // Landing pad: a guest RET arrives here with the target in %rax.
        self.point(kind::EXIT_RAX, 0, 0);
        self.a.mov_ri64(RDX, next);
        self.a.alu_rr(Alu::Cmp, Sz::Q, RAX, RDX);
        let j = self.a.jcc(Cc::Ne, None);
        self.rel_abs(j, self.cfg.stubs.dispatch_rax);
        self.exit_to(next, main_off);
    }

    /// Run the current instruction in the kernel interpreter.
    fn helper(&mut self) {
        self.flags_to_mem();
        self.fl.host = false;
        let was = self.remapped;
        self.remap_epilogue();
        let pc = self.pc();
        self.mov_imm(RAX, pc);
        self.a.store(Sz::Q, Mem::gs(OFF_PC), RAX);
        self.call_abs(self.cfg.stubs.helper);
        self.fl = Flags { host: false, inv: false, mem: true };
        self.point(kind::DONE, FLAGS_MEM, 0);
        if was {
            self.remap_prologue();
        }
    }

    // ---- shifted / extended operands ----

    /// Compute `rm` shifted into `dst` (flags may be clobbered).
    fn shifted(&mut self, sz: Sz, rm: u32, shift: AShift, amount: u32, dst: Reg) {
        self.get_into(rm, false, sz, dst);
        if amount == 0 {
            return;
        }
        let amt = amount as u8;
        match shift {
            AShift::Lsl => self.a.shift_ri(Shift::Shl, sz, dst, amt),
            AShift::Lsr => self.a.shift_ri(Shift::Shr, sz, dst, amt),
            AShift::Asr => self.a.shift_ri(Shift::Sar, sz, dst, amt),
            AShift::Ror => self.a.rorx(sz, dst, Rm::R(dst), amt),
        }
    }

    /// Extend `rm` into `dst` per `ext` (no flags clobbered).
    fn extended(&mut self, rm: u32, ext: Ext, dst: Reg) {
        let src = self.rm(rm, false, dst);
        match ext {
            Ext::Uxtb => self.a.movzx(Sz::B, dst, src),
            Ext::Uxth => self.a.movzx(Sz::W, dst, src),
            Ext::Uxtw => match src {
                Rm::R(r) => self.a.mov_rr(Sz::D, dst, r),
                Rm::M(m) => self.a.load(Sz::D, dst, m),
            },
            Ext::Sxtb => self.a.movsx(Sz::B, Sz::Q, dst, src),
            Ext::Sxth => self.a.movsx(Sz::W, Sz::Q, dst, src),
            Ext::Sxtw => self.a.movsx(Sz::D, Sz::Q, dst, src),
            Ext::Uxtx | Ext::Sxtx => match src {
                Rm::R(r) => {
                    if r != dst {
                        self.a.mov_rr(Sz::Q, dst, r)
                    }
                }
                Rm::M(m) => self.a.load(Sz::Q, dst, m),
            },
        }
    }

    // ---- instruction lowering; return false to use the helper ----

    fn add_sub_imm(&mut self, sf: bool, sub: bool, setflags: bool, rd: u32, rn: u32, imm: u64) -> bool {
        let sz = Sz::from_sf(sf);
        let imm = imm as i64;
        let simm = if sub { -imm } else { imm } as i32;
        if !setflags {
            let src = self.get(rn, true, RAX);
            match self.gp(rd, true) {
                Gp::R(d) => self.a.lea(sz, d, Mem::bd(src, simm)),
                _ => {
                    self.a.lea(sz, RAX, Mem::bd(src, simm));
                    self.put(rd_sp(rd), false, RAX);
                }
            }
            return true;
        }
        let op = if sub { Alu::Sub } else { Alu::Add };
        if rd == 31 && sub {
            let src = self.rm(rn, true, RAX);
            self.a.alu_ri(Alu::Cmp, sz, src, imm as i32);
        } else {
            let dn = self.gp(rn, true);
            let dd = self.gp(rd, false);
            match (dd, dn) {
                (Gp::R(d), Gp::R(n)) if d == n => self.a.alu_ri(op, sz, Rm::R(d), imm as i32),
                _ => {
                    self.get_into(rn, true, sz, RAX);
                    self.a.alu_ri(op, sz, Rm::R(RAX), imm as i32);
                    self.put(rd, false, RAX);
                }
            }
        }
        self.defined_flags(sub);
        true
    }

    #[allow(clippy::too_many_arguments)]
    fn add_sub_reg(&mut self, sf: bool, sub: bool, setflags: bool, rd: u32, rn: u32, op2: Rm, sp: bool, lea_ok: Option<(Reg, u8)>) {
        let sz = Sz::from_sf(sf);
        if !setflags {
            if !sub {
                if let Some((idx, scale)) = lea_ok {
                    let base = self.get(rn, sp, RAX);
                    let m = if matches!(self.gp(rn, sp), Gp::Zero) {
                        Mem::isd(idx, scale, 0)
                    } else {
                        Mem::bisd(base, idx, scale, 0)
                    };
                    match self.gp(rd, sp) {
                        Gp::R(d) => self.a.lea(sz, d, m),
                        _ => {
                            self.a.lea(sz, RAX, m);
                            self.put(rd, sp, RAX);
                        }
                    }
                    return;
                }
            }
            self.clobber();
        }
        let op = if sub { Alu::Sub } else { Alu::Add };
        let rd_x = if setflags { false } else { sp };
        if setflags && rd == 31 && sub {
            let n = self.get(rn, sp, RAX);
            match op2 {
                Rm::R(r) => self.a.alu_rr(Alu::Cmp, sz, n, r),
                Rm::M(m) => self.a.alu_rm(Alu::Cmp, sz, n, Rm::M(m)),
            }
        } else {
            let dd = self.gp(rd, rd_x);
            let dn = self.gp(rn, sp);
            let in_place = matches!((dd, dn), (Gp::R(d), Gp::R(n)) if d == n)
                && op2 != Rm::R(match dd { Gp::R(d) => d, _ => RAX });
            if in_place {
                if let Gp::R(d) = dd {
                    self.a.alu_rm(op, sz, d, op2);
                }
            } else {
                self.get_into(rn, sp, sz, RAX);
                self.a.alu_rm(op, sz, RAX, op2);
                self.put(rd, rd_x, RAX);
            }
        }
        if setflags {
            self.defined_flags(sub);
        }
    }

    fn logic(&mut self, sf: bool, op: LogicOp, rd: u32, rn: u32, op2: Rm, rd_sp_ok: bool) {
        let sz = Sz::from_sf(sf);
        let setflags = op == LogicOp::Ands;
        if !setflags {
            self.clobber();
        }
        let alu = match op {
            LogicOp::And | LogicOp::Ands => Alu::And,
            LogicOp::Orr => Alu::Or,
            LogicOp::Eor => Alu::Xor,
        };
        let rdsp = rd_sp_ok && !setflags;
        if setflags && rd == 31 {
            let n = self.get(rn, false, RAX);
            match op2 {
                Rm::R(r) => self.a.test_rr(sz, n, r),
                Rm::M(m) => {
                    self.a.mov_rr(sz, RAX, n);
                    self.a.alu_rm(Alu::And, sz, RAX, Rm::M(m));
                }
            }
        } else {
            let dd = self.gp(rd, rdsp);
            let dn = self.gp(rn, false);
            match (dd, dn) {
                (Gp::R(d), Gp::R(n)) if d == n && op2 != Rm::R(d) => self.a.alu_rm(alu, sz, d, op2),
                _ => {
                    self.get_into(rn, false, sz, RAX);
                    self.a.alu_rm(alu, sz, RAX, op2);
                    self.put(rd, rdsp, RAX);
                }
            }
        }
        if setflags {
            self.defined_flags(false);
        }
    }

    /// Immediate as an x86 operand (imm32 if representable, else in `tmp`).
    fn imm_operand(&mut self, sf: bool, imm: u64, tmp: Reg) -> Result<i32, Reg> {
        let fits = if sf { imm as i64 == imm as i32 as i64 } else { true };
        if fits {
            Ok(imm as u32 as i32)
        } else {
            self.mov_imm(tmp, imm);
            Err(tmp)
        }
    }

    fn logic_imm(&mut self, sf: bool, op: LogicOp, rd: u32, rn: u32, imm: u64) -> bool {
        let sz = Sz::from_sf(sf);
        if op == LogicOp::Orr && rn == 31 {
            // MOV (bitmask immediate)
            match self.gp(rd, true) {
                Gp::R(d) => self.mov_imm(d, imm),
                _ => {
                    self.mov_imm(RAX, imm);
                    self.put(rd_sp(rd), false, RAX);
                }
            }
            return true;
        }
        match self.imm_operand(sf, imm, RDX) {
            Ok(i) => {
                let setflags = op == LogicOp::Ands;
                if !setflags {
                    self.clobber();
                }
                let alu = match op {
                    LogicOp::And | LogicOp::Ands => Alu::And,
                    LogicOp::Orr => Alu::Or,
                    LogicOp::Eor => Alu::Xor,
                };
                if setflags && rd == 31 {
                    let n = self.rm(rn, false, RAX);
                    self.a.test_ri(sz, n, i);
                } else {
                    let rdsp = !setflags;
                    let dd = self.gp(rd, rdsp);
                    let dn = self.gp(rn, false);
                    match (dd, dn) {
                        (Gp::R(d), Gp::R(n)) if d == n => self.a.alu_ri(alu, sz, Rm::R(d), i),
                        _ => {
                            self.get_into(rn, false, sz, RAX);
                            self.a.alu_ri(alu, sz, Rm::R(RAX), i);
                            self.put(rd, rdsp, RAX);
                        }
                    }
                }
                if setflags {
                    self.defined_flags(false);
                }
            }
            Err(r) => self.logic(sf, op, rd, rn, Rm::R(r), true),
        }
        true
    }

    #[allow(clippy::too_many_arguments)]
    fn logic_shift(&mut self, sf: bool, op: LogicOp, negate: bool, shift: AShift, amount: u32, rd: u32, rn: u32, rm: u32) -> bool {
        let sz = Sz::from_sf(sf);
        // MOV / MVN aliases.
        if op == LogicOp::Orr && rn == 31 {
            if !negate && amount == 0 {
                match self.gp(rd, false) {
                    Gp::R(d) => self.get_into(rm, false, sz, d),
                    Gp::M(_) => {
                        self.get_into(rm, false, sz, RAX);
                        self.put(rd, false, RAX);
                    }
                    Gp::Zero => {}
                }
                return true;
            }
            if amount != 0 && shift != AShift::Ror {
                self.clobber();
            }
            self.shifted(sz, rm, shift, amount, RAX);
            if negate {
                self.a.not(sz, RAX);
            }
            self.put(rd, false, RAX);
            return true;
        }
        let setflags = op == LogicOp::Ands;
        if !setflags {
            self.clobber();
        }
        let is_and = op == LogicOp::And || op == LogicOp::Ands;
        let op2 = if amount == 0 && !negate {
            self.rm(rm, false, RDX)
        } else {
            self.shifted(sz, rm, shift, amount, RDX);
            if negate && !is_and {
                self.a.not(sz, RDX);
            }
            Rm::R(RDX)
        };
        if negate && is_and {
            // BIC/BICS: ~op2 & rn
            let n = self.rm(rn, false, RAX);
            self.a.andn(sz, RAX, RDX, n);
            if !(setflags && rd == 31) {
                self.put(rd, false, RAX);
            }
            if setflags {
                self.defined_flags(false);
            }
            return true;
        }
        self.logic(sf, op, rd, rn, op2, false);
        true
    }

    fn movk(&mut self, sf: bool, rd: u32, shift: u32, imm16: u64) -> bool {
        match self.gp(rd, false) {
            Gp::M(off) => {
                self.a.store_imm(Sz::W, Mem::gs(off + (shift / 8) as i32), imm16 as u16 as i16 as i32);
                if !sf {
                    self.a.store_imm(Sz::D, Mem::gs(off + 4), 0);
                }
            }
            Gp::R(d) => {
                let sz = Sz::from_sf(sf);
                if shift == 0 {
                    // Both steps are idempotent, so a restart is safe.
                    self.a.mov_ri32(RAX, imm16 as u32);
                    self.a.mov_rr(Sz::W, d, RAX);
                    if !sf {
                        self.a.mov_rr(Sz::D, d, d);
                    }
                } else {
                    self.a.rorx(sz, RAX, Rm::R(d), shift as u8);
                    self.a.mov_ri32(RDX, imm16 as u32);
                    self.a.mov_rr(Sz::W, RAX, RDX);
                    let back = if sf { 64 - shift } else { 32 - shift };
                    self.a.rorx(sz, d, Rm::R(RAX), back as u8);
                }
            }
            Gp::Zero => {}
        }
        true
    }

    /// UBFM/SBFM core: result in RAX (flags clobbered).
    fn bfm_extract(&mut self, sf: bool, signed: bool, rn: u32, r: u32, s: u32) {
        let sz = Sz::from_sf(sf);
        let ds = if sf { 64 } else { 32 };
        self.get_into(rn, false, sz, RAX);
        let right = if signed { Shift::Sar } else { Shift::Shr };
        if s >= r {
            let l = ds - 1 - s;
            let rr = l + r;
            if l != 0 {
                self.a.shift_ri(Shift::Shl, sz, RAX, l as u8);
            }
            if rr != 0 {
                self.a.shift_ri(right, sz, RAX, rr as u8);
            }
        } else {
            let l = ds - 1 - s;
            let rr = r - s - 1;
            if l != 0 {
                self.a.shift_ri(Shift::Shl, sz, RAX, l as u8);
            }
            if rr != 0 {
                self.a.shift_ri(right, sz, RAX, rr as u8);
            }
        }
    }

    fn bitfield(&mut self, sf: bool, op: BfOp, rd: u32, rn: u32, r: u32, s: u32) -> bool {
        let sz = Sz::from_sf(sf);
        let ds = if sf { 64 } else { 32 };
        if r >= ds || s >= ds {
            return false;
        }
        match op {
            BfOp::Unsigned | BfOp::Signed => {
                let signed = op == BfOp::Signed;
                let src = self.rm(rn, false, RAX);
                // Extension aliases (no flags).
                if r == 0 && (s == 7 || s == 15 || (s == 31 && sf)) {
                    match (signed, s) {
                        (false, 7) => self.a.movzx(Sz::B, RAX, src),
                        (false, 15) => self.a.movzx(Sz::W, RAX, src),
                        (false, _) => match src {
                            Rm::R(x) => self.a.mov_rr(Sz::D, RAX, x),
                            Rm::M(m) => self.a.load(Sz::D, RAX, m),
                        },
                        (true, 7) => self.a.movsx(Sz::B, sz, RAX, src),
                        (true, 15) => self.a.movsx(Sz::W, sz, RAX, src),
                        (true, _) => self.a.movsx(Sz::D, Sz::Q, RAX, src),
                    }
                    self.put(rd, false, RAX);
                    return true;
                }
                self.clobber();
                if s == ds - 1 {
                    // LSR / ASR
                    self.get_into(rn, false, sz, RAX);
                    if r != 0 {
                        self.a.shift_ri(if signed { Shift::Sar } else { Shift::Shr }, sz, RAX, r as u8);
                    }
                } else if !signed && s + 1 == r {
                    // LSL
                    self.get_into(rn, false, sz, RAX);
                    self.a.shift_ri(Shift::Shl, sz, RAX, (ds - r) as u8);
                } else {
                    self.bfm_extract(sf, signed, rn, r, s);
                }
                self.put(rd, false, RAX);
                true
            }
            BfOp::Insert => {
                if rd == 31 {
                    return true;
                }
                self.clobber();
                let (width, lsb) = if s >= r { (s - r + 1, 0) } else { (s + 1, ds - r) };
                let ones = if width >= 64 { u64::MAX } else { (1u64 << width) - 1 };
                let mask = (ones << lsb) & if sf { u64::MAX } else { 0xffff_ffff };
                self.bfm_extract(sf, false, rn, r, s);
                self.mov_imm(RDX, mask);
                let d = self.rm(rd, false, RDX);
                self.a.andn(sz, RDX, RDX, d);
                self.a.alu_rr(Alu::Or, sz, RAX, RDX);
                self.put(rd, false, RAX);
                true
            }
        }
    }

    fn cond_sel(&mut self, sf: bool, op: CselOp, rd: u32, rn: u32, rm: u32, cond: u32) -> bool {
        let sz = Sz::from_sf(sf);
        self.flags_to_host();
        let cc = self.cond_cc(cond);
        // CSET / CSETM fast paths.
        if rn == 31 && rm == 31 && op == CselOp::Csinc {
            match cc {
                Some(cc) => {
                    self.a.setcc(cc.invert(), RAX);
                    self.a.movzx(Sz::B, RAX, Rm::R(RAX));
                }
                None => self.a.mov_ri32(RAX, 0),
            }
            self.put(rd, false, RAX);
            return true;
        }
        // rax = f(rm)
        self.get_into(rm, false, sz, RAX);
        match op {
            CselOp::Csel => {}
            CselOp::Csinc => self.a.lea(sz, RAX, Mem::bd(RAX, 1)),
            CselOp::Csinv => self.a.not(sz, RAX),
            CselOp::Csneg => {
                self.a.not(sz, RAX);
                self.a.lea(sz, RAX, Mem::bd(RAX, 1));
            }
        }
        match cc {
            Some(cc) => {
                let n = self.rm(rn, false, RDX);
                self.a.cmov(cc, sz, RAX, n);
            }
            None => self.get_into(rn, false, sz, RAX),
        }
        self.put(rd, false, RAX);
        true
    }

    fn cond_cmp(&mut self, sf: bool, sub: bool, reg: bool, rn: u32, imm_or_rm: u32, nzcv: u32, cond: u32) -> bool {
        let sz = Sz::from_sf(sf);
        self.flags_to_host();
        self.flags_to_mem();
        let cc = self.cond_cc(cond);
        let img = image_from_nzcv((nzcv as u64 & 15) << 28) as u16 as i16 as i32;
        let j_else = match cc {
            Some(cc) => Some(self.a.jcc8(cc.invert())),
            None => None,
        };
        self.clobber();
        // then: compare
        self.get_into(rn, false, sz, RAX);
        let op2 = if reg {
            self.rm(imm_or_rm, false, RDX)
        } else {
            self.a.mov_ri32(RDX, imm_or_rm);
            Rm::R(RDX)
        };
        if sub {
            self.a.alu_rm(Alu::Cmp, sz, RAX, op2);
            self.a.cmc();
        } else {
            self.a.alu_rm(Alu::Add, sz, RAX, op2);
        }
        self.point(kind::DONE, FLAGS_HOST, 0);
        self.a.lahf();
        self.a.setcc(Cc::O, RAX);
        self.a.store(Sz::W, Mem::gs(OFF_FLAGS_X86), RAX);
        self.point(kind::DONE, FLAGS_MEM, 0);
        if let Some(j) = j_else {
            let j_done = self.a.jmp8();
            self.a.bind8(j);
            self.point(kind::INSN, FLAGS_MEM, 0);
            self.a.store_imm(Sz::W, Mem::gs(OFF_FLAGS_X86), img);
            self.point(kind::DONE, FLAGS_MEM, 0);
            self.a.bind8(j_done);
        }
        self.fl = Flags { host: false, inv: false, mem: true };
        true
    }

    fn add_sub_carry(&mut self, sf: bool, sub: bool, setflags: bool, rd: u32, rn: u32, rm: u32) -> bool {
        let sz = Sz::from_sf(sf);
        self.flags_to_host();
        if !setflags && self.live_after {
            self.flags_to_mem();
        }
        self.normalize_carry(sub);
        self.get_into(rn, false, sz, RAX);
        let op2 = self.rm(rm, false, RDX);
        self.a.alu_rm(if sub { Alu::Sbb } else { Alu::Adc }, sz, RAX, op2);
        self.put(rd, false, RAX);
        if setflags {
            self.defined_flags(sub);
        } else {
            self.fl.host = false;
        }
        true
    }

    fn dp1(&mut self, sf: bool, op: Dp1Op, rd: u32, rn: u32) -> bool {
        let sz = Sz::from_sf(sf);
        match op {
            Dp1Op::Clz => {
                self.clobber();
                let n = self.rm(rn, false, RAX);
                self.a.bitcnt(0xbd, sz, RAX, n);
            }
            Dp1Op::Cls => {
                self.clobber();
                self.get_into(rn, false, sz, RAX);
                self.a.mov_rr(sz, RDX, RAX);
                self.a.shift_ri(Shift::Sar, sz, RDX, 1);
                self.a.alu_rr(Alu::Xor, sz, RAX, RDX);
                self.a.bitcnt(0xbd, sz, RAX, Rm::R(RAX));
                self.a.lea(sz, RAX, Mem::bd(RAX, -1));
            }
            Dp1Op::Rev => {
                self.get_into(rn, false, sz, RAX);
                self.a.bswap(sz, RAX);
            }
            Dp1Op::Rev32 if sf => {
                self.get_into(rn, false, Sz::Q, RAX);
                self.a.bswap(Sz::Q, RAX);
                self.a.rorx(Sz::Q, RAX, Rm::R(RAX), 32);
            }
            Dp1Op::Rev16 if !sf => {
                self.get_into(rn, false, Sz::D, RAX);
                self.a.bswap(Sz::D, RAX);
                self.a.rorx(Sz::D, RAX, Rm::R(RAX), 16);
            }
            _ => return false,
        }
        self.put(rd, false, RAX);
        true
    }

    fn dp2(&mut self, sf: bool, op: Dp2Op, rd: u32, rn: u32, rm: u32, crc_sz: u8) -> bool {
        let sz = Sz::from_sf(sf);
        match op {
            Dp2Op::Lslv | Dp2Op::Lsrv | Dp2Op::Asrv => {
                let n = self.rm(rn, false, RAX);
                let m = self.get(rm, false, RDX);
                match op {
                    Dp2Op::Lslv => self.a.shlx(sz, RAX, n, m),
                    Dp2Op::Lsrv => self.a.shrx(sz, RAX, n, m),
                    _ => self.a.sarx(sz, RAX, n, m),
                }
            }
            Dp2Op::Rorv => {
                self.clobber();
                self.get_into(rm, false, Sz::D, RDX);
                let n = self.rm(rn, false, RAX);
                self.a.shrx(sz, RAX, n, RDX);
                self.a.neg(Sz::D, RDX);
                self.a.shlx(sz, RDX, n, RDX);
                self.a.alu_rr(Alu::Or, sz, RAX, RDX);
            }
            Dp2Op::Udiv | Dp2Op::Sdiv => {
                self.clobber();
                let signed = op == Dp2Op::Sdiv;
                let m = self.rm(rm, false, RDX);
                // m may be RDX only for XZR (division by zero).
                if m == Rm::R(RDX) {
                    self.a.mov_ri32(RAX, 0);
                    self.put(rd, false, RAX);
                    return true;
                }
                // zero divisor -> 0
                match m {
                    Rm::R(r) => self.a.test_rr(sz, r, r),
                    Rm::M(mm) => self.a.alu_ri(Alu::Cmp, sz, Rm::M(mm), 0),
                }
                let j_zero = self.a.jcc8(Cc::E);
                let mut j_neg = None;
                if signed {
                    self.a.alu_ri(Alu::Cmp, sz, m, -1);
                    j_neg = Some(self.a.jcc8(Cc::E));
                }
                self.get_into(rn, false, sz, RAX);
                if signed {
                    self.a.cqo(sz);
                    self.a.grp3(sz, 7, m);
                } else {
                    self.a.mov_ri32(RDX, 0);
                    self.a.grp3(sz, 6, m);
                }
                let j_done = self.a.jmp8();
                let mut j_done2 = None;
                if let Some(j) = j_neg {
                    self.a.bind8(j);
                    self.get_into(rn, false, sz, RAX);
                    self.a.neg(sz, RAX);
                    j_done2 = Some(self.a.jmp8());
                }
                self.a.bind8(j_zero);
                self.a.mov_ri32(RAX, 0);
                self.a.bind8(j_done);
                if let Some(j) = j_done2 {
                    self.a.bind8(j);
                }
            }
            Dp2Op::Crc32 => {
                // Byte-wise table CRC (IEEE polynomial); x86 crc32 is CRC32C.
                self.clobber();
                let m = self.get(rm, false, RDX);
                self.a.store(Sz::Q, Mem::gs(OFF_SCRATCH0), m);
                self.get_into(rn, false, Sz::D, RAX);
                for i in 0..(1 << crc_sz.min(3)) {
                    self.a.movzx(Sz::B, RDX, Rm::M(Mem::gs(OFF_SCRATCH0 + i)));
                    self.a.alu_rr(Alu::Xor, Sz::B, RDX, RAX);
                    self.a.movzx(Sz::B, RDX, Rm::R(RDX));
                    self.a.shift_ri(Shift::Shr, Sz::D, RAX, 8);
                    let mut t = Mem::isd(RDX, 2, OFF_CRC_TABLE);
                    t.gs = true;
                    self.a.alu_rm(Alu::Xor, Sz::D, RAX, Rm::M(t));
                }
            }
            Dp2Op::Crc32c => {
                self.get_into(rn, false, Sz::D, RAX);
                let m = self.rm(rm, false, RDX);
                let msz = match crc_sz {
                    0 => Sz::B,
                    1 => Sz::W,
                    2 => Sz::D,
                    _ => Sz::Q,
                };
                self.a.crc32(msz, RAX, m);
            }
        }
        self.put(rd, false, RAX);
        true
    }

    fn mul(&mut self, op: MulOp, rd: u32, rn: u32, rm: u32, ra: u32) -> bool {
        match op {
            MulOp::Umulh => {
                self.get_into(rn, false, Sz::Q, RDX);
                let m = self.rm(rm, false, RAX);
                if m == Rm::R(RAX) {
                    self.a.mov_ri32(RAX, 0);
                } else {
                    self.a.mulx(Sz::Q, RAX, RDX, m);
                }
                self.put(rd, false, RAX);
                return true;
            }
            MulOp::Smulh => {
                self.clobber();
                self.get_into(rn, false, Sz::Q, RAX);
                let m = self.rm(rm, false, RDX);
                if m == Rm::R(RDX) {
                    self.a.mov_ri32(RDX, 0);
                } else {
                    self.a.grp3(Sz::Q, 5, m);
                }
                self.put(rd, false, RDX);
                return true;
            }
            _ => {}
        }
        self.clobber();
        let (wide, signed, sub) = match op {
            MulOp::Madd => (false, false, false),
            MulOp::Msub => (false, false, true),
            MulOp::Smaddl => (true, true, false),
            MulOp::Smsubl => (true, true, true),
            MulOp::Umaddl => (true, false, false),
            MulOp::Umsubl => (true, false, true),
            _ => return false,
        };
        let sz = if wide { Sz::Q } else { self.mul_sz };
        if wide {
            let n = self.rm(rn, false, RAX);
            let m = self.rm(rm, false, RDX);
            if signed {
                self.a.movsx(Sz::D, Sz::Q, RAX, n);
                self.a.movsx(Sz::D, Sz::Q, RDX, m);
            } else {
                match n {
                    Rm::R(x) => self.a.mov_rr(Sz::D, RAX, x),
                    Rm::M(mm) => self.a.load(Sz::D, RAX, mm),
                }
                match m {
                    Rm::R(x) => self.a.mov_rr(Sz::D, RDX, x),
                    Rm::M(mm) => self.a.load(Sz::D, RDX, mm),
                }
            }
            self.a.imul_rr(Sz::Q, RAX, Rm::R(RDX));
        } else {
            self.get_into(rn, false, sz, RAX);
            let m = self.rm(rm, false, RDX);
            self.a.imul_rr(sz, RAX, m);
        }
        if ra != 31 {
            if sub {
                self.a.mov_rr(Sz::Q, RDX, RAX);
                self.get_into(ra, false, sz, RAX);
                self.a.alu_rr(Alu::Sub, sz, RAX, RDX);
            } else {
                let a = self.rm(ra, false, RDX);
                self.a.alu_rm(Alu::Add, sz, RAX, a);
            }
        } else if sub {
            self.a.neg(sz, RAX);
        }
        self.put(rd, false, RAX);
        true
    }

    // ---- loads and stores ----

    /// Base register value for an access (SP-encoded rn) in a register.
    fn base(&mut self, rn: u32) -> Reg {
        self.get(rn, true, RDX)
    }

    fn writeback(&mut self, rn: u32, base: Reg, off: i64) {
        match self.gp(rn, true) {
            Gp::R(r) => self.a.lea(Sz::Q, r, Mem::bd(r, off as i32)),
            Gp::M(o) => {
                self.a.lea(Sz::Q, base, Mem::bd(base, off as i32));
                self.a.store(Sz::Q, Mem::gs(o), base);
            }
            Gp::Zero => {}
        }
    }

    /// Load into a GPR from `m`.
    fn load_gpr(&mut self, size: u8, sign_ext: u8, rt: u32, m: Mem) {
        let dst = match self.gp(rt, false) {
            Gp::R(r) => r,
            _ => RAX,
        };
        match (size, sign_ext) {
            (0, 0) => self.a.movzx(Sz::B, dst, Rm::M(m)),
            (1, 0) => self.a.movzx(Sz::W, dst, Rm::M(m)),
            (2, 0) => self.a.load(Sz::D, dst, m),
            (3, _) => self.a.load(Sz::Q, dst, m),
            (0, s) => self.a.movsx(Sz::B, if s == 64 { Sz::Q } else { Sz::D }, dst, Rm::M(m)),
            (1, s) => self.a.movsx(Sz::W, if s == 64 { Sz::Q } else { Sz::D }, dst, Rm::M(m)),
            (2, _) => self.a.movsx(Sz::D, Sz::Q, dst, Rm::M(m)),
            _ => self.a.load(Sz::Q, dst, m),
        }
        if dst == RAX {
            self.put(rt, false, RAX);
        }
    }

    fn store_gpr(&mut self, size: u8, rt: u32, m: Mem, release: bool) {
        let sz = match size {
            0 => Sz::B,
            1 => Sz::W,
            2 => Sz::D,
            _ => Sz::Q,
        };
        if release {
            self.get_into(rt, false, Sz::Q, RAX);
            self.a.xchg(sz, Rm::M(m), RAX);
            return;
        }
        match self.gp(rt, false) {
            Gp::R(r) => self.a.store(sz, m, r),
            Gp::Zero => self.a.store_imm(sz, m, 0),
            Gp::M(o) => {
                self.a.load(Sz::Q, RAX, Mem::gs(o));
                self.a.store(sz, m, RAX);
            }
        }
    }

    fn load_fp(&mut self, size: u8, rt: u32, m: Mem) {
        let v = OFF_V + (rt as i32 & 31) * 16;
        match size {
            4 => {
                self.a.vmovdqu_load(15, m);
                self.a.vmovdqu_store(Mem::gs(v), 15);
            }
            3 => {
                self.a.vmovq_load(15, m);
                self.a.vmovdqu_store(Mem::gs(v), 15);
            }
            2 => {
                self.a.vmovd_load(15, m);
                self.a.vmovdqu_store(Mem::gs(v), 15);
            }
            _ => {
                self.a.movzx(if size == 0 { Sz::B } else { Sz::W }, RAX, Rm::M(m));
                self.a.vmov_from_gpr(Sz::D, 15, RAX);
                self.a.vmovdqu_store(Mem::gs(v), 15);
            }
        }
    }

    fn store_fp(&mut self, size: u8, rt: u32, m: Mem) {
        let v = OFF_V + (rt as i32 & 31) * 16;
        match size {
            4 => {
                self.a.vmovdqu_load(15, Mem::gs(v));
                self.a.vmovdqu_store(m, 15);
            }
            3 => {
                self.a.load(Sz::Q, RAX, Mem::gs(v));
                self.a.store(Sz::Q, m, RAX);
            }
            2 => {
                self.a.load(Sz::D, RAX, Mem::gs(v));
                self.a.store(Sz::D, m, RAX);
            }
            1 => {
                self.a.load(Sz::D, RAX, Mem::gs(v));
                self.a.store(Sz::W, m, RAX);
            }
            _ => {
                self.a.load(Sz::D, RAX, Mem::gs(v));
                self.a.store(Sz::B, m, RAX);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn ldst(&mut self, load: bool, fp: bool, size: u8, sign_ext: u8, index: Index, order: Order, rt: u32, rn: u32, offset: i64) -> bool {
        if offset < i32::MIN as i64 + 64 || offset > i32::MAX as i64 - 64 {
            return false;
        }
        if fp && size > 4 {
            return false;
        }
        let base = self.base(rn);
        let (m, wb) = match index {
            Index::Unsigned | Index::Signed => (Mem::bd(base, offset as i32), None),
            Index::Pre => (Mem::bd(base, offset as i32), Some(offset)),
            Index::Post => (Mem::b(base), Some(offset)),
        };
        // Acquire/release accesses must be naturally aligned (no LSE2).
        let mut done_align = None;
        if order != Order::None && size > 0 {
            self.flags_to_mem();
            self.clobber();
            self.a.lea(Sz::Q, RAX, m);
            done_align = self.align_check(RAX, size);
        }
        let release = order == Order::AcqRel && !load;
        if fp {
            if load {
                self.load_fp(size, rt, m)
            } else {
                self.store_fp(size, rt, m)
            }
        } else if load {
            self.load_gpr(size, sign_ext, rt, m);
        } else {
            self.store_gpr(size, rt, m, release);
        }
        if let Some(off) = wb {
            self.writeback(rn, base, off);
        }
        if let Some(d) = done_align {
            self.a.bind32(d);
            self.point(kind::DONE, FLAGS_MEM, 0);
        }
        true
    }

    #[allow(clippy::too_many_arguments)]
    fn ldst_reg(&mut self, load: bool, fp: bool, size: u8, sign_ext: u8, ext: Ext, shift: u32, rt: u32, rn: u32, rm: u32) -> bool {
        if shift > 3 || (fp && size > 4) {
            return false;
        }
        // index into RDX, base pinned or RAX; address computed into RDX if needed.
        let idx = match ext {
            Ext::Uxtx | Ext::Sxtx => match self.gp(rm, false) {
                Gp::R(r) => r,
                _ => {
                    self.get_into(rm, false, Sz::Q, RDX);
                    RDX
                }
            },
            _ => {
                self.extended(rm, ext, RDX);
                RDX
            }
        };
        let base = self.get(rn, true, RAX);
        let m = if base == RAX {
            // Free RAX for data: fold into RDX.
            self.a.lea(Sz::Q, RDX, Mem::bisd(RAX, idx, shift as u8, 0));
            Mem::b(RDX)
        } else {
            Mem::bisd(base, idx, shift as u8, 0)
        };
        if fp {
            if load {
                self.load_fp(size, rt, m)
            } else {
                self.store_fp(size, rt, m)
            }
        } else if load {
            self.load_gpr(size, sign_ext, rt, m);
        } else {
            self.store_gpr(size, rt, m, false);
        }
        true
    }

    #[allow(clippy::too_many_arguments)]
    fn ldst_pair(&mut self, load: bool, fp: bool, size: u8, signed: bool, index: Index, rt: u32, rt2: u32, rn: u32, offset: i64) -> bool {
        if offset < -4096 || offset > 4096 || (fp && size > 4) || (!fp && size < 2) {
            return false;
        }
        let es = 1i32 << size;
        let base = self.base(rn);
        let (off0, wb) = match index {
            Index::Unsigned | Index::Signed => (offset as i32, None),
            Index::Pre => (offset as i32, Some(offset)),
            Index::Post => (0, Some(offset)),
        };
        let m1 = Mem::bd(base, off0);
        let m2 = Mem::bd(base, off0 + es);
        let sext = if signed { 64 } else { 0 };
        if fp {
            if load {
                self.load_fp(size, rt, m1);
                self.load_fp(size, rt2, m2);
            } else {
                self.store_fp(size, rt, m1);
                self.store_fp(size, rt2, m2);
            }
        } else if load {
            // Commit the register that aliases the base last.
            let base_guest = if rn == 31 { GUEST_SP } else { rn };
            if rt == base_guest {
                self.load_gpr(size, sext, rt2, m2);
                self.load_gpr(size, sext, rt, m1);
            } else {
                self.load_gpr(size, sext, rt, m1);
                self.load_gpr(size, sext, rt2, m2);
            }
        } else {
            self.store_gpr(size, rt, m1, false);
            self.store_gpr(size, rt2, m2, false);
        }
        if let Some(off) = wb {
            self.writeback(rn, base, off);
        }
        true
    }

    /// Out-of-line helper path for misaligned atomics. Returns the rel32
    /// placeholder to bind at the end of the instruction.
    fn align_check(&mut self, base: Reg, size: u8) -> Option<usize> {
        if size == 0 {
            return None;
        }
        self.a.test_ri(Sz::D, Rm::R(base), (1 << size) - 1);
        let j = self.a.jcc8(Cc::E);
        self.helper_inline_fallback();
        let done = self.a.jmp(None);
        self.a.bind8(j);
        // Back to "restart this instruction" for the aligned path.
        self.point(kind::INSN, FLAGS_MEM, 0);
        Some(done)
    }

    fn atomic(&mut self, op: RmwOp, size: u8, rs: u32, rt: u32, rn: u32) -> bool {
        let sz = match size {
            0 => Sz::B,
            1 => Sz::W,
            2 => Sz::D,
            _ => Sz::Q,
        };
        let simple = matches!(op, RmwOp::Swp | RmwOp::Add)
            || (rt == 31 && matches!(op, RmwOp::Clr | RmwOp::Eor | RmwOp::Set));
        let minmax = matches!(op, RmwOp::Smax | RmwOp::Smin | RmwOp::Umax | RmwOp::Umin);
        if !matches!(self.gp(rn, true), Gp::R(_)) || (minmax && size < 2) {
            return false;
        }
        self.flags_to_mem();
        self.clobber();
        let base = self.base(rn);
        let m = Mem::b(base);
        let done = self.align_check(base, size);
        let zext = (size.min(3)) << 4;
        if simple {
            match op {
                RmwOp::Swp => {
                    self.get_into(rs, false, Sz::Q, RAX);
                    self.a.xchg(sz, Rm::M(m), RAX);
                    self.point(kind::ROLL, rt as u8, zext | RAX);
                    if rt != 31 {
                        self.zext_rax(size, sz);
                        self.put(rt, false, RAX);
                    }
                }
                RmwOp::Add if rt == 31 => {
                    let s = self.get(rs, false, RAX);
                    self.a.lock_alu_mr(Alu::Add, sz, m, s);
                }
                RmwOp::Add => {
                    self.get_into(rs, false, Sz::Q, RAX);
                    self.a.lock_xadd(sz, m, RAX);
                    self.point(kind::ROLL, rt as u8, zext | RAX);
                    self.zext_rax(size, sz);
                    self.put(rt, false, RAX);
                }
                _ => {
                    self.get_into(rs, false, Sz::Q, RAX);
                    let alu = match op {
                        RmwOp::Clr => {
                            self.a.not(Sz::Q, RAX);
                            Alu::And
                        }
                        RmwOp::Eor => Alu::Xor,
                        _ => Alu::Or,
                    };
                    self.a.lock_alu_mr(alu, sz, m, RAX);
                }
            }
        } else {
            self.atomic_loop(op, sz, size, rs, rt, m);
        }
        if let Some(d) = done {
            self.a.bind32(d);
            self.point(kind::DONE, FLAGS_MEM, 0);
        }
        true
    }

    fn zext_rax(&mut self, size: u8, sz: Sz) {
        if size < 2 {
            self.a.movzx(sz, RAX, Rm::R(RAX));
        } else if size == 2 {
            self.a.mov_rr(Sz::D, RAX, RAX);
        }
    }

    /// Value-returning RMW via a cmpxchg loop: rax = old, rdx = new.
    fn atomic_loop(&mut self, op: RmwOp, sz: Sz, size: u8, rs: u32, rt: u32, m: Mem) {
        if size < 2 {
            self.a.movzx(sz, RAX, Rm::M(m));
        } else {
            self.a.load(sz, RAX, m);
        }
        let top = self.a.pos;
        self.get_into(rs, false, Sz::Q, RDX);
        match op {
            RmwOp::Clr => self.a.andn(Sz::Q, RDX, RDX, Rm::R(RAX)),
            RmwOp::Eor => self.a.alu_rr(Alu::Xor, Sz::Q, RDX, RAX),
            RmwOp::Set => self.a.alu_rr(Alu::Or, Sz::Q, RDX, RAX),
            RmwOp::Add => self.a.alu_rr(Alu::Add, Sz::Q, RDX, RAX),
            RmwOp::Smax | RmwOp::Smin | RmwOp::Umax | RmwOp::Umin => {
                let csz = if size == 3 { Sz::Q } else { Sz::D };
                self.a.alu_rr(Alu::Cmp, csz, RAX, RDX);
                let cc = match op {
                    RmwOp::Smax => Cc::G,
                    RmwOp::Smin => Cc::L,
                    RmwOp::Umax => Cc::A,
                    _ => Cc::B,
                };
                // rdx = (old cc new) ? old : new
                self.a.cmov(cc, Sz::Q, RDX, Rm::R(RAX));
            }
            RmwOp::Swp => {}
        }
        self.a.lock_cmpxchg(sz, m, RDX);
        self.point(kind::ROLL_IF_ZF, rt as u8, ((size.min(3)) << 4) | RAX);
        self.a.jcc(Cc::Ne, Some(top));
        self.point(kind::ROLL, rt as u8, ((size.min(3)) << 4) | RAX);
        if rt != 31 {
            self.zext_rax(size, sz);
            self.put(rt, false, RAX);
        }
    }

    fn cas(&mut self, size: u8, rs: u32, rt: u32, rn: u32) -> bool {
        let sz = match size {
            0 => Sz::B,
            1 => Sz::W,
            2 => Sz::D,
            _ => Sz::Q,
        };
        if !matches!(self.gp(rn, true), Gp::R(_)) {
            return false;
        }
        self.flags_to_mem();
        self.clobber();
        let base = self.base(rn);
        let done = self.align_check(base, size);
        self.get_into(rs, false, Sz::Q, RAX);
        let new = self.get(rt, false, RDX);
        self.a.lock_cmpxchg(sz, Mem::b(base), new);
        self.point(kind::ROLL, rs as u8, ((size.min(3)) << 4) | RAX);
        if rs != 31 {
            self.zext_rax(size, sz);
            self.put(rs, false, RAX);
        }
        if let Some(d) = done {
            self.a.bind32(d);
            self.point(kind::DONE, FLAGS_MEM, 0);
        }
        true
    }

    /// LDXR / STXR (single register). The monitor lives in the state page
    /// with the same layout the interpreter uses.
    fn excl(&mut self, load: bool, size: u8, rs: u32, rt: u32, rn: u32) -> bool {
        let sz = [Sz::B, Sz::W, Sz::D, Sz::Q][(size & 3) as usize];
        if !matches!(self.gp(rn, true), Gp::R(_)) {
            return false;
        }
        self.flags_to_mem();
        self.clobber();
        let base = self.base(rn);
        let done_align = self.align_check(base, size);
        if load {
            match size {
                0 => self.a.movzx(Sz::B, RAX, Rm::M(Mem::b(base))),
                1 => self.a.movzx(Sz::W, RAX, Rm::M(Mem::b(base))),
                2 => self.a.load(Sz::D, RAX, Mem::b(base)),
                _ => self.a.load(Sz::Q, RAX, Mem::b(base)),
            }
            self.a.store(Sz::Q, Mem::gs(OFF_EXCL_VAL), RAX);
            self.a.store_imm(Sz::Q, Mem::gs(OFF_EXCL_VAL + 8), 0);
            self.a.store_imm(Sz::Q, Mem::gs(OFF_EXCL_SIZE), 1 << size);
            self.a.store(Sz::Q, Mem::gs(OFF_EXCL_ADDR), base);
            self.put(rt, false, RAX);
        } else {
            self.a.alu_rm(Alu::Cmp, Sz::Q, base, Rm::M(Mem::gs(OFF_EXCL_ADDR)));
            let f1 = self.a.jcc(Cc::Ne, None);
            self.a.alu_ri(Alu::Cmp, Sz::Q, Rm::M(Mem::gs(OFF_EXCL_SIZE)), 1 << size);
            let f2 = self.a.jcc(Cc::Ne, None);
            self.a.load(Sz::Q, RAX, Mem::gs(OFF_EXCL_VAL));
            let data = self.get(rt, false, RDX);
            self.a.lock_cmpxchg(sz, Mem::b(base), data);
            self.point(kind::ROLL_STATUS, rs as u8, 0);
            self.a.setcc(Cc::Ne, RAX);
            self.a.movzx(Sz::B, RAX, Rm::R(RAX));
            self.put(rs, false, RAX);
            self.point(kind::DONE, FLAGS_MEM, 0);
            let done = self.a.jmp(None);
            self.a.bind32(f1);
            self.a.bind32(f2);
            self.point(kind::INSN, FLAGS_MEM, 0);
            self.a.mov_ri32(RAX, 1);
            self.put(rs, false, RAX);
            self.a.bind32(done);
            // Status written on both paths: the instruction is complete.
            self.point(kind::DONE, FLAGS_MEM, 0);
            self.a.store_imm(Sz::Q, Mem::gs(OFF_EXCL_ADDR), -1);
        }
        if let Some(d) = done_align {
            self.a.bind32(d);
            self.point(kind::DONE, FLAGS_MEM, 0);
        }
        true
    }

    /// Emit a helper call for the current instruction from within a
    /// lowering (e.g. for a rare runtime path).
    fn helper_inline_fallback(&mut self) {
        let saved = self.fl;
        self.helper();
        self.fl = saved;
    }

    fn dc_zva(&mut self, rt: u32) -> bool {
        self.clobber();
        self.get_into(rt, false, Sz::Q, RDX);
        self.a.alu_ri(Alu::And, Sz::Q, Rm::R(RDX), -64);
        // vpxor ymm15, ymm15, ymm15 ; vmovdqu [rdx], ymm15 ; [rdx+32]
        self.a.vex(1, 1, false, true, 0xef, 15, 15, Rm::R(15));
        self.a.vex(1, 2, false, true, 0x7f, 15, 0, Rm::M(Mem::b(RDX)));
        self.a.vex(1, 2, false, true, 0x7f, 15, 0, Rm::M(Mem::bd(RDX, 32)));
        true
    }

    fn mrs(&mut self, rt: u32, enc: u32) -> bool {
        let off = match enc {
            0xde82 => OFF_TPIDR,
            0xde83 => OFF_TPIDRRO,
            _ => return false,
        };
        match self.gp(rt, false) {
            Gp::R(r) => self.a.load(Sz::Q, r, Mem::gs(off)),
            Gp::M(o) => {
                self.a.load(Sz::Q, RAX, Mem::gs(off));
                self.a.store(Sz::Q, Mem::gs(o), RAX);
            }
            Gp::Zero => {}
        }
        true
    }

    fn msr(&mut self, rt: u32, enc: u32) -> bool {
        if enc != 0xde82 {
            return false;
        }
        let v = self.get(rt, false, RAX);
        self.a.store(Sz::Q, Mem::gs(OFF_TPIDR), v);
        true
    }
}

/// GPR fields of an instruction (conservative: V register numbers in FP
/// forms may be included, which only makes the choice more cautious).
fn gpr_fields(i: &Insn, out: &mut [u32; 6]) -> usize {
    let mut n = 0;
    let mut push = |r: u32| {
        if let Some(x) = out.get_mut(n) {
            *x = r;
            n += 1;
        }
    };
    match *i {
        Insn::Adr { rd, .. } | Insn::Adrp { rd, .. } => push(rd),
        Insn::AddSubImm { rd, rn, .. } | Insn::LogicImm { rd, rn, .. } | Insn::Bitfield { rd, rn, .. } => {
            push(rd);
            push(rn)
        }
        Insn::MovN { rd, .. } | Insn::MovZ { rd, .. } | Insn::MovK { rd, .. } => push(rd),
        Insn::Extr { rd, rn, rm, .. }
        | Insn::AddSubShift { rd, rn, rm, .. }
        | Insn::AddSubExt { rd, rn, rm, .. }
        | Insn::LogicShift { rd, rn, rm, .. }
        | Insn::AddSubCarry { rd, rn, rm, .. }
        | Insn::CondSel { rd, rn, rm, .. }
        | Insn::Dp2 { rd, rn, rm, .. } => {
            push(rd);
            push(rn);
            push(rm)
        }
        Insn::CondCmp { rn, imm_or_rm, reg, .. } => {
            push(rn);
            if reg {
                push(imm_or_rm)
            }
        }
        Insn::Dp1 { rd, rn, .. } => {
            push(rd);
            push(rn)
        }
        Insn::Mul { rd, rn, rm, ra, .. } => {
            push(rd);
            push(rn);
            push(rm);
            push(ra)
        }
        Insn::Cbz { rt, .. } | Insn::Tbz { rt, .. } => push(rt),
        Insn::Br { rn } | Insn::Blr { rn } | Insn::Ret { rn } => push(rn),
        Insn::LdSt { rt, rn, fp, .. } => {
            if !fp {
                push(rt)
            }
            push(rn)
        }
        Insn::LdStReg { rt, rn, rm, fp, .. } => {
            if !fp {
                push(rt)
            }
            push(rn);
            push(rm)
        }
        Insn::LdStPair { rt, rt2, rn, fp, .. } => {
            if !fp {
                push(rt);
                push(rt2)
            }
            push(rn)
        }
        Insn::LdStLiteral { rt, fp, .. } => {
            if !fp {
                push(rt)
            }
        }
        _ => {}
    }
    n
}

/// Pick up to MAX_REMAP (victim, candidate) pairs for a block: candidates
/// are frequently used unpinned registers, victims pinned registers the
/// block never touches. Returns 0 for blocks that use anything we cannot
/// account for (helpers, syscalls, unknown register uses).
fn choose_remap(words: &[u32], out: &mut [(u32, u32); MAX_REMAP]) -> usize {
    let mut count = [0u32; 33];
    let mut used_pinned = [false; 33];
    let mut f = [0u32; 6];
    let mut self_loop = false;
    for (k, w) in words.iter().enumerate() {
        let i = decode::decode(*w);
        if !is_native(&i) || matches!(i, Insn::Svc { .. } | Insn::Mrs { .. } | Insn::MsrReg { .. }) {
            return 0;
        }
        // Anything outside the integer/memory/branch subset: be safe.
        let nf = gpr_fields(&i, &mut f);
        if nf == 0
            && !matches!(
                i,
                Insn::B { .. } | Insn::Bl { .. } | Insn::BCond { .. } | Insn::Nop | Insn::Prfm | Insn::Dmb | Insn::Dsb
            )
        {
            return 0;
        }
        if let Insn::BCond { imm, .. } | Insn::Cbz { imm, .. } | Insn::Tbz { imm, .. } | Insn::B { imm } = i {
            if (k as i64) * 4 + imm == 0 {
                self_loop = true;
            }
        }
        if matches!(i, Insn::Bl { .. } | Insn::Blr { .. }) {
            used_pinned[30] = true;
        }
        for r in f.iter().take(nf) {
            let g = if *r == 31 { GUEST_SP } else { *r };
            if host_of(g).is_some() {
                used_pinned[g as usize] = true;
            } else if (g as usize) < 31 {
                count[g as usize] += 1;
            }
        }
    }
    let threshold = if self_loop { 2 } else { 4 };
    let mut n = 0;
    let mut victims = PINNED.iter().map(|(g, _)| *g).filter(|g| !used_pinned[*g as usize]);
    loop {
        // most used remaining candidate
        let mut best = None;
        for g in 0..31u32 {
            if count[g as usize] >= threshold && best.is_none_or(|b: u32| count[g as usize] > count[b as usize]) {
                best = Some(g);
            }
        }
        let c = match best {
            Some(c) => c,
            None => break,
        };
        count[c as usize] = 0;
        match victims.next() {
            Some(v) => {
                if let Some(slot) = out.get_mut(n) {
                    *slot = (v, c);
                    n += 1;
                }
            }
            None => break,
        }
        if n == MAX_REMAP {
            break;
        }
    }
    n
}

/// Does `i` read the guest flags?
/// Are the guest flags dead on entry to `pc`, i.e. written before being
/// read on every path? Looks at a few straight-line instructions, follows
/// B and both arms of CBZ/TBZ up to `depth`; anything else is "live".
fn flags_dead_at<E: Env>(env: &mut E, mut pc: u64, depth: u32) -> bool {
    for _ in 0..12 {
        let insn = match env.fetch(pc) {
            Ok(w) => decode::decode(w),
            Err(_) => return false,
        };
        match insn {
            Insn::B { imm } => {
                pc = pc.wrapping_add(imm as u64);
                continue;
            }
            Insn::Cbz { imm, .. } | Insn::Tbz { imm, .. } => {
                return depth > 0
                    && flags_dead_at(env, pc.wrapping_add(imm as u64), depth - 1)
                    && flags_dead_at(env, pc.wrapping_add(4), depth - 1);
            }
            _ => {}
        }
        if uses_flags(&insn) || ends_block(&insn) {
            return false;
        }
        if defs_flags(&insn) {
            return true;
        }
        pc = pc.wrapping_add(4);
    }
    false
}

fn uses_flags(i: &Insn) -> bool {
    match i {
        // Side exits leave the block with the flags in memory, so the
        // flags are live at every conditional branch.
        Insn::BCond { .. }
        | Insn::Cbz { .. }
        | Insn::Tbz { .. }
        | Insn::CondSel { .. }
        | Insn::CondCmp { .. }
        | Insn::AddSubCarry { .. }
        | Insn::FpCCmp { .. }
        | Insn::FpCSel { .. }
        | Insn::Rmif { .. }
        | Insn::SetfFlags { .. }
        | Insn::Mrs { .. }
        | Insn::MsrImm { .. } => true,
        _ => !is_native(i),
    }
}

/// Does `i` define all guest flags?
fn defs_flags(i: &Insn) -> bool {
    match i {
        Insn::AddSubImm { setflags, .. }
        | Insn::AddSubShift { setflags, .. }
        | Insn::AddSubExt { setflags, .. }
        | Insn::AddSubCarry { setflags, .. } => *setflags,
        Insn::LogicImm { op, .. } | Insn::LogicShift { op, .. } => *op == LogicOp::Ands,
        Insn::CondCmp { .. } | Insn::FpCmp { .. } => true,
        _ => false,
    }
}

/// Instructions the T1 lowering may handle natively (others always use
/// the helper and are treated as flag readers).
fn is_native(i: &Insn) -> bool {
    !matches!(
        i,
        Insn::Undefined
            | Insn::Hlt { .. }
            | Insn::Brk { .. }
            | Insn::IcIvau { .. }
            | Insn::FpCCmp { .. }
            | Insn::SimdAcross { .. }
            | Insn::SimdSmov { .. }
            | Insn::SimdTbl { .. }
            | Insn::SimdIndexed { .. }
            | Insn::SimdScalarCopy { .. }
            | Insn::Aese { .. }
            | Insn::Aesd { .. }
            | Insn::Aesmc { .. }
            | Insn::Aesimc { .. }
            | Insn::Sha1 { .. }
            | Insn::Sha256 { .. }
            | Insn::Rmif { .. }
            | Insn::SetfFlags { .. }
            | Insn::MsrImm { .. }
    )
}

/// Does `i` end a translation block?
fn ends_block(i: &Insn) -> bool {
    matches!(
        i,
        Insn::B { .. }
            | Insn::Bl { .. }
            | Insn::Br { .. }
            | Insn::Blr { .. }
            | Insn::Ret { .. }
            | Insn::Svc { .. }
            | Insn::Brk { .. }
            | Insn::Hlt { .. }
            | Insn::Undefined
            | Insn::IcIvau { .. }
            | Insn::Isb
    )
}

/// Translate the guest block at `pc` into `out`.
pub fn translate<E: Env>(env: &mut E, pc: u64, out: &mut [u8], cfg: &Cfg, s: &mut Scratch) -> Result<TOk, TErr> {
    // A superblock can run out of exit slots or recovery points; retry with
    // fewer guest instructions before reporting failure.
    let mut limit = if jit_off() & 4 != 0 { 1 } else { MAX_INSNS };
    loop {
        match translate_n(env, pc, out, cfg, s, limit) {
            Err(TErr::NoSpace) if limit > 1 => limit /= 2,
            r => return r,
        }
    }
}

fn translate_n<E: Env>(env: &mut E, pc: u64, out: &mut [u8], cfg: &Cfg, s: &mut Scratch, limit: usize) -> Result<TOk, TErr> {
    // 1. Fetch and decode.
    let mut n = 0usize;
    let mut p = pc;
    while n < limit.min(MAX_INSNS) {
        if n > 0 && p & 0xfff == 0 {
            break;
        }
        let w = match env.fetch(p) {
            Ok(w) => w,
            Err(f) => {
                if n == 0 {
                    return Err(TErr::Fault(f));
                }
                break;
            }
        };
        let insn = decode::decode(w);
        if let Some(ws) = s.words.get_mut(n) {
            *ws = w;
        }
        n += 1;
        p = p.wrapping_add(4);
        if ends_block(&insn) {
            break;
        }
    }

    // 2. Flag liveness (live after each instruction). Direct exits look
    // ahead into their targets: flags written before any read are dead.
    s.ndead = 0;
    let note_target = |s: &mut Scratch, env: &mut E, t: u64| -> bool {
        let dead = flags_dead_at(env, t, 2);
        if dead {
            if let Some(d) = s.dead.get_mut(s.ndead as usize) {
                *d = t;
                s.ndead += 1;
            } else {
                return false;
            }
        }
        dead
    };
    let last_pc = pc.wrapping_add((n.saturating_sub(1) as u64) * 4);
    let last = decode::decode(s.words.get(n.wrapping_sub(1)).copied().unwrap_or(0));
    let mut live = match last {
        Insn::B { imm } => !note_target(s, env, last_pc.wrapping_add(imm as u64)),
        Insn::Bl { imm } => !note_target(s, env, last_pc.wrapping_add(imm as u64)),
        _ if !ends_block(&last) => !note_target(s, env, last_pc.wrapping_add(4)),
        _ => true,
    };
    let mut i = n;
    while i > 0 {
        i -= 1;
        if let Some(l) = s.live_after.get_mut(i) {
            *l = live as u8;
        }
        let insn = decode::decode(s.words.get(i).copied().unwrap_or(0));
        let ipc = pc.wrapping_add((i as u64) * 4);
        live = match insn {
            Insn::Cbz { imm, .. } | Insn::Tbz { imm, .. } => {
                // The block's own last insn already exits to `next`.
                live || !note_target(s, env, ipc.wrapping_add(imm as u64))
            }
            Insn::BCond { imm, .. } => {
                note_target(s, env, ipc.wrapping_add(imm as u64));
                true
            }
            _ => uses_flags(&insn) || (live && !defs_flags(&insn)),
        };
    }
    let live_in0 = live;

    // 3. Emit.
    let mut g = Gen {
        a: Asm::new(out),
        cfg: *cfg,
        pc0: pc,
        idx: 0,
        fl: Flags { host: false, inv: false, mem: true },
        live_after: true,
        s,
        np: 0,
        ne: 0,
        overflow: false,
        mul_sz: Sz::Q,
        remap: [(0, 0); MAX_REMAP],
        nremap: 0,
        remapped: false,
        body_off: 0,
        live_in0,
    };
    if jit_off() & 32 == 0 {
        g.nremap = choose_remap(&g.s.words[..n.min(MAX_INSNS)], &mut g.remap);
    }
    // Header placeholder.
    for _ in 0..meta::HEADER_SIZE {
        g.a.byte(0);
    }
    // Inline-cache entry: %rax holds the branch target; mismatches go to
    // the lookup table.
    g.point(kind::EXIT_RAX, 0, 0);
    g.a.mov_ri64(RDX, pc);
    g.a.alu_rr(Alu::Cmp, Sz::Q, RAX, RDX);
    let jd = g.a.jcc(Cc::Ne, None);
    g.rel_abs(jd, cfg.stubs.dispatch_rax);
    let jmain = g.a.jmp(None);
    while g.a.pos < meta::CHECK_OFF {
        g.a.byte(0xcc);
    }
    // Checking entry (lookup table): mismatches go to the translator.
    let check_off = g.a.pos;
    g.a.mov_ri64(RDX, pc);
    g.a.alu_rr(Alu::Cmp, Sz::Q, RAX, RDX);
    let jm = g.a.jcc(Cc::Ne, None);
    g.rel_abs(jm, cfg.stubs.miss);
    let main_off = g.a.pos;
    g.a.patch_rel32(jmain, main_off);
    g.idx = 0;
    g.point(kind::INSN, FLAGS_MEM, 0);
    g.remap_prologue();
    g.body_off = g.a.pos;

    let mut ended = false;
    let mut idx = 0usize;
    while idx < n {
        g.idx = idx;
        g.live_after = g.s.live_after.get(idx).copied().unwrap_or(1) != 0;
        let w = g.s.words.get(idx).copied().unwrap_or(0);
        let insn = decode::decode(w);
        g.mul_sz = Sz::from_sf(w >> 31 != 0);
        g.insn_point();
        let ipc = g.pc();
        let next = ipc.wrapping_add(4);
        let off = jit_off();
        let branch = ends_block(&insn) || matches!(insn, Insn::BCond { .. } | Insn::Cbz { .. } | Insn::Tbz { .. });
        let simdfp = matches!(
            insn,
            Insn::Fp2 { .. }
                | Insn::Fp3 { .. }
                | Insn::Fp1 { .. }
                | Insn::FpCmp { .. }
                | Insn::FpCSel { .. }
                | Insn::FpCvt { .. }
                | Insn::SimdThree { .. }
                | Insn::SimdMisc { .. }
                | Insn::SimdDup { .. }
                | Insn::SimdModImm { .. }
                | Insn::SimdShift { .. }
                | Insn::SimdExt { .. }
                | Insn::SimdUmov { .. }
                | Insn::SimdInsGpr { .. }
                | Insn::SimdInsElt { .. }
                | Insn::SimdLdSt { .. }
                | Insn::SimdPermute { .. }
        );
        let ok = if (off & 1 != 0 && !branch) || (off & 2 != 0 && simdfp) {
            false
        } else {
            match insn {
            Insn::Nop | Insn::Prfm | Insn::CacheNop | Insn::Sb => true,
            Insn::Dmb | Insn::Dsb => {
                g.clobber();
                g.a.lock_or_rsp();
                true
            }
            Insn::Isb => {
                g.flags_to_mem();
                g.exit_to(next, main_off);
                ended = true;
                true
            }
            Insn::Clrex => {
                g.a.store_imm(Sz::Q, Mem::gs(OFF_EXCL_ADDR), -1);
                true
            }
            Insn::Adr { rd, imm } | Insn::Adrp { rd, imm } => {
                let v = if matches!(insn, Insn::Adrp { .. }) {
                    (ipc & !0xfff).wrapping_add(imm as u64)
                } else {
                    ipc.wrapping_add(imm as u64)
                };
                match g.gp(rd, false) {
                    Gp::R(r) => g.mov_imm(r, v),
                    Gp::M(o) => {
                        g.mov_imm(RAX, v);
                        g.a.store(Sz::Q, Mem::gs(o), RAX);
                    }
                    Gp::Zero => {}
                }
                true
            }
            Insn::AddSubImm { sf, sub, setflags, rd, rn, imm } => g.add_sub_imm(sf, sub, setflags, rd, rn, imm),
            Insn::AddSubShift { sf, sub, setflags, shift, amount, rd, rn, rm } => {
                let sz = Sz::from_sf(sf);
                if amount == 0 {
                    let op2 = g.rm(rm, false, RDX);
                    let lea = match op2 {
                        Rm::R(r) => Some((r, 0)),
                        _ => None,
                    };
                    g.add_sub_reg(sf, sub, setflags, rd, rn, op2, false, lea);
                } else if shift == AShift::Lsl && amount <= 3 && !setflags && !sub {
                    let r = g.get(rm, false, RDX);
                    g.add_sub_reg(sf, sub, setflags, rd, rn, Rm::R(r), false, Some((r, amount as u8)));
                } else {
                    if !setflags {
                        g.clobber();
                    }
                    g.shifted(sz, rm, shift, amount, RDX);
                    g.add_sub_reg(sf, sub, setflags, rd, rn, Rm::R(RDX), false, Some((RDX, 0)));
                }
                true
            }
            Insn::AddSubExt { sf, sub, setflags, ext, amount, rd, rn, rm } => {
                if amount > 4 {
                    false
                } else {
                    g.extended(rm, ext, RDX);
                    if amount <= 3 && !setflags && !sub {
                        g.add_sub_reg(sf, sub, setflags, rd, rn, Rm::R(RDX), true, Some((RDX, amount as u8)));
                    } else {
                        if amount != 0 {
                            if !setflags {
                                g.clobber();
                            }
                            g.a.shift_ri(Shift::Shl, Sz::Q, RDX, amount as u8);
                        }
                        g.add_sub_reg(sf, sub, setflags, rd, rn, Rm::R(RDX), true, Some((RDX, 0)));
                    }
                    true
                }
            }
            Insn::LogicImm { sf, op, rd, rn, imm } => g.logic_imm(sf, op, rd, rn, imm),
            Insn::LogicShift { sf, op, negate, shift, amount, rd, rn, rm } => {
                g.logic_shift(sf, op, negate, shift, amount, rd, rn, rm)
            }
            Insn::MovZ { sf: _, rd, imm: v } | Insn::MovN { sf: _, rd, imm: v } => {
                // The decoder provides the final value for both.
                match g.gp(rd, false) {
                    Gp::R(r) => g.mov_imm(r, v),
                    Gp::M(o) => {
                        g.mov_imm(RAX, v);
                        g.a.store(Sz::Q, Mem::gs(o), RAX);
                    }
                    Gp::Zero => {}
                }
                true
            }
            Insn::MovK { sf, rd, shift, imm16 } => g.movk(sf, rd, shift, imm16),
            Insn::Bitfield { sf, op, rd, rn, immr, imms } => g.bitfield(sf, op, rd, rn, immr, imms),
            Insn::Extr { sf, rd, rn, rm, lsb } => {
                let sz = Sz::from_sf(sf);
                if rn == rm {
                    let m = g.rm(rm, false, RAX);
                    g.a.rorx(sz, RAX, m, lsb as u8);
                } else if lsb == 0 {
                    g.get_into(rm, false, sz, RAX);
                } else {
                    g.clobber();
                    g.get_into(rm, false, sz, RAX);
                    let r = g.get(rn, false, RDX);
                    g.a.shrd_ri(sz, RAX, r, lsb as u8);
                }
                g.put(rd, false, RAX);
                true
            }
            Insn::AddSubCarry { sf, sub, setflags, rd, rn, rm } => g.add_sub_carry(sf, sub, setflags, rd, rn, rm),
            Insn::CondCmp { sf, sub, reg, rn, imm_or_rm, nzcv, cond } => {
                g.cond_cmp(sf, sub, reg, rn, imm_or_rm, nzcv, cond)
            }
            Insn::CondSel { sf, op, rd, rn, rm, cond } => g.cond_sel(sf, op, rd, rn, rm, cond),
            Insn::Dp1 { sf, op, rd, rn } => g.dp1(sf, op, rd, rn),
            Insn::Dp2 { sf, op, rd, rn, rm, crc_sz } => g.dp2(sf, op, rd, rn, rm, crc_sz),
            Insn::Mul { op, rd, rn, rm, ra } => g.mul(op, rd, rn, rm, ra),
            Insn::LdSt { load, fp, size, sign_ext, index, order, rt, rn, offset } => {
                g.ldst(load, fp, size, sign_ext, index, order, rt, rn, offset)
            }
            Insn::LdStLiteral { fp, size, sign_ext, rt, imm } => {
                let addr = ipc.wrapping_add(imm as u64);
                g.mov_imm(RDX, addr);
                let m = Mem::b(RDX);
                if fp {
                    if size <= 4 {
                        g.load_fp(size, rt, m);
                        true
                    } else {
                        false
                    }
                } else {
                    g.load_gpr(size, sign_ext, rt, m);
                    true
                }
            }
            Insn::LdStReg { load, fp, size, sign_ext, ext, shift, rt, rn, rm } => {
                g.ldst_reg(load, fp, size, sign_ext, ext, shift, rt, rn, rm)
            }
            Insn::LdStPair { load, fp, size, signed, index, no_alloc: _, rt, rt2, rn, offset } => {
                g.ldst_pair(load, fp, size, signed, index, rt, rt2, rn, offset)
            }
            Insn::Atomic { op, size, acquire: _, release: _, rs, rt, rn } => g.atomic(op, size, rs, rt, rn),
            Insn::Cas { pair: false, size, acquire: _, release: _, rs, rt, rn } => g.cas(size, rs, rt, rn),
            Insn::LdStExcl { load, pair: false, size, order: _, rs, rt, rt2: _, rn } => g.excl(load, size, rs, rt, rn),
            Insn::DcZva { rt } => g.dc_zva(rt),
            Insn::Mrs { rt, enc } => g.mrs(rt, enc),
            Insn::FpImm { ftype, rd, imm8 } => g.fp_imm_insn(ftype, rd, imm8),
            Insn::Fp2 { ftype, op, rd, rn, rm } => g.fp2(ftype, op, rd, rn, rm),
            Insn::Fp3 { ftype, neg, sub, rd, rn, rm, ra } => g.fp3(ftype, neg, sub, rd, rn, rm, ra),
            Insn::Fp1 { ftype, op, to, rd, rn } => g.fp1(ftype, op, to, rd, rn),
            Insn::FpCmp { ftype, rn, rm, zero, signal } => g.fp_cmp(ftype, rn, rm, zero, signal),
            Insn::FpCSel { ftype, rd, rn, rm, cond } => g.fp_csel(ftype, rd, rn, rm, cond),
            Insn::FpCvt { ftype, sf, op, rd, rn } => g.fp_cvt(ftype, sf, op, rd, rn),
            Insn::SimdThree { q, u, size, op, rd, rn, rm, scalar } => g.simd_three(q, u, size, op, rd, rn, rm, scalar),
            Insn::SimdMisc { q, u, size, op, rd, rn, scalar } => g.simd_misc(q, u, size, op, rd, rn, scalar),
            Insn::SimdDup { q, imm5, rd, rn, from_gpr } => g.simd_dup(q, imm5, rd, rn, from_gpr),
            Insn::SimdModImm { q, op, cmode, rd, imm, fp } => g.simd_mod_imm(q, op, cmode, rd, imm, fp),
            Insn::SimdShift { q, u, immh, immb, opcode, rd, rn, scalar } => g.simd_shift(q, u, immh, immb, opcode, rd, rn, scalar),
            Insn::SimdExt { q, imm4, rd, rn, rm } => g.simd_ext(q, imm4, rd, rn, rm),
            Insn::SimdUmov { q: _, imm5, rd, rn } => g.simd_umov(imm5, rd, rn),
            Insn::SimdInsGpr { imm5, rd, rn } => g.simd_ins_gpr(imm5, rd, rn),
            Insn::SimdInsElt { imm5, imm4, rd, rn } => g.simd_ins_elt(imm5, imm4, rd, rn),
            Insn::SimdLdSt { load: true, q, size, opcode: _, rt, rn, rm, single: true, index: _, replicate: true, selem: 1, post } => {
                g.simd_ld1r(q, size, rt, rn, rm, post)
            }
            Insn::SimdLdSt { load, q, size: _, opcode, rt, rn, rm, single, index: _, replicate: _, selem: _, post } => {
                g.simd_ldst(load, q, opcode, rt, rn, rm, single, post)
            }
            Insn::SimdPermute { q, size, opcode, rd, rn, rm } => g.simd_permute(q, size, opcode, rd, rn, rm),
            Insn::MsrReg { rt, enc } => g.msr(rt, enc),

            // ---- branches ----
            Insn::B { imm } => {
                g.flags_for_exit(ipc.wrapping_add(imm as u64));
                g.exit_to(ipc.wrapping_add(imm as u64), main_off);
                ended = true;
                true
            }
            Insn::Bl { imm } => {
                g.flags_for_exit(ipc.wrapping_add(imm as u64));
                g.call_to(Some(ipc.wrapping_add(imm as u64)), next, main_off);
                ended = true;
                true
            }
            Insn::BCond { cond, imm } => {
                let target = ipc.wrapping_add(imm as u64);
                g.flags_to_host();
                if g.bcond_exit(cond, target, main_off) {
                    if idx + 1 == n {
                        g.flags_for_exit(next);
                        g.exit_to(next, main_off);
                        ended = true;
                    }
                } else {
                    g.flags_for_exit(target);
                    g.exit_to(target, main_off);
                    ended = true;
                }
                true
            }
            Insn::Cbz { sf, nz, rt, imm } => {
                let target = ipc.wrapping_add(imm as u64);
                if g.live_after || !g.dead_at(target) {
                    g.flags_to_mem();
                }
                g.fl.host = false;
                let sz = Sz::from_sf(sf);
                match g.gp(rt, false) {
                    Gp::R(r) => g.a.test_rr(sz, r, r),
                    Gp::M(o) => g.a.alu_ri(Alu::Cmp, sz, Rm::M(Mem::gs(o)), 0),
                    Gp::Zero => g.a.alu_rr(Alu::Xor, Sz::D, RAX, RAX),
                }
                g.exit_if(if nz { Cc::Ne } else { Cc::E }, target, main_off);
                if idx + 1 == n {
                    g.exit_to(next, main_off);
                    ended = true;
                }
                true
            }
            Insn::Tbz { bit, nz, rt, imm } => {
                let target = ipc.wrapping_add(imm as u64);
                if g.live_after || !g.dead_at(target) {
                    g.flags_to_mem();
                }
                g.fl.host = false;
                let r = g.rm(rt, false, RAX);
                g.a.bt_ri(Sz::Q, r, bit as u8);
                g.exit_if(if nz { Cc::B } else { Cc::Ae }, target, main_off);
                if idx + 1 == n {
                    g.exit_to(next, main_off);
                    ended = true;
                }
                true
            }
            Insn::Ret { rn } => {
                g.flags_to_mem();
                g.get_into(rn, false, Sz::Q, RAX);
                g.remap_epilogue();
                g.point(kind::EXIT_RAX, 0, 0);
                g.a.ret();
                ended = true;
                true
            }
            Insn::Br { rn } => {
                g.flags_to_mem();
                g.get_into(rn, false, Sz::Q, RAX);
                g.exit_ic();
                ended = true;
                true
            }
            Insn::Blr { rn } => {
                g.flags_to_mem();
                g.get_into(rn, false, Sz::Q, RAX);
                g.call_to(None, next, main_off);
                ended = true;
                true
            }
            Insn::Svc { .. } => {
                g.flags_to_mem();
                g.fl.host = false;
                g.remap_epilogue();
                g.mov_imm(RAX, next);
                g.a.store(Sz::Q, Mem::gs(OFF_PC), RAX);
                g.call_abs(cfg.stubs.svc);
                g.fl = Flags { host: false, inv: false, mem: true };
                g.point(kind::DONE, FLAGS_MEM, 0);
                g.exit_to(next, main_off);
                ended = true;
                true
            }
            _ => false,
            }
        };
        if !ok {
            // Discard any partial code? Lowerings that return false emit
            // nothing before deciding, so just use the helper.
            g.helper();
            if ends_block(&insn) {
                g.exit_to(next, main_off);
                ended = true;
            }
        }
        idx += 1;
    }
    if !ended {
        g.idx = n;
        g.flags_for_exit(pc.wrapping_add((n as u64) * 4));
        let next = pc.wrapping_add((n as u64) * 4);
        g.idx = n.saturating_sub(1);
        g.point(kind::DONE, FLAGS_MEM, 0);
        g.exit_to(next, main_off);
    }

    // 4. Exit trampolines.
    let ne = g.ne;
    for k in 0..ne {
        let e = g.s.exits.get(k).copied().unwrap_or_default();
        let t = g.a.pos;
        g.idx = n.saturating_sub(1);
        if e.kind == meta::EXIT_IC {
            g.point(kind::EXIT_RAX, 0, 0);
        } else {
            g.point(kind::EXIT, k as u8, 0);
            g.a.mov_ri64(RAX, e.target);
        }
        g.a.lea(Sz::Q, RDX, Mem::rip(e.site as i32));
        g.jmp_abs(cfg.stubs.chain);
        g.a.patch_rel32(e.site as usize, t);
    }
    let code_end = g.a.pos;
    g.a.align(16);

    // 5. Metadata.
    let meta_off = g.a.pos;
    let np = g.np;
    let overflow = g.overflow;
    let g_nremap = g.nremap;
    let g_remap = g.remap;
    let mut a = g.a;
    let s = g.s;
    if overflow || !a.ok() {
        return Err(TErr::NoSpace);
    }
    let points = s.points.get(..np).unwrap_or(&[]);
    let exits = s.exits.get(..ne).unwrap_or(&[]);
    let nremap = g_nremap;
    let remap = g_remap;
    let need = meta::META_HDR_SIZE + np * meta::POINT_SIZE + ne * meta::EXIT_SIZE + 2 * nremap;
    for _ in 0..need {
        a.byte(0);
    }
    if !a.ok() {
        return Err(TErr::NoSpace);
    }
    let total = a.pos;
    drop(a);
    let meta_buf = out.get_mut(meta_off..total).ok_or(TErr::NoSpace)?;
    let mut pairs = [(0u8, 0u8); MAX_REMAP];
    for (d, s) in pairs.iter_mut().zip(remap.iter().take(nremap)) {
        *d = (s.0 as u8, s.1 as u8);
    }
    let mlen = meta::write_meta(meta_buf, points, exits, &pairs[..nremap]).ok_or(TErr::NoSpace)?;
    let hdr = Header {
        main_off: main_off as u32,
        code_end: code_end as u32,
        meta_off: meta_off as u32,
        meta_len: mlen as u32,
        guest_pc: pc,
        guest_insns: n as u32,
    };
    if !hdr.write(out) {
        return Err(TErr::NoSpace);
    }
    Ok(TOk { size: hdr.size(), main_off: main_off as u32, check_off: check_off as u32, ninsns: n as u32 })
}
