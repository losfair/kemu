// SPDX-License-Identifier: GPL-2.0
// Load/store execution for the interpreter.

use super::{Exit, Step};
use crate::decode::{Index, Insn, Order, RmwOp};
use crate::env::{Access, Env, Fault};
use crate::state::CpuState;

/// Read `size` (log2 bytes) from guest memory, zero-extended into u64.
fn load_mem(env: &mut dyn DynEnv, addr: u64, size: u8) -> Result<u64, Fault> {
    Ok(match size {
        0 => env.r8(addr)? as u64,
        1 => env.r16(addr)? as u64,
        2 => env.r32(addr)? as u64,
        _ => env.r64(addr)?,
    })
}

fn store(env: &mut dyn DynEnv, addr: u64, size: u8, val: u64) -> Result<(), Fault> {
    match size {
        0 => env.w8(addr, val as u8),
        1 => env.w16(addr, val as u16),
        2 => env.w32(addr, val as u32),
        _ => env.w64(addr, val),
    }
}

/// Object-safe view of Env so the mem routines aren't generic-duplicated.
trait DynEnv {
    fn r8(&mut self, a: u64) -> Result<u8, Fault>;
    fn r16(&mut self, a: u64) -> Result<u16, Fault>;
    fn r32(&mut self, a: u64) -> Result<u32, Fault>;
    fn r64(&mut self, a: u64) -> Result<u64, Fault>;
    fn w8(&mut self, a: u64, v: u8) -> Result<(), Fault>;
    fn w16(&mut self, a: u64, v: u16) -> Result<(), Fault>;
    fn w32(&mut self, a: u64, v: u32) -> Result<(), Fault>;
    fn w64(&mut self, a: u64, v: u64) -> Result<(), Fault>;
    fn cx(&mut self, a: u64, sz: u32, e: [u64; 2], n: [u64; 2]) -> Result<[u64; 2], Fault>;
}

impl<T: Env> DynEnv for T {
    fn r8(&mut self, a: u64) -> Result<u8, Fault> {
        self.read_u8(a)
    }
    fn r16(&mut self, a: u64) -> Result<u16, Fault> {
        self.read_u16(a)
    }
    fn r32(&mut self, a: u64) -> Result<u32, Fault> {
        self.read_u32(a)
    }
    fn r64(&mut self, a: u64) -> Result<u64, Fault> {
        self.read_u64(a)
    }
    fn w8(&mut self, a: u64, v: u8) -> Result<(), Fault> {
        self.write_u8(a, v)
    }
    fn w16(&mut self, a: u64, v: u16) -> Result<(), Fault> {
        self.write_u16(a, v)
    }
    fn w32(&mut self, a: u64, v: u32) -> Result<(), Fault> {
        self.write_u32(a, v)
    }
    fn w64(&mut self, a: u64, v: u64) -> Result<(), Fault> {
        self.write_u64(a, v)
    }
    fn cx(&mut self, a: u64, sz: u32, e: [u64; 2], n: [u64; 2]) -> Result<[u64; 2], Fault> {
        self.cmpxchg(a, sz, e, n)
    }
}

#[inline]
fn sign_extend(val: u64, from_bytes: u8, to64: bool) -> u64 {
    let bits = (from_bytes as u32) * 8;
    let sb = 64 - bits;
    let s = (((val << sb) as i64) >> sb) as u64;
    if to64 {
        s
    } else {
        s & 0xffff_ffff
    }
}

pub(super) fn exec_ldst<E: Env>(cpu: &mut CpuState, env: &mut E, insn: Insn) -> Step {
    match insn {
        Insn::LdSt { load: ld, fp, size, sign_ext, index, order, rt, rn, offset } => {
            let base = cpu.xsp(rn);
            let addr = match index {
                Index::Post => base,
                _ => base.wrapping_add(offset as u64),
            };
            if order != Order::None {
                // Load-acquire/store-release (incl. RCpc): an unaligned access
                // faults if it is not within one 16-byte aligned block
                // (AArch64.UnalignedAccessFaults with SCTLR_ELx.nAA == 0).
                let bytes = 1u64 << size;
                if addr & (bytes - 1) != 0 && (addr & 15) + bytes > 16 {
                    return Step::Exit(Exit::Fault(Fault { addr, access: if ld { Access::Read } else { Access::Write }, align: true }));
                }
            }
            if let Err(f) = do_single(cpu, env, ld, fp, size, sign_ext, rt, addr) {
                return Step::Exit(Exit::Fault(f));
            }
            apply_wb(cpu, index, rn, base, offset);
            Step::Next
        }
        Insn::LdStReg { load: ld, fp, size, sign_ext, ext, shift, rt, rn, rm } => {
            let base = cpu.xsp(rn);
            let idx = super::extend_reg(cpu.xr(rm), ext, shift);
            let addr = base.wrapping_add(idx);
            if let Err(f) = do_single(cpu, env, ld, fp, size, sign_ext, rt, addr) {
                return Step::Exit(Exit::Fault(f));
            }
            Step::Next
        }
        Insn::LdStLiteral { fp, size, sign_ext, rt, imm } => {
            let addr = cpu.pc.wrapping_add(imm as u64);
            if let Err(f) = do_single(cpu, env, true, fp, size, sign_ext, rt, addr) {
                return Step::Exit(Exit::Fault(f));
            }
            Step::Next
        }
        Insn::LdStPair { load: ld, fp, size, signed, index, no_alloc: _, rt, rt2, rn, offset } => {
            let base = cpu.xsp(rn);
            let addr = match index {
                Index::Post => base,
                _ => base.wrapping_add(offset as u64),
            };
            let esz = 1u64 << size;
            if let Err(f) = do_pair(cpu, env, ld, fp, size, signed, rt, rt2, addr, esz) {
                return Step::Exit(Exit::Fault(f));
            }
            apply_wb(cpu, index, rn, base, offset);
            Step::Next
        }
        _ => Step::Exit(Exit::Undefined(0)),
    }
}

fn do_single<E: Env>(
    cpu: &mut CpuState,
    env: &mut E,
    ld: bool,
    fp: bool,
    size: u8,
    sign_ext: u8,
    rt: u32,
    addr: u64,
) -> Result<(), Fault> {
    if fp {
        if ld {
            let v = load_vec(env, addr, size)?;
            cpu.set_vreg(rt, v);
        } else {
            let v = cpu.vreg(rt);
            store_vec(env, addr, size, v)?;
        }
        return Ok(());
    }
    if ld {
        let raw = load_mem(env, addr, size)?;
        let val = if sign_ext != 0 {
            sign_extend(raw, 1 << size, sign_ext == 64)
        } else {
            raw
        };
        cpu.set_xr(rt, val);
    } else {
        store(env, addr, size, cpu.xr(rt))?;
    }
    Ok(())
}

fn load_vec<E: Env>(env: &mut E, addr: u64, size: u8) -> Result<[u64; 2], Fault> {
    Ok(match size {
        0 => [env.read_u8(addr)? as u64, 0],
        1 => [env.read_u16(addr)? as u64, 0],
        2 => [env.read_u32(addr)? as u64, 0],
        3 => [env.read_u64(addr)?, 0],
        _ => [env.read_u64(addr)?, env.read_u64(addr.wrapping_add(8))?],
    })
}

fn store_vec<E: Env>(env: &mut E, addr: u64, size: u8, v: [u64; 2]) -> Result<(), Fault> {
    match size {
        0 => env.write_u8(addr, v[0] as u8),
        1 => env.write_u16(addr, v[0] as u16),
        2 => env.write_u32(addr, v[0] as u32),
        3 => env.write_u64(addr, v[0]),
        _ => {
            env.write_u64(addr, v[0])?;
            env.write_u64(addr.wrapping_add(8), v[1])
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn do_pair<E: Env>(
    cpu: &mut CpuState,
    env: &mut E,
    ld: bool,
    fp: bool,
    size: u8,
    signed: bool,
    rt: u32,
    rt2: u32,
    addr: u64,
    esz: u64,
) -> Result<(), Fault> {
    let a2 = addr.wrapping_add(esz);
    if fp {
        if ld {
            let v1 = load_vec(env, addr, size)?;
            let v2 = load_vec(env, a2, size)?;
            cpu.set_vreg(rt, v1);
            cpu.set_vreg(rt2, v2);
        } else {
            store_vec(env, addr, size, cpu.vreg(rt))?;
            store_vec(env, a2, size, cpu.vreg(rt2))?;
        }
        return Ok(());
    }
    if ld {
        let r1 = load_mem(env, addr, size)?;
        let r2 = load_mem(env, a2, size)?;
        let (v1, v2) = if signed {
            (sign_extend(r1, 4, true), sign_extend(r2, 4, true))
        } else {
            (r1, r2)
        };
        cpu.set_xr(rt, v1);
        cpu.set_xr(rt2, v2);
    } else {
        store(env, addr, size, cpu.xr(rt))?;
        store(env, a2, size, cpu.xr(rt2))?;
    }
    Ok(())
}

fn apply_wb(cpu: &mut CpuState, index: Index, rn: u32, base: u64, offset: i64) {
    match index {
        Index::Pre | Index::Post => {
            cpu.set_xsp(rn, base.wrapping_add(offset as u64));
        }
        _ => {}
    }
}

pub(super) fn exec_excl<E: Env>(cpu: &mut CpuState, env: &mut E, insn: Insn) -> Step {
    if let Insn::LdStExcl { load, pair, size, order: _, rs, rt, rt2, rn } = insn {
        let addr = cpu.xsp(rn);
        let esz = 1u64 << size;
        let total = if pair { esz * 2 } else { esz };
        if addr & (total - 1) != 0 {
            return Step::Exit(Exit::Fault(Fault {
                addr,
                access: if load { Access::Read } else { Access::Write },
                align: true,
            }));
        }
        if load {
            // LDXR/LDXP: load and set the monitor.
            if pair && size == 2 {
                // LDXP Wt, Wt2: one 64-bit single-copy-atomic access.
                let v = match load_mem(env, addr, 3) {
                    Ok(v) => v,
                    Err(f) => return Step::Exit(Exit::Fault(f)),
                };
                cpu.set_xr(rt, v & 0xffff_ffff);
                cpu.set_xr(rt2, v >> 32);
                cpu.excl_val = [v, 0];
            } else if pair {
                let v1 = match load_mem(env, addr, size) {
                    Ok(v) => v,
                    Err(f) => return Step::Exit(Exit::Fault(f)),
                };
                let v2 = match load_mem(env, addr.wrapping_add(esz), size) {
                    Ok(v) => v,
                    Err(f) => return Step::Exit(Exit::Fault(f)),
                };
                cpu.set_xr(rt, v1);
                cpu.set_xr(rt2, v2);
                cpu.excl_val = [v1, v2];
            } else {
                let v = match load_mem(env, addr, size) {
                    Ok(v) => v,
                    Err(f) => return Step::Exit(Exit::Fault(f)),
                };
                cpu.set_xr(rt, v);
                cpu.excl_val = [v, 0];
            }
            cpu.excl_addr = addr;
            cpu.excl_size = total;
            Step::Next
        } else {
            // STXR/STXP: succeed iff the monitor still holds.
            let success = cpu.excl_addr == addr && cpu.excl_size == total;
            let result = if success {
                let new = if pair && size == 2 {
                    [(cpu.xr(rt) & 0xffff_ffff) | (cpu.xr(rt2) << 32), 0]
                } else if pair {
                    [cpu.xr(rt), cpu.xr(rt2)]
                } else {
                    [cpu.xr(rt), 0]
                };
                let cxsz = total as u32;
                match env.cmpxchg(addr, cxsz, cpu.excl_val, new) {
                    Ok(old) => {
                        if old == normalize(cpu.excl_val, total) {
                            0u64 // success
                        } else {
                            1
                        }
                    }
                    Err(f) => return Step::Exit(Exit::Fault(f)),
                }
            } else {
                1
            };
            cpu.excl_addr = u64::MAX;
            cpu.set_xr(rs, result);
            Step::Next
        }
    } else {
        Step::Exit(Exit::Undefined(0))
    }
}

#[inline]
fn normalize(v: [u64; 2], total: u64) -> [u64; 2] {
    match total {
        1 => [v[0] & 0xff, 0],
        2 => [v[0] & 0xffff, 0],
        4 => [v[0] & 0xffff_ffff, 0],
        8 => [v[0], 0],
        _ => v,
    }
}

pub(super) fn exec_atomic<E: Env>(cpu: &mut CpuState, env: &mut E, insn: Insn) -> Step {
    if let Insn::Atomic { op, size, acquire: _, release: _, rs, rt, rn } = insn {
        let addr = cpu.xsp(rn);
        if addr & ((1u64 << size) - 1) != 0 {
            return Step::Exit(Exit::Fault(Fault { addr, access: Access::Write, align: true }));
        }
        let operand = cpu.xr(rs);
        // Read-modify-write via a cmpxchg loop on `size` bytes.
        loop {
            let old = match load_mem(env, addr, size) {
                Ok(v) => v,
                Err(f) => return Step::Exit(Exit::Fault(f)),
            };
            let new = match op {
                RmwOp::Add => old.wrapping_add(operand),
                RmwOp::Clr => old & !operand,
                RmwOp::Eor => old ^ operand,
                RmwOp::Set => old | operand,
                RmwOp::Swp => operand,
                RmwOp::Smax => smax(old, operand, size),
                RmwOp::Smin => smin(old, operand, size),
                RmwOp::Umax => umax(old, operand, size),
                RmwOp::Umin => umin(old, operand, size),
            };
            let got = match env.cmpxchg(addr, 1u32 << size, [truncsz(old, size), 0], [truncsz(new, size), 0]) {
                Ok(g) => g[0],
                Err(f) => return Step::Exit(Exit::Fault(f)),
            };
            if got == truncsz(old, size) {
                // Return the pre-op value (zero-extended) to rt (unless XZR).
                cpu.set_xr(rt, truncsz(old, size));
                break;
            }
        }
        Step::Next
    } else {
        Step::Exit(Exit::Undefined(0))
    }
}

pub(super) fn exec_cas<E: Env>(cpu: &mut CpuState, env: &mut E, insn: Insn) -> Step {
    if let Insn::Cas { pair, size, acquire: _, release: _, rs, rt, rn } = insn {
        let addr = cpu.xsp(rn);
        let total = (1u64 << size) << pair as u32;
        if addr & (total - 1) != 0 {
            return Step::Exit(Exit::Fault(Fault { addr, access: Access::Write, align: true }));
        }
        if pair {
            let (rs1, rt1) = ((rs + 1) & 31, (rt + 1) & 31);
            if size == 2 {
                // CASP Ws, W(s+1), Wt, W(t+1): one 64-bit access, first
                // register at the lower address.
                let pack = |a: u64, b: u64| (a & 0xffff_ffff) | (b << 32);
                let expected = [pack(cpu.xr(rs), cpu.xr(rs1)), 0];
                let new = [pack(cpu.xr(rt), cpu.xr(rt1)), 0];
                match env.cmpxchg(addr, 8, expected, new) {
                    Ok(old) => {
                        cpu.set_xr(rs, old[0] & 0xffff_ffff);
                        cpu.set_xr(rs1, old[0] >> 32);
                    }
                    Err(f) => return Step::Exit(Exit::Fault(f)),
                }
            } else {
                let expected = [cpu.xr(rs), cpu.xr(rs1)];
                let new = [cpu.xr(rt), cpu.xr(rt1)];
                match env.cmpxchg(addr, 16, expected, new) {
                    Ok(old) => {
                        cpu.set_xr(rs, old[0]);
                        cpu.set_xr(rs1, old[1]);
                    }
                    Err(f) => return Step::Exit(Exit::Fault(f)),
                }
            }
        } else {
            let expected = truncsz(cpu.xr(rs), size);
            let new = truncsz(cpu.xr(rt), size);
            match env.cmpxchg(addr, 1u32 << size, [expected, 0], [new, 0]) {
                Ok(old) => cpu.set_xr(rs, old[0]),
                Err(f) => return Step::Exit(Exit::Fault(f)),
            }
        }
        Step::Next
    } else {
        Step::Exit(Exit::Undefined(0))
    }
}

pub(super) fn exec_dc_zva<E: Env>(cpu: &mut CpuState, env: &mut E, rt: u32) -> Step {
    let addr = cpu.xr(rt) & !63u64;
    let mut i = 0u64;
    while i < 64 {
        if let Err(f) = env.write_u64(addr.wrapping_add(i), 0) {
            return Step::Exit(Exit::Fault(f));
        }
        i += 8;
    }
    Step::Next
}

#[inline]
fn truncsz(v: u64, size: u8) -> u64 {
    match size {
        0 => v & 0xff,
        1 => v & 0xffff,
        2 => v & 0xffff_ffff,
        _ => v,
    }
}
#[inline]
fn sext_sz(v: u64, size: u8) -> i64 {
    match size {
        0 => v as u8 as i8 as i64,
        1 => v as u16 as i16 as i64,
        2 => v as u32 as i32 as i64,
        _ => v as i64,
    }
}
fn smax(a: u64, b: u64, sz: u8) -> u64 {
    if sext_sz(a, sz) >= sext_sz(b, sz) {
        a
    } else {
        b
    }
}
fn smin(a: u64, b: u64, sz: u8) -> u64 {
    if sext_sz(a, sz) <= sext_sz(b, sz) {
        a
    } else {
        b
    }
}
fn umax(a: u64, b: u64, sz: u8) -> u64 {
    if truncsz(a, sz) >= truncsz(b, sz) {
        a
    } else {
        b
    }
}
fn umin(a: u64, b: u64, sz: u8) -> u64 {
    if truncsz(a, sz) <= truncsz(b, sz) {
        a
    } else {
        b
    }
}
