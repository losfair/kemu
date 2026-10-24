// SPDX-License-Identifier: GPL-2.0
//! Translated block layout and recovery metadata.
//!
//! Block layout in the code cache (all offsets relative to the block
//! start, which is 16-byte aligned):
//!
//! ```text
//!   0   BlockHeader (32 bytes)
//!   32  check entry: verifies %rax == guest_pc, falls into main entry
//!   ..  main entry, translated code, exit trampolines
//!   ..  metadata (points, exits)
//! ```
//!
//! The metadata lets the kernel rebuild the exact guest state for any
//! host instruction pointer inside the block (DESIGN.md §9.1).

use super::regmap::{self, GUEST_SP};
use crate::state::CpuState;

pub const BLOCK_MAGIC: u32 = 0x4b42_4c4b; // "KBLK"
pub const HEADER_SIZE: usize = 32;
/// Inline-cache entry: checks %rax, falls back to the lookup table.
pub const IC_OFF: usize = 32;
/// Table entry: checks %rax, falls back to the translate stub.
pub const CHECK_OFF: usize = 64;
pub const POINT_SIZE: usize = 12;
pub const EXIT_SIZE: usize = 16;
pub const META_HDR_SIZE: usize = 8;
pub const NO_SITE: u32 = u32::MAX;

/// Kinds of recovery points.
pub mod kind {
    /// Start of guest instruction `idx`; `a` = flags location (FLAGS_*).
    pub const INSN: u8 = 0;
    /// Within instruction `idx`, guest flags are now in the image.
    pub const FLAGS_MEM: u8 = 1;
    /// Instruction `idx` has performed its side effects; finish it by
    /// writing guest register `a` from host register `b & 15`,
    /// zero-extended from `1 << (b >> 4)` bytes (b >> 4 == 3: no extension),
    /// then continue at the next instruction.
    pub const ROLL: u8 = 2;
    /// Like ROLL, but only if ZF is set in RFLAGS (cmpxchg loops); else
    /// the instruction is restarted.
    pub const ROLL_IF_ZF: u8 = 3;
    /// Instruction `idx` completed and control is leaving the block to
    /// exit `a`'s target.
    pub const EXIT: u8 = 4;
    /// Instruction `idx` completed; the next guest PC is in %rax.
    pub const EXIT_RAX: u8 = 5;
    /// Instruction `idx` completed (pc = idx + 1); `a` = flags location.
    pub const DONE: u8 = 6;
    /// Register remapping state changes to `a`: 0 canonical, 1 victims and
    /// candidates in the state page, 2 remapped (candidates in the victims'
    /// host registers, victims in the page).
    pub const REMAP: u8 = 7;
    /// STXR performed its compare-exchange: finish by writing the status
    /// (ZF ? 0 : 1) to guest register `a`; continue at the next insn.
    pub const ROLL_STATUS: u8 = 8;
}

/// Flag locations for `kind::INSN` points.
pub const FLAGS_MEM: u8 = 0;
pub const FLAGS_HOST: u8 = 1;
pub const FLAGS_HOST_INV: u8 = 2;

#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Point {
    pub off: u32,
    pub idx: u16,
    pub kind: u8,
    pub a: u8,
    pub b: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Exit {
    /// Offset of the patchable rel32 field, or NO_SITE.
    pub site: u32,
    /// EXIT_DIRECT (patch to the target's main entry) or EXIT_IC
    /// (indirect-branch inline cache: patch to the IC entry of whatever
    /// target was seen first).
    pub kind: u32,
    pub target: u64,
}

pub const EXIT_DIRECT: u32 = 0;
pub const EXIT_IC: u32 = 1;

fn put16(b: &mut [u8], off: usize, v: u16) -> bool {
    match b.get_mut(off..off + 2) {
        Some(d) => {
            d.copy_from_slice(&v.to_le_bytes());
            true
        }
        None => false,
    }
}
fn put32(b: &mut [u8], off: usize, v: u32) -> bool {
    match b.get_mut(off..off + 4) {
        Some(d) => {
            d.copy_from_slice(&v.to_le_bytes());
            true
        }
        None => false,
    }
}
fn put64(b: &mut [u8], off: usize, v: u64) -> bool {
    match b.get_mut(off..off + 8) {
        Some(d) => {
            d.copy_from_slice(&v.to_le_bytes());
            true
        }
        None => false,
    }
}
pub fn get16(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}
pub fn get32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    let mut a = [0u8; 4];
    a.copy_from_slice(s);
    Some(u32::from_le_bytes(a))
}
pub fn get64(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off + 8)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Some(u64::from_le_bytes(a))
}

/// Block header, as stored at the block start.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Header {
    pub main_off: u32,
    pub code_end: u32,
    pub meta_off: u32,
    pub meta_len: u32,
    pub guest_pc: u64,
    pub guest_insns: u32,
}

impl Header {
    pub fn write(&self, b: &mut [u8]) -> bool {
        put32(b, 0, BLOCK_MAGIC)
            && put32(b, 4, self.main_off)
            && put32(b, 8, self.code_end)
            && put32(b, 12, self.meta_off)
            && put32(b, 16, self.meta_len)
            && put32(b, 20, self.guest_insns)
            && put64(b, 24, self.guest_pc)
    }

    pub fn read(b: &[u8]) -> Option<Header> {
        if get32(b, 0)? != BLOCK_MAGIC {
            return None;
        }
        Some(Header {
            main_off: get32(b, 4)?,
            code_end: get32(b, 8)?,
            meta_off: get32(b, 12)?,
            meta_len: get32(b, 16)?,
            guest_insns: get32(b, 20)?,
            guest_pc: get64(b, 24)?,
        })
    }

    /// Total bytes occupied by the block, 16-byte aligned.
    pub fn size(&self) -> usize {
        ((self.meta_off as usize + self.meta_len as usize) + 15) & !15
    }
}

/// Serialize metadata into `b`; returns bytes written.
pub fn write_meta(b: &mut [u8], points: &[Point], exits: &[Exit], remap: &[(u8, u8)]) -> Option<usize> {
    let np = u16::try_from(points.len()).ok()?;
    let ne = u16::try_from(exits.len()).ok()?;
    let nr = u32::try_from(remap.len()).ok()?;
    if !(put16(b, 0, np) && put16(b, 2, ne) && put32(b, 4, nr)) {
        return None;
    }
    let mut off = META_HDR_SIZE;
    for p in points {
        if !(put32(b, off, p.off) && put16(b, off + 4, p.idx)) {
            return None;
        }
        let d = b.get_mut(off + 6..off + 9)?;
        d[0] = p.kind;
        d[1] = p.a;
        d[2] = p.b;
        off += POINT_SIZE;
    }
    for e in exits {
        if !(put32(b, off, e.site) && put32(b, off + 4, e.kind) && put64(b, off + 8, e.target)) {
            return None;
        }
        off += EXIT_SIZE;
    }
    for (v, c) in remap {
        let d = b.get_mut(off..off + 2)?;
        d[0] = *v;
        d[1] = *c;
        off += 2;
    }
    Some(off)
}

pub fn meta_counts(m: &[u8]) -> Option<(usize, usize)> {
    Some((get16(m, 0)? as usize, get16(m, 2)? as usize))
}

pub fn read_point(m: &[u8], i: usize) -> Option<Point> {
    let off = META_HDR_SIZE + i * POINT_SIZE;
    let s = m.get(off + 6..off + 9)?;
    Some(Point { off: get32(m, off)?, idx: get16(m, off + 4)?, kind: s[0], a: s[1], b: s[2] })
}

pub fn read_exit(m: &[u8], i: usize) -> Option<Exit> {
    let (np, _) = meta_counts(m)?;
    let off = META_HDR_SIZE + np * POINT_SIZE + i * EXIT_SIZE;
    Some(Exit { site: get32(m, off)?, kind: get32(m, off + 4)?, target: get64(m, off + 8)? })
}

/// Is `site` (block-relative offset of a rel32 field) a patchable exit?
pub fn find_exit_site(m: &[u8], site: u32) -> Option<Exit> {
    let (_, ne) = meta_counts(m)?;
    for i in 0..ne {
        let e = read_exit(m, i)?;
        if e.site == site && site != NO_SITE {
            return Some(e);
        }
    }
    None
}

/// Host general-purpose registers and flags at the interruption point.
#[derive(Clone, Copy, Default, Debug)]
pub struct HostRegs {
    pub gpr: [u64; 16],
    pub rflags: u64,
}

/// Copy pinned guest registers from host registers into `st`.
pub fn pinned_from_host(st: &mut CpuState, h: &HostRegs) {
    for (g, r) in regmap::PINNED.iter() {
        let v = h.gpr[(*r & 15) as usize];
        if *g == GUEST_SP {
            st.sp = v;
        } else {
            st.set_xr(*g, v);
        }
    }
}

fn set_guest(st: &mut CpuState, g: u32, v: u64) {
    if g == GUEST_SP {
        st.sp = v;
    } else {
        st.set_xr(g, v);
    }
}

/// Rebuild the guest state for host offset `host_off` within the block
/// whose bytes are `blk`. Unpinned registers in `st` are assumed to be up
/// to date (they live in the state page). Returns false if the offset is
/// not covered (caller falls back to restarting at the block entry).
pub fn recover(blk: &[u8], host_off: u32, h: &HostRegs, st: &mut CpuState) -> bool {
    let hdr = match Header::read(blk) {
        Some(x) => x,
        None => return false,
    };
    let m = match blk.get(hdr.meta_off as usize..(hdr.meta_off + hdr.meta_len) as usize) {
        Some(x) => x,
        None => return false,
    };
    let (np, _) = match meta_counts(m) {
        Some(x) => x,
        None => return false,
    };
    // Last point at or before host_off; also remember the flags state of
    // the enclosing instruction start.
    let mut best: Option<Point> = None;
    let mut flags_loc = FLAGS_MEM;
    let mut remap_mode = 0u8;
    for i in 0..np {
        let p = match read_point(m, i) {
            Some(p) => p,
            None => return false,
        };
        if p.off > host_off {
            break;
        }
        match p.kind {
            kind::INSN => flags_loc = p.a,
            kind::FLAGS_MEM => flags_loc = FLAGS_MEM,
            kind::REMAP => {
                remap_mode = p.a;
                continue;
            }
            _ => {}
        }
        best = Some(p);
    }
    let p = match best {
        Some(p) => p,
        None => return false,
    };

    // Page values of remap victims (pinned registers that were spilled).
    let nr = get32(m, 4).unwrap_or(0) as usize;
    let (_, ne) = meta_counts(m).unwrap_or((0, 0));
    let roff = META_HDR_SIZE + np * POINT_SIZE + ne * EXIT_SIZE;
    let mut pairs = [(0u32, 0u32, 0u64); 4];
    let nr = nr.min(4);
    for (k, slot) in pairs.iter_mut().enumerate().take(nr) {
        let v = m.get(roff + 2 * k).copied().unwrap_or(0) as u32;
        let c = m.get(roff + 2 * k + 1).copied().unwrap_or(0) as u32;
        let page_v = if v == GUEST_SP { st.sp } else { st.xr(v) };
        *slot = (v, c, page_v);
    }
    pinned_from_host(st, h);
    if remap_mode != 0 {
        for &(v, c, page_v) in pairs.iter().take(nr) {
            let host_val = regmap::host_of(v).map(|r| h.gpr[(r & 15) as usize]).unwrap_or(0);
            set_guest(st, v, page_v);
            if remap_mode == 2 {
                set_guest(st, c, host_val);
            }
        }
    }
    let pc_of = |idx: u16| hdr.guest_pc.wrapping_add((idx as u64) * 4);
    let flags_from = |st: &mut CpuState, loc: u8| match loc {
        FLAGS_HOST => st.nzcv = regmap::nzcv_from_rflags(h.rflags, false),
        FLAGS_HOST_INV => st.nzcv = regmap::nzcv_from_rflags(h.rflags, true),
        _ => st.nzcv = regmap::nzcv_from_image(st.flags_x86),
    };
    match p.kind {
        kind::INSN | kind::FLAGS_MEM => {
            st.pc = pc_of(p.idx);
            flags_from(st, flags_loc);
        }
        kind::ROLL | kind::ROLL_IF_ZF => {
            let zf = (h.rflags >> 6) & 1 != 0;
            if p.kind == kind::ROLL_IF_ZF && !zf {
                st.pc = pc_of(p.idx);
            } else {
                let mut v = h.gpr[(p.b & 15) as usize];
                match p.b >> 4 {
                    0 => v &= 0xff,
                    1 => v &= 0xffff,
                    2 => v &= 0xffff_ffff,
                    _ => {}
                }
                if (p.a as u32) <= GUEST_SP && p.a != 31 {
                    set_guest(st, p.a as u32, v);
                }
                st.pc = pc_of(p.idx.wrapping_add(1));
            }
            // Atomic sequences only run with flags saved.
            st.nzcv = regmap::nzcv_from_image(st.flags_x86);
        }
        kind::DONE => {
            st.pc = pc_of(p.idx.wrapping_add(1));
            flags_from(st, p.a);
        }
        kind::ROLL_STATUS => {
            let zf = (h.rflags >> 6) & 1 != 0;
            if p.a != 31 {
                set_guest(st, p.a as u32, if zf { 0 } else { 1 });
            }
            st.excl_addr = u64::MAX;
            st.pc = pc_of(p.idx.wrapping_add(1));
            st.nzcv = regmap::nzcv_from_image(st.flags_x86);
        }
        kind::EXIT_RAX => {
            st.pc = h.gpr[0];
            st.nzcv = regmap::nzcv_from_image(st.flags_x86);
        }
        kind::EXIT => {
            let e = match read_exit(m, p.a as usize) {
                Some(e) => e,
                None => return false,
            };
            st.pc = e.target;
            st.nzcv = regmap::nzcv_from_image(st.flags_x86);
        }
        _ => return false,
    }
    true
}
