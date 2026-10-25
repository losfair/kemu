// SPDX-License-Identifier: GPL-2.0
//! Shared translation cache support (DESIGN.md §10.4).
//!
//! A block translated in relocatable mode can be copied into another
//! process (or another place in the same code cache) where the guest code
//! sits at a different address. The translator records:
//!
//! - **relocations**: every immediate derived from a guest PC (always a
//!   full `movabs` imm64 in this mode) and every rel32 that leaves the
//!   block (all of them target kemu stubs, which sit at the same offset
//!   from the code base in every mm);
//! - **dependencies**: every guest instruction word the translation read,
//!   including look-ahead into exit targets. A cached block may only be
//!   reused if all of them read back identically at the new address, so
//!   in-memory patching of file-backed text simply misses.
//!
//! Guest-PC-derived values are always `pc + constant`, so shifting them by
//! `new_pc - old_pc` is exact (and page-aligned, which keeps ADRP exact).

use super::meta;
use crate::env::Env;

/// Relocation kinds, in the top 4 bits of a record; the rest is the
/// block-relative offset of the field.
pub const RELOC_IMM64: u32 = 1 << 28;
pub const RELOC_REL32: u32 = 2 << 28;
pub const RELOC_OFF_MASK: u32 = (1 << 28) - 1;

pub const MAX_RELOCS: usize = 96;
pub const MAX_DEPS: usize = 128;

/// One guest instruction word the translation depends on.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Dep {
    pub pc: u64,
    pub word: u32,
    /// 1 = fetched `word`, 0 = the fetch faulted.
    pub ok: u32,
}

const MAGIC: u32 = 0x3243_584b; // "KXC2"
const HDR: usize = 32;
/// Packed dependency: i32 offset from the block's guest PC (bit 0 set =
/// the fetch faulted; offsets are multiples of 4), then the word.
const DEP_SIZE: usize = 8;

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

fn deps_off(nrelocs: usize) -> usize {
    (HDR + 4 * nrelocs + 7) & !7
}

/// Bytes needed for a relocation blob.
pub fn blob_size(nrelocs: usize, ndeps: usize) -> usize {
    deps_off(nrelocs) + DEP_SIZE * ndeps
}

/// Serialize the relocation records of a block translated at guest `pc`,
/// `blk_off` bytes from the code base.
pub fn write_blob(out: &mut [u8], pc: u64, blk_off: u64, relocs: &[u32], deps: &[Dep]) -> Option<usize> {
    let size = blob_size(relocs.len(), deps.len());
    if out.len() < size {
        return None;
    }
    let ok = put32(out, 0, MAGIC)
        && put32(out, 4, relocs.len() as u32)
        && put32(out, 8, deps.len() as u32)
        && put32(out, 12, 0)
        && put64(out, 16, pc)
        && put64(out, 24, blk_off);
    if !ok {
        return None;
    }
    for (i, r) in relocs.iter().enumerate() {
        if !put32(out, HDR + 4 * i, *r) {
            return None;
        }
    }
    let d0 = deps_off(relocs.len());
    for (i, d) in deps.iter().enumerate() {
        let o = d0 + DEP_SIZE * i;
        let rel = d.pc.wrapping_sub(pc) as i64;
        if rel < i32::MIN as i64 || rel > i32::MAX as i64 || rel & 3 != 0 {
            return None;
        }
        let tag = rel as i32 as u32 | (d.ok == 0) as u32;
        if !(put32(out, o, tag) && put32(out, o + 4, d.word)) {
            return None;
        }
    }
    Some(size)
}

struct Blob<'a> {
    b: &'a [u8],
    nrelocs: usize,
    ndeps: usize,
    pc: u64,
    blk_off: u64,
}

fn parse(b: &[u8]) -> Option<Blob<'_>> {
    if meta::get32(b, 0)? != MAGIC {
        return None;
    }
    let nrelocs = meta::get32(b, 4)? as usize;
    let ndeps = meta::get32(b, 8)? as usize;
    if nrelocs > MAX_RELOCS || ndeps > MAX_DEPS || b.len() < blob_size(nrelocs, ndeps) {
        return None;
    }
    Some(Blob { b, nrelocs, ndeps, pc: meta::get64(b, 16)?, blk_off: meta::get64(b, 24)? })
}

fn dep(bl: &Blob<'_>, i: usize) -> Option<Dep> {
    let o = deps_off(bl.nrelocs) + DEP_SIZE * i;
    let tag = meta::get32(bl.b, o)?;
    let rel = (tag & !3) as i32 as i64 as u64;
    Some(Dep { pc: bl.pc.wrapping_add(rel), word: meta::get32(bl.b, o + 4)?, ok: (tag & 1 == 0) as u32 })
}

/// Guest PC the cached block was translated for.
pub fn blob_pc(b: &[u8]) -> Option<u64> {
    parse(b).map(|bl| bl.pc)
}

/// Can the cached block be used for guest `new_pc`? Every instruction word
/// it depends on must read back identically, shifted by the same delta.
pub fn validate<E: Env>(env: &mut E, b: &[u8], new_pc: u64) -> bool {
    let bl = match parse(b) {
        Some(x) => x,
        None => return false,
    };
    let delta = new_pc.wrapping_sub(bl.pc);
    if delta & 0xfff != 0 {
        return false;
    }
    for i in 0..bl.ndeps {
        let d = match dep(&bl, i) {
            Some(d) => d,
            None => return false,
        };
        let now = env.fetch(d.pc.wrapping_add(delta));
        let same = match now {
            Ok(w) => d.ok == 1 && w == d.word,
            Err(_) => d.ok == 0,
        };
        if !same {
            return false;
        }
    }
    true
}

/// The guest pages a cached block depends on when used for `new_pc`
/// (page-aligned addresses, deduplicated). None if they don't fit in `out`.
pub fn pages(b: &[u8], new_pc: u64, out: &mut [u64]) -> Option<usize> {
    let bl = parse(b)?;
    let delta = new_pc.wrapping_sub(bl.pc);
    let mut n = 0;
    for i in 0..bl.ndeps {
        let pg = dep(&bl, i)?.pc.wrapping_add(delta) & !0xfff;
        if out.iter().take(n).any(|&x| x == pg) {
            continue;
        }
        *out.get_mut(n)? = pg;
        n += 1;
    }
    Some(n)
}

/// Relocate a copy of a cached block (`code`, header included) for guest
/// `new_pc`, placed `new_blk_off` bytes from the new code base.
pub fn apply(b: &[u8], code: &mut [u8], new_pc: u64, new_blk_off: u64) -> bool {
    let bl = match parse(b) {
        Some(x) => x,
        None => return false,
    };
    let delta = new_pc.wrapping_sub(bl.pc);
    let hdelta = new_blk_off.wrapping_sub(bl.blk_off) as i64;
    for i in 0..bl.nrelocs {
        let r = match meta::get32(b, HDR + 4 * i) {
            Some(r) => r,
            None => return false,
        };
        let off = (r & RELOC_OFF_MASK) as usize;
        match r & !RELOC_OFF_MASK {
            RELOC_IMM64 => {
                let v = match meta::get64(code, off) {
                    Some(v) => v,
                    None => return false,
                };
                if !put64(code, off, v.wrapping_add(delta)) {
                    return false;
                }
            }
            RELOC_REL32 => {
                let v = match meta::get32(code, off) {
                    Some(v) => v as i32 as i64,
                    None => return false,
                };
                let n = v.wrapping_sub(hdelta);
                if n < i32::MIN as i64 || n > i32::MAX as i64 || !put32(code, off, n as i32 as u32) {
                    return false;
                }
            }
            _ => return false,
        }
    }
    meta::relocate_block(code, delta)
}
