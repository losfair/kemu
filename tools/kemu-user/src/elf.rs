// SPDX-License-Identifier: GPL-2.0
//! Minimal AArch64 ELF loader with identity mapping.

use kemu_core::sysregs;
use std::fs;

pub struct Loaded {
    pub entry: u64,
    pub sp: u64,
}

const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_ENTRY: u64 = 9;
const AT_UID: u64 = 11;
const AT_EUID: u64 = 12;
const AT_GID: u64 = 13;
const AT_EGID: u64 = 14;
const AT_HWCAP: u64 = 16;
const AT_CLKTCK: u64 = 17;
const AT_SECURE: u64 = 23;
const AT_RANDOM: u64 = 25;
const AT_HWCAP2: u64 = 26;
const AT_EXECFN: u64 = 31;
const AT_PLATFORM: u64 = 15;

#[inline]
fn rd_u16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
#[inline]
fn rd_u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
#[inline]
fn rd_u64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

struct Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

struct Image {
    phdrs: Vec<Phdr>,
    phoff: u64,
    phentsize: u16,
    phnum: u16,
    entry: u64,
    e_machine: u16,
}

fn parse(bytes: &[u8]) -> Result<Image, String> {
    if bytes.len() < 64 || &bytes[0..4] != b"\x7fELF" {
        return Err("not an ELF".into());
    }
    if bytes[4] != 2 {
        return Err("not ELFCLASS64".into());
    }
    let e_machine = rd_u16(bytes, 18);
    let entry = rd_u64(bytes, 24);
    let phoff = rd_u64(bytes, 32);
    let phentsize = rd_u16(bytes, 54);
    let phnum = rd_u16(bytes, 56);
    let mut phdrs = Vec::new();
    for i in 0..phnum as usize {
        let o = phoff as usize + i * phentsize as usize;
        if o + 56 > bytes.len() {
            return Err("truncated phdr".into());
        }
        phdrs.push(Phdr {
            p_type: rd_u32(bytes, o),
            p_flags: rd_u32(bytes, o + 4),
            p_offset: rd_u64(bytes, o + 8),
            p_vaddr: rd_u64(bytes, o + 16),
            p_filesz: rd_u64(bytes, o + 32),
            p_memsz: rd_u64(bytes, o + 40),
            p_align: rd_u64(bytes, o + 48),
        });
    }
    Ok(Image { phdrs, phoff, phentsize, phnum, entry, e_machine })
}

fn prot(flags: u32) -> i32 {
    let mut p = 0;
    if flags & PF_R != 0 {
        p |= libc::PROT_READ;
    }
    if flags & PF_W != 0 {
        p |= libc::PROT_WRITE;
    }
    if flags & PF_X != 0 {
        // The interpreter never executes guest pages natively, but keeping
        // READ is enough; we drop host-exec here deliberately.
        p |= libc::PROT_READ;
    }
    p
}

const PAGE: u64 = 4096;

fn map_segments(bytes: &[u8], img: &Image, load_bias: u64) -> Result<(u64, u64), String> {
    // Reserve the whole [min_vaddr, max_vaddr] span as one mapping, so that
    // gaps between PT_LOAD segments are backed (a real loader does the same).
    // Reserve to the maximum segment alignment (arm64 ld.so/libc are built for
    // 64 KiB pages and may touch up to the next 64 KiB boundary of a segment).
    let mut lo = u64::MAX;
    let mut hi = 0u64;
    let mut align = PAGE;
    for ph in img.phdrs.iter().filter(|p| p.p_type == PT_LOAD) {
        align = align.max(ph.p_align.max(PAGE));
    }
    for ph in img.phdrs.iter().filter(|p| p.p_type == PT_LOAD) {
        let va = ph.p_vaddr + load_bias;
        lo = lo.min(va & !(align - 1));
        hi = hi.max((va + ph.p_memsz + align - 1) & !(align - 1));
    }
    if lo == u64::MAX {
        return Err("no PT_LOAD segments".into());
    }
    let span = (hi - lo) as usize;
    let addr = unsafe {
        libc::mmap(
            lo as *mut libc::c_void,
            span,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
            -1,
            0,
        )
    };
    if addr == libc::MAP_FAILED || addr as u64 != lo {
        return Err(format!("mmap failed at {:#x}", lo));
    }
    // Copy each segment's file contents into place.
    for ph in img.phdrs.iter().filter(|p| p.p_type == PT_LOAD) {
        let va = ph.p_vaddr + load_bias;
        let foff = ph.p_offset as usize;
        let fsz = ph.p_filesz as usize;
        if fsz > 0 {
            if foff + fsz > bytes.len() {
                return Err("segment past EOF".into());
            }
            unsafe {
                core::ptr::copy_nonoverlapping(bytes[foff..].as_ptr(), va as *mut u8, fsz);
            }
        }
        let _ = prot(ph.p_flags);
    }
    Ok((load_bias, hi))
}

pub fn load(path: &str, args: &[Vec<u8>], envp: &[Vec<u8>]) -> Result<Loaded, String> {
    let bytes = fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    let img = parse(&bytes)?;
    if img.e_machine != 183 {
        return Err(format!("not EM_AARCH64 (e_machine={})", img.e_machine));
    }

    // Static vs PIE: ET_DYN uses a load bias.
    let e_type = rd_u16(&bytes, 16);
    let exec_bias = if e_type == 3 { 0x5555_5555_0000u64 } else { 0 };
    let (_bias, _end) = map_segments(&bytes, &img, exec_bias)?;
    let mut entry = img.entry + exec_bias;
    let phdr_addr = exec_bias
        + img
            .phdrs
            .iter()
            .find(|p| p.p_type == PT_LOAD)
            .map(|p| img.phoff - p.p_offset + p.p_vaddr)
            .unwrap_or(img.phoff);

    // Dynamic interpreter (ld.so) if present.
    let mut interp_base = 0u64;
    let mut at_base = 0u64;
    if let Some(interp_ph) = img.phdrs.iter().find(|p| p.p_type == PT_INTERP) {
        let o = interp_ph.p_offset as usize;
        let sz = interp_ph.p_filesz as usize;
        let interp_path = String::from_utf8_lossy(&bytes[o..o + sz])
            .trim_end_matches('\0')
            .to_string();
        let resolved = resolve_interp(&interp_path);
        let interp_bytes = fs::read(&resolved).map_err(|e| format!("{resolved}: {e}"))?;
        let interp_img = parse(&interp_bytes)?;
        interp_base = 0x6666_0000_0000u64;
        map_segments(&interp_bytes, &interp_img, interp_base)?;
        entry = interp_img.entry + interp_base;
        at_base = interp_base;
    }

    let sp = setup_stack(path, args, envp, phdr_addr, &img, img.entry + exec_bias, at_base)?;
    let _ = interp_base;
    Ok(Loaded { entry, sp })
}

fn setup_stack(
    execfn: &str,
    args: &[Vec<u8>],
    envp: &[Vec<u8>],
    phdr_addr: u64,
    img: &Image,
    real_entry: u64,
    at_base: u64,
) -> Result<u64, String> {
    // Reserve a stack region.
    let stack_size = 8 * 1024 * 1024u64;
    let stack_top = 0x7fff_f000_0000u64;
    let stack_bottom = stack_top - stack_size;
    let addr = unsafe {
        libc::mmap(
            stack_bottom as *mut libc::c_void,
            stack_size as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
            -1,
            0,
        )
    };
    if addr == libc::MAP_FAILED {
        return Err("stack mmap failed".into());
    }

    // Build the auxv/argv/envp block from the top down.
    // Debug aid: shift the initial stack (e.g. to match another
    // emulator's alignment in lockstep traces).
    let adj: u64 = std::env::var("KEMU_STACK_ADJ").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    let mut sp = stack_top - adj;
    let mut push_bytes = |sp: &mut u64, data: &[u8]| -> u64 {
        *sp -= data.len() as u64;
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), *sp as *mut u8, data.len()) };
        *sp
    };

    // String area.
    let platform = push_bytes(&mut sp, b"aarch64\0");
    let execfn_addr = {
        let mut b = execfn.as_bytes().to_vec();
        b.push(0);
        push_bytes(&mut sp, &b)
    };
    let mut rand = [0u8; 16];
    unsafe { libc::getrandom(rand.as_mut_ptr() as *mut _, 16, 0) };
    let random_addr = push_bytes(&mut sp, &rand);

    let mut env_addrs = Vec::new();
    for e in envp.iter() {
        let mut b = e.clone();
        b.push(0);
        env_addrs.push(push_bytes(&mut sp, &b));
    }
    let mut arg_addrs = Vec::new();
    for a in args.iter() {
        let mut b = a.clone();
        b.push(0);
        arg_addrs.push(push_bytes(&mut sp, &b));
    }

    // Align down to 16.
    sp &= !0xfu64;

    // auxv entries (pairs).
    let auxv: Vec<(u64, u64)> = vec![
        (AT_PHDR, phdr_addr),
        (AT_PHENT, img.phentsize as u64),
        (AT_PHNUM, img.phnum as u64),
        (AT_PAGESZ, 4096),
        (AT_BASE, at_base),
        (AT_ENTRY, real_entry),
        (AT_HWCAP, sysregs::HWCAP),
        (AT_HWCAP2, sysregs::HWCAP2),
        (AT_CLKTCK, 100),
        (AT_UID, unsafe { libc::getuid() } as u64),
        (AT_EUID, unsafe { libc::geteuid() } as u64),
        (AT_GID, unsafe { libc::getgid() } as u64),
        (AT_EGID, unsafe { libc::getegid() } as u64),
        (AT_SECURE, 0),
        (AT_RANDOM, random_addr),
        (AT_EXECFN, execfn_addr),
        (AT_PLATFORM, platform),
        (AT_NULL, 0),
    ];

    // Compute total slots to keep final sp 16-aligned.
    let n_argc = 1;
    let n_argv = arg_addrs.len() + 1;
    let n_envp = env_addrs.len() + 1;
    let n_aux = auxv.len() * 2;
    let total = n_argc + n_argv + n_envp + n_aux;
    if total % 2 != 0 {
        sp -= 8;
    }

    let mut push = |sp: &mut u64, v: u64| {
        *sp -= 8;
        unsafe { core::ptr::write(*sp as *mut u64, v) };
    };

    // Push in reverse so the final layout is argc, argv[], 0, envp[], 0, auxv.
    for &(k, v) in auxv.iter().rev() {
        push(&mut sp, v);
        push(&mut sp, k);
    }
    push(&mut sp, 0); // envp terminator
    for &a in env_addrs.iter().rev() {
        push(&mut sp, a);
    }
    push(&mut sp, 0); // argv terminator
    for &a in arg_addrs.iter().rev() {
        push(&mut sp, a);
    }
    push(&mut sp, arg_addrs.len() as u64); // argc

    Ok(sp)
}

/// Apply KEMU_SYSROOT to the PT_INTERP path if the original is missing.
fn resolve_interp(path: &str) -> String {
    if std::path::Path::new(path).exists() {
        return path.to_string();
    }
    if let Ok(root) = std::env::var("KEMU_SYSROOT") {
        let joined = format!("{}{}", root.trim_end_matches('/'), path);
        if std::path::Path::new(&joined).exists() {
            return joined;
        }
    }
    path.to_string()
}
