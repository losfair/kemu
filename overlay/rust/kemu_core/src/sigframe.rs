// SPDX-License-Identifier: GPL-2.0
//! arm64 `struct ucontext` construction and parsing for signal delivery and
//! `rt_sigreturn`. Mirrors arch/arm64/kernel/signal.c.
//!
//! The ucontext buffer is guest-controlled on restore and must be parsed
//! defensively.

use crate::state::CpuState;

pub const UCONTEXT_SIZE: usize = 4560;

const UC_FLAGS: usize = 0;
const UC_LINK: usize = 8;
const UC_SS_SP: usize = 16;
const UC_SS_FLAGS: usize = 24;
const UC_SS_SIZE: usize = 32;
const UC_SIGMASK: usize = 40;
const UC_MCONTEXT: usize = 176;

const SC_FAULT_ADDRESS: usize = UC_MCONTEXT;
const SC_REGS: usize = UC_MCONTEXT + 8;
const SC_SP: usize = UC_MCONTEXT + 256;
const SC_PC: usize = UC_MCONTEXT + 264;
const SC_PSTATE: usize = UC_MCONTEXT + 272;
const SC_RESERVED: usize = UC_MCONTEXT + 288;
const SC_RESERVED_SIZE: usize = 4096;

const FPSIMD_MAGIC: u32 = 0x4650_8001;
const FPSIMD_SIZE: u32 = 528;
const ESR_MAGIC: u32 = 0x4553_5201;
const ESR_SIZE: u32 = 16;

const PSTATE_NZCV: u64 = 0xf000_0000;
const PSR_MODE_MASK: u64 = 0xf;
const PSR_MODE32_BIT: u64 = 0x10;
const PSR_DAIF: u64 = 0x3c0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadFrame;

fn put32(b: &mut [u8], off: usize, v: u32) -> Result<(), BadFrame> {
    let d = b.get_mut(off..off + 4).ok_or(BadFrame)?;
    d.copy_from_slice(&v.to_le_bytes());
    Ok(())
}

fn put64(b: &mut [u8], off: usize, v: u64) -> Result<(), BadFrame> {
    let d = b.get_mut(off..off + 8).ok_or(BadFrame)?;
    d.copy_from_slice(&v.to_le_bytes());
    Ok(())
}

fn get32(b: &[u8], off: usize) -> Result<u32, BadFrame> {
    let s = b.get(off..off + 4).ok_or(BadFrame)?;
    let mut a = [0u8; 4];
    a.copy_from_slice(s);
    Ok(u32::from_le_bytes(a))
}

fn get64(b: &[u8], off: usize) -> Result<u64, BadFrame> {
    let s = b.get(off..off + 8).ok_or(BadFrame)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Ok(u64::from_le_bytes(a))
}

/// Alternate signal stack description saved in `uc_stack`.
#[derive(Clone, Copy)]
pub struct AltStack {
    pub sp: u64,
    pub flags: u32,
    pub size: u64,
}

/// Fill `buf` (which must be zeroed and `UCONTEXT_SIZE` long) with the
/// ucontext for `st`. `esr` is included as an esr_context when non-zero.
pub fn build(
    buf: &mut [u8],
    st: &CpuState,
    sigmask: u64,
    ss: AltStack,
    fault_addr: u64,
    esr: u64,
) -> Result<(), BadFrame> {
    if buf.len() < UCONTEXT_SIZE {
        return Err(BadFrame);
    }
    put64(buf, UC_FLAGS, 0)?;
    put64(buf, UC_LINK, 0)?;
    put64(buf, UC_SS_SP, ss.sp)?;
    put32(buf, UC_SS_FLAGS, ss.flags)?;
    put64(buf, UC_SS_SIZE, ss.size)?;
    put64(buf, UC_SIGMASK, sigmask)?;

    put64(buf, SC_FAULT_ADDRESS, fault_addr)?;
    for (i, r) in st.x.iter().enumerate() {
        put64(buf, SC_REGS + i * 8, *r)?;
    }
    put64(buf, SC_SP, st.sp)?;
    put64(buf, SC_PC, st.pc)?;
    put64(buf, SC_PSTATE, st.nzcv & PSTATE_NZCV)?;

    let mut off = SC_RESERVED;
    put32(buf, off, FPSIMD_MAGIC)?;
    put32(buf, off + 4, FPSIMD_SIZE)?;
    put32(buf, off + 8, st.fpsr)?;
    put32(buf, off + 12, st.fpcr)?;
    for (i, v) in st.v.iter().enumerate() {
        put64(buf, off + 16 + i * 16, v[0])?;
        put64(buf, off + 24 + i * 16, v[1])?;
    }
    off += FPSIMD_SIZE as usize;

    if esr != 0 {
        put32(buf, off, ESR_MAGIC)?;
        put32(buf, off + 4, ESR_SIZE)?;
        put64(buf, off + 8, esr)?;
        off += ESR_SIZE as usize;
    }
    // Terminator.
    put32(buf, off, 0)?;
    put32(buf, off + 4, 0)?;
    Ok(())
}

/// Parse a guest ucontext into `st` (only on success) and return the
/// saved signal mask.
pub fn restore(buf: &[u8], st: &mut CpuState) -> Result<u64, BadFrame> {
    if buf.len() < UCONTEXT_SIZE {
        return Err(BadFrame);
    }
    let mut new = *st;
    let sigmask = get64(buf, UC_SIGMASK)?;
    for i in 0..31 {
        new.x[i] = get64(buf, SC_REGS + i * 8)?;
    }
    new.sp = get64(buf, SC_SP)?;
    new.pc = get64(buf, SC_PC)?;
    let pstate = get64(buf, SC_PSTATE)?;
    if pstate & PSR_MODE_MASK != 0 || pstate & PSR_MODE32_BIT != 0 || pstate & PSR_DAIF != 0 {
        return Err(BadFrame);
    }
    new.nzcv = pstate & PSTATE_NZCV;

    // Walk the record list in __reserved.
    let base = SC_RESERVED;
    let limit = SC_RESERVED_SIZE;
    let mut offset = 0usize;
    let mut fpsimd: Option<usize> = None;
    loop {
        if limit - offset < 8 || offset % 16 != 0 {
            return Err(BadFrame);
        }
        let magic = get32(buf, base + offset)?;
        let size = get32(buf, base + offset + 4)? as usize;
        if limit - offset < size {
            return Err(BadFrame);
        }
        match magic {
            0 => {
                if size != 0 {
                    return Err(BadFrame);
                }
                break;
            }
            FPSIMD_MAGIC => {
                if fpsimd.is_some() || size != FPSIMD_SIZE as usize {
                    return Err(BadFrame);
                }
                fpsimd = Some(base + offset);
            }
            ESR_MAGIC => {}
            _ => return Err(BadFrame),
        }
        if size < 8 {
            return Err(BadFrame);
        }
        offset += size;
    }

    let fp = fpsimd.ok_or(BadFrame)?;
    new.fpsr = get32(buf, fp + 8)?;
    new.fpcr = get32(buf, fp + 12)?;
    for i in 0..32 {
        new.v[i] = [get64(buf, fp + 16 + i * 16)?, get64(buf, fp + 24 + i * 16)?];
    }
    *st = new;
    Ok(sigmask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut st = CpuState::new();
        for i in 0..31 {
            st.x[i] = 0x1000 + i as u64;
        }
        st.sp = 0x7fff_0000;
        st.pc = 0x40_0000;
        st.nzcv = 0x6000_0000;
        st.fpcr = 0x0300_0000;
        st.fpsr = 0x10;
        st.v[3] = [1, 2];
        let mut buf = [0u8; UCONTEXT_SIZE];
        build(&mut buf, &st, 0x55, AltStack { sp: 0, flags: 2, size: 0 }, 0, 0x9200_0047).unwrap();
        let mut out = CpuState::new();
        let mask = restore(&buf, &mut out).unwrap();
        assert_eq!(mask, 0x55);
        assert_eq!(out.x, st.x);
        assert_eq!(out.pc, st.pc);
        assert_eq!(out.nzcv, st.nzcv);
        assert_eq!(out.fpcr, st.fpcr);
        assert_eq!(out.v[3], [1, 2]);
    }

    #[test]
    fn rejects_bad_pstate_and_missing_fpsimd() {
        let st = CpuState::new();
        let mut buf = [0u8; UCONTEXT_SIZE];
        build(&mut buf, &st, 0, AltStack { sp: 0, flags: 0, size: 0 }, 0, 0).unwrap();
        let mut b2 = buf;
        b2[SC_PSTATE] = 0x5; // EL1h
        assert!(restore(&b2, &mut CpuState::new()).is_err());
        let mut b3 = buf;
        b3[SC_RESERVED..SC_RESERVED + 8].fill(0); // terminator first
        assert!(restore(&b3, &mut CpuState::new()).is_err());
    }
}
