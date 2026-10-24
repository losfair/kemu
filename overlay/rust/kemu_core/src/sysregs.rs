// SPDX-License-Identifier: GPL-2.0
//! Emulated AArch64 ID/system registers and HWCAP bits.

// Linux arm64 uapi HWCAP bit positions.
pub const HWCAP_FP: u64 = 1 << 0;
pub const HWCAP_ASIMD: u64 = 1 << 1;
pub const HWCAP_AES: u64 = 1 << 3;
pub const HWCAP_PMULL: u64 = 1 << 4;
pub const HWCAP_SHA1: u64 = 1 << 5;
pub const HWCAP_SHA2: u64 = 1 << 6;
pub const HWCAP_CRC32: u64 = 1 << 7;
pub const HWCAP_ATOMICS: u64 = 1 << 8;
pub const HWCAP_CPUID: u64 = 1 << 11;
pub const HWCAP_ASIMDRDM: u64 = 1 << 12;
pub const HWCAP_JSCVT: u64 = 1 << 13;
pub const HWCAP_LRCPC: u64 = 1 << 15;
pub const HWCAP_DCPOP: u64 = 1 << 16;
pub const HWCAP_ASIMDDP: u64 = 1 << 20;
pub const HWCAP_FLAGM: u64 = 1 << 23;
pub const HWCAP_SB: u64 = 1 << 29;
pub const HWCAP_ILRCPC: u64 = 1 << 26;

pub const HWCAP2_DCPODP: u64 = 1 << 0;
pub const HWCAP2_FLAGM2: u64 = 1 << 2;
pub const HWCAP2_FRINT: u64 = 1 << 3;
pub const HWCAP2_RNG: u64 = 1 << 16;

pub const HWCAP: u64 = HWCAP_FP
    | HWCAP_ASIMD
    | HWCAP_AES
    | HWCAP_PMULL
    | HWCAP_SHA1
    | HWCAP_SHA2
    | HWCAP_CRC32
    | HWCAP_ATOMICS
    | HWCAP_CPUID
    | HWCAP_ASIMDRDM
    | HWCAP_JSCVT
    | HWCAP_LRCPC
    | HWCAP_DCPOP
    | HWCAP_ASIMDDP
    | HWCAP_ILRCPC
    | HWCAP_FLAGM
    | HWCAP_SB;

pub const HWCAP2: u64 = HWCAP2_DCPODP | HWCAP2_FLAGM2 | HWCAP2_FRINT | HWCAP2_RNG;

/// CTR_EL0: DIC=0, IDC=1, DminLine=IminLine=4 (16 words = 64 bytes),
/// L1Ip=0b11 (PIPT), ERG/CWG = 4.
pub const CTR_EL0: u64 = {
    let idc = 1u64 << 28;
    let dic = 0u64 << 29;
    let cwg = 4u64 << 24;
    let erg = 4u64 << 20;
    let dmin = 4u64 << 16;
    let l1ip = 0b11u64 << 14;
    let imin = 4u64;
    idc | dic | cwg | erg | dmin | l1ip | imin
};

/// DCZID_EL0: block size 2^4 words = 64 bytes, DZP=0 (permitted).
pub const DCZID_EL0: u64 = 4;

pub const MIDR_EL1: u64 = 0x0000_0000; // implementer 0 (software)
pub const MPIDR_EL1: u64 = 0x8000_0000;
pub const REVIDR_EL1: u64 = 0;

// Sanitized ID registers matching the advertised feature set. Fields not
// listed here are zero (feature absent).
pub const ID_AA64PFR0_EL1: u64 = {
    // FP=0, AdvSIMD=0 (0 means "implemented, no fp16"), EL0/EL1=1 (AArch64 only)
    0x0000_0000_0000_0011
};
pub const ID_AA64PFR1_EL1: u64 = 0;
pub const ID_AA64ZFR0_EL1: u64 = 0;
pub const ID_AA64ISAR0_EL1: u64 = {
    // AES=2(PMULL), SHA1=1, SHA2=1, CRC32=1, Atomic=2(LSE), RDM=1, SHA3=0,
    // SM3/4=0, DP=1, FHM=0, TS=2(FLAGM2), RNDR=1
    let aes = 2u64 << 4;
    let sha1 = 1u64 << 8;
    let sha2 = 1u64 << 12;
    let crc = 1u64 << 16;
    let atomic = 2u64 << 20;
    let rdm = 1u64 << 28;
    let dp = 1u64 << 44;
    let ts = 2u64 << 52;
    let rndr = 1u64 << 60;
    aes | sha1 | sha2 | crc | atomic | rdm | dp | ts | rndr
};
pub const ID_AA64ISAR1_EL1: u64 = {
    // DPB=2 (DCPODP), JSCVT=1, LRCPC=2 (ILRCPC)
    let dpb = 2u64 << 0;
    let jscvt = 1u64 << 12;
    let lrcpc = 2u64 << 20;
    dpb | jscvt | lrcpc
};
pub const ID_AA64ISAR2_EL1: u64 = 0;
pub const ID_AA64MMFR0_EL1: u64 = {
    // PARange=2 (40-bit), 4KB granule supported (TGran4=0), 64KB (TGran64=0)
    0x0000_0000_0000_0002
};
pub const ID_AA64MMFR1_EL1: u64 = 0;
pub const ID_AA64MMFR2_EL1: u64 = 0;
pub const ID_AA64DFR0_EL1: u64 = {
    // DebugVer=6 (ARMv8), minimal
    0x0000_0000_0000_0006
};
pub const ID_AA64DFR1_EL1: u64 = 0;
pub const ID_AA64AFR0_EL1: u64 = 0;
pub const ID_AA64AFR1_EL1: u64 = 0;
