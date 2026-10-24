// SPDX-License-Identifier: GPL-2.0
//! AArch64 A64 instruction decoder.
//!
//! `decode(u32) -> Insn` produces a structured, `Copy` enum describing one
//! instruction. The enum is grouped by operation class with explicit operand
//! fields so that both the interpreter and the (future) x86 JIT can consume
//! it without re-parsing bits. Any unallocated or unsupported encoding
//! decodes to `Insn::Undefined`. HINT-space instructions that the advertised
//! CPU treats as NOPs decode to `Insn::Nop`.
//!
//! Register number 31 is left as-is in the fields; consumers apply XZR vs SP
//! semantics per the field's documented meaning.

/// Index/writeback mode for scalar and SIMD loads and stores.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Index {
    /// `[Xn, #imm]` with no writeback.
    Unsigned,
    /// Signed offset, no writeback (`[Xn, #imm]`, LDUR-style).
    Signed,
    /// `[Xn], #imm` — base updated after the access.
    Post,
    /// `[Xn, #imm]!` — base updated before the access.
    Pre,
}

/// Extend/shift option for register-offset addressing and extended ALU ops.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ext {
    Uxtb,
    Uxth,
    Uxtw,
    Uxtx,
    Sxtb,
    Sxth,
    Sxtw,
    Sxtx,
}

impl Ext {
    pub const fn from_option(o: u32) -> Ext {
        match o & 7 {
            0 => Ext::Uxtb,
            1 => Ext::Uxth,
            2 => Ext::Uxtw,
            3 => Ext::Uxtx,
            4 => Ext::Sxtb,
            5 => Ext::Sxth,
            6 => Ext::Sxtw,
            _ => Ext::Sxtx,
        }
    }
    /// True for the signed extensions.
    pub const fn signed(self) -> bool {
        matches!(self, Ext::Sxtb | Ext::Sxth | Ext::Sxtw | Ext::Sxtx)
    }
    /// Source width in bits before extension.
    pub const fn src_bits(self) -> u32 {
        match self {
            Ext::Uxtb | Ext::Sxtb => 8,
            Ext::Uxth | Ext::Sxth => 16,
            Ext::Uxtw | Ext::Sxtw => 32,
            Ext::Uxtx | Ext::Sxtx => 64,
        }
    }
}

/// Shift type for shifted-register ALU ops.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Shift {
    Lsl,
    Lsr,
    Asr,
    Ror,
}

impl Shift {
    pub const fn from2(s: u32) -> Shift {
        match s & 3 {
            0 => Shift::Lsl,
            1 => Shift::Lsr,
            2 => Shift::Asr,
            _ => Shift::Ror,
        }
    }
}

/// Memory ordering attached to a load or store.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Order {
    None,
    /// Load-Acquire / Store-Release (LDAR/STLR, acquire/release exclusives).
    AcqRel,
    /// LDAPR / LDAPUR (RCpc acquire).
    AcqPc,
}

/// Size of a scalar memory access / data operation, in log2 bytes.
pub type Sz = u8;

/// LSE read-modify-write operation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RmwOp {
    Add,
    Clr,
    Eor,
    Set,
    Smax,
    Smin,
    Umax,
    Umin,
    Swp,
}

/// ALU operation for the logical class.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LogicOp {
    And,
    Orr,
    Eor,
    Ands,
}

/// Bitfield operation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BfOp {
    Signed,
    Unsigned,
    Insert,
}

/// Conditional-select kind.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CselOp {
    /// CSEL
    Csel,
    /// CSINC (rd = cond ? rn : rm+1)
    Csinc,
    /// CSINV
    Csinv,
    /// CSNEG
    Csneg,
}

/// Data-processing (1 source) integer op.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dp1Op {
    Rbit,
    Rev16,
    Rev32,
    Rev,
    Clz,
    Cls,
}

/// Data-processing (2 source) integer op.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dp2Op {
    Udiv,
    Sdiv,
    Lslv,
    Lsrv,
    Asrv,
    Rorv,
    Crc32,
    Crc32c,
}

/// Multiply-accumulate class (3 source).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MulOp {
    Madd,
    Msub,
    Smaddl,
    Smsubl,
    Umaddl,
    Umsubl,
    Smulh,
    Umulh,
}

/// Floating-point data-processing (1 source).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fp1Op {
    Mov,
    Abs,
    Neg,
    Sqrt,
    RintN,
    RintP,
    RintM,
    RintZ,
    RintA,
    RintX,
    RintI,
    Rint32Z,
    Rint32X,
    Rint64Z,
    Rint64X,
    Recpx,
    /// Convert to another precision (ftype in `to`).
    Cvt,
}

/// Floating-point data-processing (2 source).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fp2Op {
    Mul,
    Div,
    Add,
    Sub,
    Max,
    Min,
    MaxNm,
    MinNm,
    Nmul,
}

/// Floating-point/integer conversion direction and kind.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FcvtOp {
    /// FCVT{N,P,M,Z,A}{S,U}: FP -> int, named rounding.
    FtoI { round: u8, unsigned: bool },
    /// SCVTF/UCVTF: int -> FP.
    ItoF { unsigned: bool },
    /// FCVTZS/U with explicit fbits (fixed-point FP->int).
    FtoFixed { unsigned: bool, fbits: u32 },
    /// {S,U}CVTF fixed-point int->FP.
    FixedToF { unsigned: bool, fbits: u32 },
    /// FMOV between register and FP (no conversion). `to_fp` chooses dir.
    Fmov { to_fp: bool, top: bool },
    /// FJCVTZS.
    Fjcvt,
}

/// A decoded NEON/scalar-SIMD arrangement.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Arr {
    /// Element size, log2 bytes (0=B,1=H,2=S,3=D).
    pub size: u8,
    /// True = 128-bit (16-byte) vector, false = 64-bit.
    pub q: bool,
}

impl Arr {
    #[inline]
    pub const fn lanes(self) -> u32 {
        let bytes = if self.q { 16 } else { 8 };
        bytes >> self.size
    }
}

/// SIMD three-same / three-different operation selector. Kept as the raw
/// decoded opcode plus a semantic tag the interpreter and JIT switch on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SimdOp {
    // Integer three-same
    Add,
    Sub,
    AddP,
    And,
    Bic,
    Orr,
    Orn,
    Eor,
    Bsl,
    Bit,
    Bif,
    CmEq,
    CmGe,
    CmGt,
    CmHi,
    CmHs,
    CmTst,
    Mul,
    Mla,
    Mls,
    SMax,
    SMin,
    UMax,
    UMin,
    SMaxP,
    SMinP,
    UMaxP,
    UMinP,
    SAbd,
    UAbd,
    SAba,
    UAba,
    SHAdd,
    UHAdd,
    SHSub,
    UHSub,
    SRHAdd,
    URHAdd,
    SQAdd,
    UQAdd,
    SQSub,
    UQSub,
    SShl,
    UShl,
    SRShl,
    URShl,
    SQShl,
    UQShl,
    SQRShl,
    UQRShl,
    SQDMulh,
    SQRDMulh,
    SQRDMlah,
    SQRDMlsh,
    SQDMull,
    SQDMull2,
    PMul,
    // FP three-same
    FAdd,
    FSub,
    FMul,
    FDiv,
    FMla,
    FMls,
    FAbd,
    FMax,
    FMin,
    FMaxNm,
    FMinNm,
    FMaxP,
    FMinP,
    FMaxNmP,
    FMinNmP,
    FAddP,
    FMulx,
    FCmEq,
    FCmGe,
    FCmGt,
    FRecps,
    FRsqrts,
    FAcGe,
    FAcGt,
    // Dot product
    SDot,
    UDot,
    // Three-different (widening) integer ops
    SAddL,
    SAddL2,
    UAddL,
    UAddL2,
    SSubL,
    SSubL2,
    USubL,
    USubL2,
    SAddW,
    SAddW2,
    UAddW,
    UAddW2,
    SSubW,
    SSubW2,
    USubW,
    USubW2,
    AddHn,
    AddHn2,
    SubHn,
    SubHn2,
    RAddHn,
    RAddHn2,
    RSubHn,
    RSubHn2,
    SAbaL,
    SAbaL2,
    UAbaL,
    UAbaL2,
    SAbdL,
    SAbdL2,
    UAbdL,
    UAbdL2,
    SMlaL,
    SMlaL2,
    UMlaL,
    UMlaL2,
    SMlsL,
    SMlsL2,
    UMlsL,
    UMlsL2,
    SMullL,
    SMullL2,
    UMullL,
    UMullL2,
    PMull,
    PMull2,
    SQDMlaL,
    SQDMlaL2,
    SQDMlsL,
    SQDMlsL2,
}

/// SIMD two-register-miscellaneous operation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Simd2Op {
    Rev64,
    Rev32,
    Rev16,
    Cnt,
    NotOrRbit, // U selects: 0=NOT, 1=RBIT (handled by interp via U flag)
    Not,
    Rbit,
    Cls,
    Clz,
    Abs,
    Neg,
    SqAbs,
    SqNeg,
    SuqAdd,
    UsqAdd,
    CmEq0,
    CmGe0,
    CmGt0,
    CmLe0,
    CmLt0,
    FCmEq0,
    FCmGe0,
    FCmGt0,
    FCmLe0,
    FCmLt0,
    Xtn,
    Xtn2,
    SqXtn,
    SqXtn2,
    UqXtn,
    UqXtn2,
    SqXtun,
    SqXtun2,
    Shll,
    Shll2,
    Fabs,
    Fneg,
    Fsqrt,
    FrintN,
    FrintP,
    FrintM,
    FrintZ,
    FrintA,
    FrintX,
    FrintI,
    Frint32Z,
    Frint32X,
    Frint64Z,
    Frint64X,
    FcvtN,
    FcvtN2,
    FcvtL,
    FcvtL2,
    FcvtXn,
    FcvtXn2,
    Fcvtns,
    Fcvtnu,
    Fcvtps,
    Fcvtpu,
    Fcvtms,
    Fcvtmu,
    Fcvtzs,
    Fcvtzu,
    Fcvtas,
    Fcvtau,
    Scvtf,
    Ucvtf,
    Frecpe,
    Frsqrte,
    Frecpx,
    Fcvtl16,
    Urecpe,
    Ursqrte,
    SaddLp,
    UaddLp,
    SadaLp,
    UadaLp,
}

/// Across-lanes reduction.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AcrossOp {
    SAddLV,
    UAddLV,
    AddV,
    SMaxV,
    SMinV,
    UMaxV,
    UMinV,
    FMaxV,
    FMinV,
    FMaxNmV,
    FMinNmV,
}

/// The decoded instruction.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Insn {
    Undefined,
    /// NOP and NOP-like HINTs (yield/wfe/pac/bti/...).
    Nop,
    /// SVC #imm (we only honour #0, but carry the imm).
    Svc { imm: u16 },
    /// BRK #imm.
    Brk { imm: u16 },
    /// HLT #imm (treated as Undefined by interp, carried for completeness).
    Hlt { imm: u16 },

    // --- barriers / sync ---
    Dmb,
    Dsb,
    Isb,
    Clrex,
    Sb,

    // --- PC-relative ---
    Adr { rd: u32, imm: i64 },
    Adrp { rd: u32, imm: i64 },

    // --- add/sub immediate (rd/rn are SP-encoded) ---
    AddSubImm { sf: bool, sub: bool, setflags: bool, rd: u32, rn: u32, imm: u64 },
    // --- logical immediate (rd is SP-encoded unless setflags) ---
    LogicImm { sf: bool, op: LogicOp, rd: u32, rn: u32, imm: u64 },
    // --- move wide immediate ---
    MovN { sf: bool, rd: u32, imm: u64 },
    MovZ { sf: bool, rd: u32, imm: u64 },
    MovK { sf: bool, rd: u32, shift: u32, imm16: u64 },
    // --- bitfield / extract ---
    Bitfield { sf: bool, op: BfOp, rd: u32, rn: u32, immr: u32, imms: u32 },
    Extr { sf: bool, rd: u32, rn: u32, rm: u32, lsb: u32 },

    // --- add/sub shifted & extended register ---
    AddSubShift { sf: bool, sub: bool, setflags: bool, shift: Shift, amount: u32, rd: u32, rn: u32, rm: u32 },
    AddSubExt { sf: bool, sub: bool, setflags: bool, ext: Ext, amount: u32, rd: u32, rn: u32, rm: u32 },
    // --- logical shifted register ---
    LogicShift { sf: bool, op: LogicOp, negate: bool, shift: Shift, amount: u32, rd: u32, rn: u32, rm: u32 },
    // --- add/sub with carry ---
    AddSubCarry { sf: bool, sub: bool, setflags: bool, rd: u32, rn: u32, rm: u32 },
    Rmif { rn: u32, lsb: u32, mask: u32 },
    SetfFlags { sz: u8, rn: u32 },
    // --- conditional compare ---
    CondCmp { sf: bool, sub: bool, reg: bool, rn: u32, imm_or_rm: u32, nzcv: u32, cond: u32 },
    // --- conditional select ---
    CondSel { sf: bool, op: CselOp, rd: u32, rn: u32, rm: u32, cond: u32 },
    // --- data processing 1/2/3 source ---
    Dp1 { sf: bool, op: Dp1Op, rd: u32, rn: u32 },
    Dp2 { sf: bool, op: Dp2Op, rd: u32, rn: u32, rm: u32, crc_sz: u8 },
    Mul { op: MulOp, rd: u32, rn: u32, rm: u32, ra: u32 },

    // --- branches ---
    B { imm: i64 },
    Bl { imm: i64 },
    BCond { cond: u32, imm: i64 },
    Cbz { sf: bool, nz: bool, rt: u32, imm: i64 },
    Tbz { bit: u32, nz: bool, rt: u32, imm: i64 },
    Br { rn: u32 },
    Blr { rn: u32 },
    Ret { rn: u32 },

    // --- loads/stores: scalar integer ---
    /// Load/store register. `fp` selects the SIMD&FP register file.
    /// `sign_ext` != 0 means load-signed to a sf==(sign_ext==64) dest.
    LdSt {
        load: bool,
        fp: bool,
        size: Sz,
        sign_ext: u8, // 0 = none/zero-ext, 32 or 64 = signed to that width
        index: Index,
        order: Order,
        rt: u32,
        rn: u32,
        offset: i64,
    },
    /// PC-relative literal load.
    LdStLiteral { fp: bool, size: Sz, sign_ext: u8, rt: u32, imm: i64 },
    /// Register-offset load/store.
    LdStReg {
        load: bool,
        fp: bool,
        size: Sz,
        sign_ext: u8,
        ext: Ext,
        shift: u32,
        rt: u32,
        rn: u32,
        rm: u32,
    },
    /// Load/store pair.
    LdStPair {
        load: bool,
        fp: bool,
        size: Sz,     // log2 element bytes
        signed: bool, // LDPSW
        index: Index,
        no_alloc: bool,
        rt: u32,
        rt2: u32,
        rn: u32,
        offset: i64,
    },
    /// Exclusive load/store (and acquire/release variants).
    LdStExcl {
        load: bool,
        pair: bool,
        size: Sz,
        order: Order,
        rs: u32, // status reg for stores
        rt: u32,
        rt2: u32,
        rn: u32,
    },
    /// LSE atomic read-modify-write.
    Atomic {
        op: RmwOp,
        size: Sz,
        acquire: bool,
        release: bool,
        rs: u32,
        rt: u32,
        rn: u32,
    },
    /// LSE compare-and-swap.
    Cas {
        pair: bool,
        size: Sz,
        acquire: bool,
        release: bool,
        rs: u32,
        rt: u32,
        rn: u32,
    },

    // --- cache / address maintenance ---
    DcZva { rt: u32 },
    IcIvau { rt: u32 },
    /// DC CVAU/CVAC/CVAP/CVADP/CIVAC and IC: treated as NOP by interp.
    CacheNop,
    Prfm, // treated as NOP

    // --- system register ---
    Mrs { rt: u32, enc: u32 },
    MsrReg { rt: u32, enc: u32 },
    MsrImm { op: u32, crm: u32 }, // MSR to PSTATE field (DAIFSet etc.) -> mostly NOP

    // === Floating point (scalar) ===
    FpImm { ftype: u8, rd: u32, imm8: u8 },
    FpCmp { ftype: u8, rn: u32, rm: u32, zero: bool, signal: bool },
    FpCCmp { ftype: u8, rn: u32, rm: u32, nzcv: u32, cond: u32, signal: bool },
    FpCSel { ftype: u8, rd: u32, rn: u32, rm: u32, cond: u32 },
    Fp1 { ftype: u8, op: Fp1Op, to: u8, rd: u32, rn: u32 },
    Fp2 { ftype: u8, op: Fp2Op, rd: u32, rn: u32, rm: u32 },
    Fp3 { ftype: u8, neg: bool, sub: bool, rd: u32, rn: u32, rm: u32, ra: u32 },
    FpCvt { ftype: u8, sf: bool, op: FcvtOp, rd: u32, rn: u32 },

    // === Advanced SIMD ===
    SimdThree { q: bool, u: bool, size: u8, op: SimdOp, rd: u32, rn: u32, rm: u32, scalar: bool },
    SimdMisc { q: bool, u: bool, size: u8, op: Simd2Op, rd: u32, rn: u32, scalar: bool },
    SimdAcross { q: bool, size: u8, op: AcrossOp, rd: u32, rn: u32 },
    SimdDup { q: bool, imm5: u32, rd: u32, rn: u32, from_gpr: bool },
    SimdInsElt { imm5: u32, imm4: u32, rd: u32, rn: u32 },
    SimdInsGpr { imm5: u32, rd: u32, rn: u32 },
    SimdUmov { q: bool, imm5: u32, rd: u32, rn: u32 },
    SimdSmov { q: bool, imm5: u32, rd: u32, rn: u32 },
    SimdModImm { q: bool, op: u8, cmode: u8, rd: u32, imm: u64, fp: bool },
    SimdShift { q: bool, u: bool, immh: u32, immb: u32, opcode: u8, rd: u32, rn: u32, scalar: bool },
    SimdExt { q: bool, imm4: u32, rd: u32, rn: u32, rm: u32 },
    SimdPermute { q: bool, size: u8, opcode: u8, rd: u32, rn: u32, rm: u32 },
    SimdTbl { q: bool, len: u8, tbx: bool, rd: u32, rn: u32, rm: u32 },
    SimdIndexed { q: bool, u: bool, size: u8, opcode: u8, rd: u32, rn: u32, rm: u32, index: u32, scalar: bool },
    SimdScalarCopy { imm5: u32, rd: u32, rn: u32 }, // scalar DUP (element)
    SimdLdSt {
        load: bool,
        q: bool,
        size: u8,
        opcode: u8,
        rt: u32,
        rn: u32,
        rm: u32,  // 31 = no register post-index, 32-encoded otherwise
        single: bool,
        index: u32,
        replicate: bool,
        selem: u8,
        post: bool,
    },
    Aese { rd: u32, rn: u32 },
    Aesd { rd: u32, rn: u32 },
    Aesmc { rd: u32, rn: u32 },
    Aesimc { rd: u32, rn: u32 },
    Sha1 { op: u8, rd: u32, rn: u32, rm: u32 },
    Sha256 { op: u8, rd: u32, rn: u32, rm: u32 },
}

#[inline]
const fn bit(x: u32, n: u32) -> bool {
    (x >> n) & 1 != 0
}
#[inline]
const fn bits(x: u32, hi: u32, lo: u32) -> u32 {
    (x >> lo) & ((1 << (hi - lo + 1)) - 1)
}
#[inline]
const fn sx(v: u32, nbits: u32) -> i64 {
    let shift = 64 - nbits;
    ((v as i64) << shift) >> shift
}

/// Decode a DecodeBitMasks logical immediate. Returns None if reserved.
pub fn decode_bit_masks(sf: bool, n: u32, imms: u32, immr: u32) -> Option<u64> {
    let combined6 = ((n as u64) << 6) | ((!imms as u64) & 0x3f);
    if combined6 == 0 {
        return None;
    }
    let len = 63 - combined6.leading_zeros();
    if len < 1 || (!sf && n == 1) {
        return None;
    }
    let size = 1u32 << len;
    let levels = size - 1;
    let s = imms & levels;
    let r = immr & levels;
    if s == levels {
        return None;
    }
    let esize = size;
    let welem = mask_lo(s + 1);
    let rotated = ror_within(welem, r, esize);
    let bits = replicate(rotated, esize);
    Some(if sf { bits } else { bits & 0xffff_ffff })
}


#[inline]
fn ror_within(v: u64, r: u32, esize: u32) -> u64 {
    if r == 0 || esize == 0 {
        return v & mask_lo(esize);
    }
    let v = v & mask_lo(esize);
    let r = r % esize;
    if r == 0 {
        v
    } else {
        ((v >> r) | (v << (esize - r))) & mask_lo(esize)
    }
}

#[inline]
fn mask_lo(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

#[inline]
fn replicate(v: u64, esize: u32) -> u64 {
    if esize >= 64 {
        return v;
    }
    let mut r = 0u64;
    let mut i = 0;
    while i < 64 {
        r |= (v & mask_lo(esize)) << i;
        i += esize;
    }
    r
}

/// Expand an 8-bit SIMD modified immediate. Returns (value_per_64bit, is_fp).
/// The caller replicates `value` across the vector as needed.
pub fn adv_simd_expand_imm(op: u8, cmode: u8, imm8: u64) -> (u64, bool) {
    let rep = |b: u64, step: u32| {
        let mut r = 0u64;
        let mut i = 0;
        while i < 64 {
            r |= b << i;
            i += step;
        }
        r
    };
    match cmode >> 1 {
        0b000 | 0b001 | 0b010 | 0b011 => {
            // 32-bit, imm8 << (8*sel)
            let sel = (cmode >> 1) & 3;
            let v = imm8 << (8 * sel as u64);
            (rep(v, 32), false)
        }
        0b100 | 0b101 => {
            let sel = (cmode >> 1) & 1;
            let v = imm8 << (8 * sel as u64);
            (rep(v, 32), false)
        }
        0b110 => {
            // cmode 0b1100: (imm8<<8)|0xff ; 0b1101: (imm8<<16)|0xffff
            let v = if cmode & 1 == 0 {
                (imm8 << 8) | 0xff
            } else {
                (imm8 << 16) | 0xffff
            };
            (rep(v, 32), false)
        }
        0b111 => {
            match (cmode & 1, op) {
                (0, 0) => (rep(imm8, 8), false), // 8-bit replicate
                (1, 0) => {
                    // float32 immediate
                    let a = (imm8 >> 7) & 1;
                    let b = (imm8 >> 6) & 1;
                    let notb = b ^ 1;
                    let cdefgh = imm8 & 0x3f;
                    let mut v = a << 31;
                    v |= notb << 30;
                    v |= (if b == 1 { 0u64 } else { 0x1f }) << 25;
                    v |= cdefgh << 19;
                    (rep(v, 32), true)
                }
                (0, 1) => {
                    // 64-bit: each imm8 bit -> a byte of 0x00/0xff
                    let mut v = 0u64;
                    let mut i = 0;
                    while i < 8 {
                        if (imm8 >> i) & 1 != 0 {
                            v |= 0xffu64 << (i * 8);
                        }
                        i += 1;
                    }
                    (v, false)
                }
                (1, 1) => {
                    // float64 immediate
                    let a = (imm8 >> 7) & 1;
                    let b = (imm8 >> 6) & 1;
                    let notb = b ^ 1;
                    let cdefgh = imm8 & 0x3f;
                    let mut v = a << 63;
                    v |= notb << 62;
                    v |= (if b == 1 { 0u64 } else { 0x1ff }) << 54;
                    v |= cdefgh << 48;
                    (v, true)
                }
                _ => (0, false),
            }
        }
        _ => (0, false),
    }
}


/// Main decode entry.
pub fn decode(x: u32) -> Insn {
    let op0 = bits(x, 28, 25);
    match op0 {
        // Reserved
        0b0000 => Insn::Undefined,
        // Data processing -- immediate
        0b1000 | 0b1001 => decode_dp_imm(x),
        // Branches, exceptions, system
        0b1010 | 0b1011 => decode_branch_sys(x),
        // Loads and stores
        0b0100 | 0b0110 | 0b1100 | 0b1110 => decode_ldst(x),
        // Data processing -- register
        0b0101 | 0b1101 => decode_dp_reg(x),
        // Data processing -- SIMD and FP
        0b0111 | 0b1111 => decode_simd_fp(x),
        _ => Insn::Undefined,
    }
}

fn decode_dp_imm(x: u32) -> Insn {
    let op = bits(x, 25, 23);
    let sf = bit(x, 31);
    let rd = bits(x, 4, 0);
    let rn = bits(x, 9, 5);
    match op {
        0b000 | 0b001 => {
            // PC-rel addressing
            let immlo = bits(x, 30, 29);
            let immhi = bits(x, 23, 5);
            let imm = (immhi << 2) | immlo;
            if bit(x, 31) {
                // ADRP
                let v = sx(imm, 21) << 12;
                Insn::Adrp { rd, imm: v }
            } else {
                Insn::Adr { rd, imm: sx(imm, 21) }
            }
        }
        0b010 => {
            // Add/sub immediate
            let sub = bit(x, 30);
            let setflags = bit(x, 29);
            let sh = bit(x, 22);
            let imm12 = bits(x, 21, 10) as u64;
            if bits(x, 23, 23) != 0 {
                return Insn::Undefined;
            }
            let imm = if sh { imm12 << 12 } else { imm12 };
            Insn::AddSubImm { sf, sub, setflags, rd, rn, imm }
        }
        0b011 => {
            // Add/sub immediate with tags (not advertised) -> Undefined
            Insn::Undefined
        }
        0b100 => {
            // Logical immediate
            let opc = bits(x, 30, 29);
            let n = bits(x, 22, 22);
            let immr = bits(x, 21, 16);
            let imms = bits(x, 15, 10);
            if !sf && n == 1 {
                return Insn::Undefined;
            }
            let imm = match decode_bit_masks(sf, n, imms, immr) {
                Some(v) => v,
                None => return Insn::Undefined,
            };
            let op = match opc {
                0 => LogicOp::And,
                1 => LogicOp::Orr,
                2 => LogicOp::Eor,
                _ => LogicOp::Ands,
            };
            Insn::LogicImm { sf, op, rd, rn, imm }
        }
        0b101 => {
            // Move wide immediate
            let opc = bits(x, 30, 29);
            let hw = bits(x, 22, 21);
            let imm16 = bits(x, 20, 5) as u64;
            if (!sf && hw >= 2) || opc == 1 {
                return Insn::Undefined;
            }
            let shift = hw * 16;
            match opc {
                0 => {
                    let v = !(imm16 << shift);
                    let v = if sf { v } else { v & 0xffff_ffff };
                    Insn::MovN { sf, rd, imm: v }
                }
                2 => Insn::MovZ { sf, rd, imm: imm16 << shift },
                _ => Insn::MovK { sf, rd, shift, imm16 },
            }
        }
        0b110 => {
            // Bitfield
            let opc = bits(x, 30, 29);
            let n = bits(x, 22, 22);
            let immr = bits(x, 21, 16);
            let imms = bits(x, 15, 10);
            if n != (sf as u32) || opc == 3 {
                return Insn::Undefined;
            }
            let op = match opc {
                0 => BfOp::Signed,
                1 => BfOp::Insert,
                _ => BfOp::Unsigned,
            };
            Insn::Bitfield { sf, op, rd, rn, immr, imms }
        }
        0b111 => {
            // Extract
            let op21 = bits(x, 30, 29);
            let n = bits(x, 22, 22);
            let o0 = bits(x, 21, 21);
            let rm = bits(x, 20, 16);
            let imms = bits(x, 15, 10);
            if op21 != 0 || o0 != 0 || n != (sf as u32) || (!sf && imms >= 32) {
                return Insn::Undefined;
            }
            Insn::Extr { sf, rd, rn, rm, lsb: imms }
        }
        _ => Insn::Undefined,
    }
}

fn decode_branch_sys(x: u32) -> Insn {
    let op0 = bits(x, 31, 29);
    let op1 = bits(x, 25, 22);
    if op0 == 0b010 && !bit(x, 25) {
        // Conditional branch immediate
        if bit(x, 24) || bit(x, 4) {
            return Insn::Undefined;
        }
        let cond = bits(x, 3, 0);
        let imm = sx(bits(x, 23, 5), 19) * 4;
        return Insn::BCond { cond, imm };
    }
    if op0 == 0b110 && bit(x, 25) {
        // Unconditional branch (register)
        return decode_br_reg(x);
    }
    if (op0 & 0b011) == 0b000 {
        // Unconditional branch immediate (B/BL)
        let imm = sx(bits(x, 25, 0), 26) * 4;
        return if bit(x, 31) { Insn::Bl { imm } } else { Insn::B { imm } };
    }
    if (op0 & 0b011) == 0b001 {
        // Compare & branch / test & branch
        let sf = bit(x, 31);
        let rt = bits(x, 4, 0);
        if !bit(x, 25) {
            // CBZ/CBNZ
            let nz = bit(x, 24);
            let imm = sx(bits(x, 23, 5), 19) * 4;
            return Insn::Cbz { sf, nz, rt, imm };
        } else {
            // TBZ/TBNZ
            let nz = bit(x, 24);
            let b5 = bit(x, 31) as u32;
            let b40 = bits(x, 23, 19);
            let bitn = (b5 << 5) | b40;
            let imm = sx(bits(x, 18, 5), 14) * 4;
            return Insn::Tbz { bit: bitn, nz, rt, imm };
        }
    }
    if op0 == 0b110 && !bit(x, 25) {
        // Exception generation + system
        if op1 == 0b0100 && bits(x, 23, 22) == 0b00 && bits(x, 21, 12) == 0 {
            // actually handle below
        }
        return decode_sys(x);
    }
    Insn::Undefined
}

fn decode_sys(x: u32) -> Insn {
    // Exception generation
    if bits(x, 31, 24) == 0b1101_0100 {
        let opc = bits(x, 23, 21);
        let imm16 = bits(x, 20, 5) as u16;
        let op2 = bits(x, 4, 2);
        let ll = bits(x, 1, 0);
        if op2 != 0 {
            return Insn::Undefined;
        }
        return match (opc, ll) {
            (0b000, 0b01) => Insn::Svc { imm: imm16 },
            (0b000, 0b10) => Insn::Undefined, // HVC
            (0b000, 0b11) => Insn::Undefined, // SMC
            (0b001, 0b00) => Insn::Brk { imm: imm16 },
            (0b010, 0b00) => Insn::Hlt { imm: imm16 },
            _ => Insn::Undefined,
        };
    }
    // System / hints / barriers (op0=110 1010 0100... )
    let l = bit(x, 21);
    let op0f = bits(x, 20, 19);
    let op1f = bits(x, 18, 16);
    let crn = bits(x, 15, 12);
    let crm = bits(x, 11, 8);
    let op2f = bits(x, 7, 5);
    let rt = bits(x, 4, 0);
    // MSR (immediate) to PSTATE
    if !l && op0f == 0b00 && op1f & 0b100 == 0 && crn == 0b0100 {
        // op1 is actually 3 bits here combined; treat as PSTATE write (NOP-ish)
        return Insn::MsrImm { op: op2f, crm };
    }
    if bits(x, 31, 12) == 0b1101_0101_0000_0011_0010 {
        // HINT / barriers region: crn==0011 handled; here crn==0010 hints
    }
    // Hints: 1101 0101 0000 0011 0010 CRm op2 11111
    if bits(x, 31, 22) == 0b1101_0101_00 && crn == 0b0010 && rt == 0b11111 && !l && op0f == 0 && op1f == 0b011 {
        // NOP, YIELD, WFE, WFI, SEV, SEVL, ESB, CSDB, and hint space (pac/bti)
        return Insn::Nop;
    }
    // Barriers: crn==0011
    if crn == 0b0011 && op0f == 0 && op1f == 0b011 && rt == 0b11111 && !l {
        return match op2f {
            0b010 => Insn::Clrex,
            0b100 => Insn::Dsb,
            0b101 => Insn::Dmb,
            0b110 => Insn::Isb,
            0b111 => Insn::Sb,
            0b001 => Insn::Nop, // SSBB/PSSBB (DSB variants)
            0b000 => Insn::Nop,
            _ => Insn::Nop,
        };
    }
    // DC/IC (sys with L==0) and MRS/MSR register
    // System instructions: op0f (bits 20:19) == 01 -> SYS/SYSL
    let sysop0 = bits(x, 20, 19);
    if sysop0 == 0b01 {
        // SYS / SYSL
        let op1 = bits(x, 18, 16);
        if !l {
            // SYS: DC/IC
            if crn == 0b0111 {
                // DC: crm/op2 select the operation
                if op1 == 0b011 && crm == 0b0100 && op2f == 0b001 {
                    return Insn::DcZva { rt };
                }
                if crn == 0b0111 && crm == 0b0101 && op2f == 0b001 {
                    return Insn::IcIvau { rt };
                }
                // Other DC/IC: NOP for us (clean/invalidate to PoC etc.)
                return Insn::CacheNop;
            }
            return Insn::CacheNop;
        } else {
            // SYSL -> read; treat unsupported as Undefined
            return Insn::Undefined;
        }
    }
    // MRS/MSR (register): op0f bits 20:19 == 10 or 11
    if sysop0 == 0b10 || sysop0 == 0b11 {
        let o0 = if sysop0 == 0b11 { 3 } else { 2 };
        let enc = (o0 << 14) | (op1f << 11) | (crn << 7) | (crm << 3) | op2f;
        if l {
            return Insn::Mrs { rt, enc };
        } else {
            return Insn::MsrReg { rt, enc };
        }
    }
    Insn::Undefined
}

fn decode_br_reg(x: u32) -> Insn {
    let opc = bits(x, 24, 21);
    let op2 = bits(x, 20, 16);
    let op3 = bits(x, 15, 10);
    let rn = bits(x, 9, 5);
    let op4 = bits(x, 4, 0);
    if op2 != 0b11111 {
        return Insn::Undefined;
    }
    match opc {
        0b0000 if op3 == 0 && op4 == 0 => Insn::Br { rn },
        0b0001 if op3 == 0 && op4 == 0 => Insn::Blr { rn },
        0b0010 if op3 == 0 && op4 == 0 => Insn::Ret { rn },
        // RETAA/RETAB/BRAA.. (PAC) not advertised
        0b0100 if rn == 0b11111 && op3 == 0 && op4 == 0 => Insn::Undefined, // ERET
        _ => Insn::Undefined,
    }
}

include!("decode_ldst.rs");
include!("decode_dpreg.rs");
include!("decode_simd.rs");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logical_imm() {
        // AND x0, x0, #0xff  -> ANDS? plain AND: 0x92401c00
        let i = decode(0x92401c00);
        match i {
            Insn::LogicImm { op: LogicOp::And, imm, rd: 0, rn: 0, sf: true } => assert_eq!(imm, 0xff),
            _ => panic!("{:?}", i),
        }
    }

    #[test]
    fn add_imm() {
        // add x1, x2, #1
        let i = decode(0x91000441);
        assert_eq!(i, Insn::AddSubImm { sf: true, sub: false, setflags: false, rd: 1, rn: 2, imm: 1 });
    }

    #[test]
    fn movz_movk() {
        // movz x0, #0x1234
        assert_eq!(decode(0xd2824680), Insn::MovZ { sf: true, rd: 0, imm: 0x1234 });
    }

    #[test]
    fn branch() {
        // b .+8
        assert_eq!(decode(0x14000002), Insn::B { imm: 8 });
        // bl .-4
        assert_eq!(decode(0x97ffffff), Insn::Bl { imm: -4 });
        // ret
        assert_eq!(decode(0xd65f03c0), Insn::Ret { rn: 30 });
    }

    #[test]
    fn ldr_str() {
        // ldr x0, [x1] -> 0xf9400020
        match decode(0xf9400020) {
            Insn::LdSt { load: true, size: 3, rt: 0, rn: 1, offset: 0, fp: false, .. } => {}
            o => panic!("{:?}", o),
        }
    }

    #[test]
    fn nop_and_svc() {
        assert_eq!(decode(0xd503201f), Insn::Nop);
        assert_eq!(decode(0xd4000001), Insn::Svc { imm: 0 });
        assert_eq!(decode(0xd65f03c0), Insn::Ret { rn: 30 });
    }
}
