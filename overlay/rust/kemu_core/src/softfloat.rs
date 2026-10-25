// SPDX-License-Identifier: GPL-2.0
//! Integer-only IEEE 754 arithmetic with exact AArch64 semantics.
//!
//! Follows the Arm ARM pseudocode (FPUnpack, FPRoundBase, FPProcessNaNs,
//! FPAdd, FPMulAdd, FPToFixed, FPRecipEstimate, ...). The kernel builds Rust
//! with soft-float, so no host floating point is used anywhere; values are
//! passed around as raw bit patterns in `u64`.
//!
//! Only FPCR.{AHP, DN, FZ, RMode} are honoured (FZ16 and the trap enables
//! are not implemented by the advertised CPU). Half precision is supported
//! for conversions only.

/// Floating-point formats.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fmt {
    H,
    S,
    D,
}

impl Fmt {
    #[inline]
    pub const fn ebits(self) -> u32 {
        match self {
            Fmt::H => 5,
            Fmt::S => 8,
            Fmt::D => 11,
        }
    }
    #[inline]
    pub const fn fbits(self) -> u32 {
        match self {
            Fmt::H => 10,
            Fmt::S => 23,
            Fmt::D => 52,
        }
    }
    #[inline]
    pub const fn nbits(self) -> u32 {
        match self {
            Fmt::H => 16,
            Fmt::S => 32,
            Fmt::D => 64,
        }
    }
    #[inline]
    const fn bias(self) -> i32 {
        (1 << (self.ebits() - 1)) - 1
    }
    #[inline]
    const fn emax(self) -> u64 {
        (1 << self.ebits()) - 1
    }
    #[inline]
    const fn fmask(self) -> u64 {
        (1 << self.fbits()) - 1
    }
    #[inline]
    pub const fn mask(self) -> u64 {
        if self.nbits() == 64 {
            u64::MAX
        } else {
            (1 << self.nbits()) - 1
        }
    }
    #[inline]
    const fn sign_bit(self) -> u64 {
        1 << (self.nbits() - 1)
    }
    /// Format for a SIMD element size (log2 bytes): 1 = H, 2 = S, 3 = D.
    pub const fn from_size(size: u32) -> Fmt {
        match size {
            1 => Fmt::H,
            2 => Fmt::S,
            _ => Fmt::D,
        }
    }
}

pub const FPCR_AHP: u32 = 1 << 26;
pub const FPCR_DN: u32 = 1 << 25;
pub const FPCR_FZ: u32 = 1 << 24;
pub const FPCR_RMODE_SHIFT: u32 = 22;
/// FPCR bits implemented by kemu (everything else is RES0 / RAZ-WI).
pub const FPCR_MASK: u32 = FPCR_AHP | FPCR_DN | FPCR_FZ | (3 << FPCR_RMODE_SHIFT);

pub const FPSR_IOC: u32 = 1 << 0;
pub const FPSR_DZC: u32 = 1 << 1;
pub const FPSR_OFC: u32 = 1 << 2;
pub const FPSR_UFC: u32 = 1 << 3;
pub const FPSR_IXC: u32 = 1 << 4;
pub const FPSR_IDC: u32 = 1 << 7;
pub const FPSR_QC: u32 = 1 << 27;
/// FPSR bits implemented by kemu.
pub const FPSR_MASK: u32 = FPSR_IOC | FPSR_DZC | FPSR_OFC | FPSR_UFC | FPSR_IXC | FPSR_IDC | FPSR_QC;

/// Rounding modes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Rounding {
    TieEven,
    PosInf,
    NegInf,
    Zero,
    TieAway,
    Odd,
}

impl Rounding {
    /// From an FPCR.RMode / instruction rmode field (0..3).
    #[inline]
    pub const fn from_rmode(r: u32) -> Rounding {
        match r & 3 {
            0 => Rounding::TieEven,
            1 => Rounding::PosInf,
            2 => Rounding::NegInf,
            _ => Rounding::Zero,
        }
    }
}

/// Floating-point control and status, threaded through every operation.
#[derive(Clone, Copy, Debug)]
pub struct FpCtx {
    pub fpcr: u32,
    pub fpsr: u32,
}

impl FpCtx {
    #[inline]
    pub const fn new(fpcr: u32, fpsr: u32) -> Self {
        FpCtx { fpcr, fpsr }
    }
    #[inline]
    fn fz(&self) -> bool {
        self.fpcr & FPCR_FZ != 0
    }
    #[inline]
    fn dn(&self) -> bool {
        self.fpcr & FPCR_DN != 0
    }
    #[inline]
    fn ahp(&self) -> bool {
        self.fpcr & FPCR_AHP != 0
    }
    /// Rounding mode selected by FPCR.RMode.
    #[inline]
    pub fn rmode(&self) -> Rounding {
        Rounding::from_rmode(self.fpcr >> FPCR_RMODE_SHIFT)
    }
    #[inline]
    fn raise(&mut self, flags: u32) {
        self.fpsr |= flags;
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ty {
    Zero,
    Num,
    Inf,
    QNaN,
    SNaN,
}

/// Unpacked operand. For `Num`, value = (-1)^sign * sig * 2^exp.
#[derive(Clone, Copy, Debug)]
struct Un {
    ty: Ty,
    sign: bool,
    exp: i32,
    sig: u64,
}

impl Un {
    #[inline]
    fn is_nan(&self) -> bool {
        matches!(self.ty, Ty::QNaN | Ty::SNaN)
    }
}

#[inline]
fn unpack(c: &mut FpCtx, f: Fmt, x: u64) -> Un {
    let fb = f.fbits();
    let sign = x & f.sign_bit() != 0;
    let e = (x >> fb) & f.emax();
    let frac = x & f.fmask();
    if e == 0 {
        if frac == 0 {
            Un { ty: Ty::Zero, sign, exp: 0, sig: 0 }
        } else if f != Fmt::H && c.fz() {
            c.raise(FPSR_IDC);
            Un { ty: Ty::Zero, sign, exp: 0, sig: 0 }
        } else {
            Un { ty: Ty::Num, sign, exp: 1 - f.bias() - fb as i32, sig: frac }
        }
    } else if e == f.emax() && !(f == Fmt::H && c.ahp()) {
        let ty = if frac == 0 {
            Ty::Inf
        } else if frac >> (fb - 1) & 1 != 0 {
            Ty::QNaN
        } else {
            Ty::SNaN
        };
        Un { ty, sign, exp: 0, sig: 0 }
    } else {
        Un {
            ty: Ty::Num,
            sign,
            exp: e as i32 - f.bias() - fb as i32,
            sig: frac | (1 << fb),
        }
    }
}

/// Classify without side effects (no FZ flushing).
pub fn classify(f: Fmt, x: u64) -> Ty {
    let mut c = FpCtx::new(0, 0);
    unpack(&mut c, f, x).ty
}

#[inline]
pub const fn zero(f: Fmt, sign: bool) -> u64 {
    if sign {
        f.sign_bit()
    } else {
        0
    }
}
#[inline]
pub const fn inf(f: Fmt, sign: bool) -> u64 {
    zero(f, sign) | (f.emax() << f.fbits())
}
#[inline]
pub const fn max_normal(f: Fmt, sign: bool) -> u64 {
    zero(f, sign) | ((f.emax() - 1) << f.fbits()) | f.fmask()
}
#[inline]
pub const fn default_nan(f: Fmt) -> u64 {
    (f.emax() << f.fbits()) | (1 << (f.fbits() - 1))
}
/// +2.0, +1.5, +1.0 and +3.0 in format `f`.
#[inline]
const fn two(f: Fmt, sign: bool) -> u64 {
    zero(f, sign) | (((f.bias() + 1) as u64) << f.fbits())
}
#[inline]
const fn one_point_five(f: Fmt) -> u64 {
    ((f.bias() as u64) << f.fbits()) | (1 << (f.fbits() - 1))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Err {
    Exact,
    Below,
    Half,
    Above,
}

/// Compare the low `sh` bits of `v` with half of 2^sh.
#[inline]
fn rem_class(v: u128, sh: u32) -> Err {
    if sh == 0 {
        return Err::Exact;
    }
    if sh > 128 {
        return if v == 0 { Err::Exact } else { Err::Below };
    }
    let rem = if sh == 128 { v } else { v & ((1u128 << sh) - 1) };
    let half = 1u128 << (sh - 1);
    if rem == 0 {
        Err::Exact
    } else if rem < half {
        Err::Below
    } else if rem == half {
        Err::Half
    } else {
        Err::Above
    }
}

#[inline]
fn shr128(v: u128, sh: u32) -> u128 {
    if sh >= 128 {
        0
    } else {
        v >> sh
    }
}

/// Should the magnitude be incremented, given the rounding error class?
#[inline]
fn round_up(rnd: Rounding, sign: bool, lsb_odd: bool, err: Err) -> bool {
    match rnd {
        Rounding::TieEven => err == Err::Above || (err == Err::Half && lsb_odd),
        Rounding::TieAway => err == Err::Above || err == Err::Half,
        Rounding::PosInf => err != Err::Exact && !sign,
        Rounding::NegInf => err != Err::Exact && sign,
        Rounding::Zero | Rounding::Odd => false,
    }
}

/// FPRoundBase: round (-1)^sign * sig * 2^exp (sig != 0) to format `f`.
fn round(c: &mut FpCtx, f: Fmt, sign: bool, exp: i32, sig: u128, rnd: Rounding) -> u64 {
    if sig == 0 {
        return zero(f, sign);
    }
    let fb = f.fbits() as i32;
    let p = 127 - sig.leading_zeros() as i32;
    let e = exp.saturating_add(p);
    let emin = 1 - f.bias();
    if f != Fmt::H && c.fz() && e < emin {
        c.raise(FPSR_UFC);
        return zero(f, sign);
    }
    let lsb_exp = if e > emin { e } else { emin } - fb;
    let shift = lsb_exp.saturating_sub(exp);
    let (mut mant, err) = if shift <= 0 {
        let l = (-shift) as u32;
        // e - lsb_exp <= fb, so this fits in fb + 1 bits.
        (((sig << l) & u64::MAX as u128) as u64, Err::Exact)
    } else {
        let sh = shift as u32;
        ((shr128(sig, sh) & u64::MAX as u128) as u64, rem_class(sig, sh))
    };
    let tiny = e < emin;
    if tiny && err != Err::Exact {
        c.raise(FPSR_UFC);
    }
    let overflow_to_inf = match rnd {
        Rounding::TieEven | Rounding::TieAway => true,
        Rounding::PosInf => !sign,
        Rounding::NegInf => sign,
        Rounding::Zero | Rounding::Odd => false,
    };
    if round_up(rnd, sign, mant & 1 != 0, err) {
        mant = mant.wrapping_add(1);
    }
    if rnd == Rounding::Odd && err != Err::Exact {
        mant |= 1;
    }
    // Biased exponent of the (possibly rounded-up) result.
    let mut biased: i64 = if mant >> fb != 0 {
        (if e > emin { e } else { emin }) as i64 + f.bias() as i64
    } else {
        0
    };
    if mant >> (fb + 1) != 0 {
        biased += 1;
        mant >>= 1;
    }
    let mut inexact = err != Err::Exact;
    let res;
    if f == Fmt::H && c.ahp() {
        if biased >= (1 << f.ebits()) {
            c.raise(FPSR_IOC);
            return zero(f, sign) | (f.mask() >> 1);
        }
        res = zero(f, sign) | ((biased as u64) << fb) | (mant & f.fmask());
    } else if biased >= f.emax() as i64 {
        res = if overflow_to_inf { inf(f, sign) } else { max_normal(f, sign) };
        c.raise(FPSR_OFC);
        inexact = true;
    } else {
        res = zero(f, sign) | ((biased as u64) << fb) | (mant & f.fmask());
    }
    if inexact {
        c.raise(FPSR_IXC);
    }
    res
}

#[inline]
fn quiet(f: Fmt, x: u64) -> u64 {
    x | (1 << (f.fbits() - 1))
}

/// FPProcessNaN.
fn process_nan(c: &mut FpCtx, f: Fmt, ty: Ty, x: u64) -> u64 {
    if ty == Ty::SNaN {
        c.raise(FPSR_IOC);
    }
    if c.dn() {
        default_nan(f)
    } else {
        quiet(f, x)
    }
}

/// FPProcessNaNs.
fn process_nans(c: &mut FpCtx, f: Fmt, a: &Un, b: &Un, xa: u64, xb: u64) -> Option<u64> {
    if a.ty == Ty::SNaN {
        Some(process_nan(c, f, a.ty, xa))
    } else if b.ty == Ty::SNaN {
        Some(process_nan(c, f, b.ty, xb))
    } else if a.ty == Ty::QNaN {
        Some(process_nan(c, f, a.ty, xa))
    } else if b.ty == Ty::QNaN {
        Some(process_nan(c, f, b.ty, xb))
    } else {
        None
    }
}

/// FPProcessNaNs3.
#[allow(clippy::too_many_arguments)]
fn process_nans3(c: &mut FpCtx, f: Fmt, a: &Un, b: &Un, d: &Un, xa: u64, xb: u64, xd: u64) -> Option<u64> {
    if a.ty == Ty::SNaN {
        Some(process_nan(c, f, a.ty, xa))
    } else if b.ty == Ty::SNaN {
        Some(process_nan(c, f, b.ty, xb))
    } else if d.ty == Ty::SNaN {
        Some(process_nan(c, f, d.ty, xd))
    } else if a.ty == Ty::QNaN {
        Some(process_nan(c, f, a.ty, xa))
    } else if b.ty == Ty::QNaN {
        Some(process_nan(c, f, b.ty, xb))
    } else if d.ty == Ty::QNaN {
        Some(process_nan(c, f, d.ty, xd))
    } else {
        None
    }
}

/// Right shift with jamming (lost bits ORed into bit 0).
#[inline]
fn jam_shr(v: u128, sh: u32) -> u128 {
    if sh == 0 {
        v
    } else if sh >= 128 {
        (v != 0) as u128
    } else {
        (v >> sh) | ((v & ((1u128 << sh) - 1)) != 0) as u128
    }
}

/// Exact (up to jamming far below the rounding point) sum of two signed
/// values. Returns None for an exact zero result.
fn add_exact(sa: bool, ea: i32, ma: u128, sb: bool, eb: i32, mb: u128) -> Option<(bool, i32, u128)> {
    if ma == 0 && mb == 0 {
        return None;
    }
    if mb == 0 {
        return Some((sa, ea, ma));
    }
    if ma == 0 {
        return Some((sb, eb, mb));
    }
    let pa = ea + (127 - ma.leading_zeros() as i32);
    let pb = eb + (127 - mb.leading_zeros() as i32);
    // Place the larger operand's msb at bit 124.
    let top = if pa >= pb { pa } else { pb };
    let target = top - 124;
    let align = |m: u128, e: i32| -> u128 {
        if e >= target {
            m << ((e - target) as u32)
        } else {
            jam_shr(m, (target - e) as u32)
        }
    };
    let xa = align(ma, ea);
    let xb = align(mb, eb);
    if sa == sb {
        Some((sa, target, xa + xb))
    } else if xa > xb {
        Some((sa, target, xa - xb))
    } else if xb > xa {
        Some((sb, target, xb - xa))
    } else {
        None
    }
}

/// Exact-zero sign rule for sums.
#[inline]
fn exact_zero_sign(c: &FpCtx) -> bool {
    c.rmode() == Rounding::NegInf
}

fn add_impl(c: &mut FpCtx, f: Fmt, xa: u64, xb: u64, negate_b: bool) -> u64 {
    let a = unpack(c, f, xa);
    let b = unpack(c, f, xb);
    if let Some(r) = process_nans(c, f, &a, &b, xa, xb) {
        return r;
    }
    let sb = b.sign ^ negate_b;
    let rnd = c.rmode();
    if a.ty == Ty::Inf && b.ty == Ty::Inf && a.sign != sb {
        c.raise(FPSR_IOC);
        default_nan(f)
    } else if (a.ty == Ty::Inf && !a.sign) || (b.ty == Ty::Inf && !sb) {
        inf(f, false)
    } else if (a.ty == Ty::Inf && a.sign) || (b.ty == Ty::Inf && sb) {
        inf(f, true)
    } else if a.ty == Ty::Zero && b.ty == Ty::Zero && a.sign == sb {
        zero(f, a.sign)
    } else {
        match add_exact(a.sign, a.exp, a.sig as u128, sb, b.exp, b.sig as u128) {
            None => zero(f, exact_zero_sign(c)),
            Some((s, e, m)) => round(c, f, s, e, m, rnd),
        }
    }
}

pub fn add(c: &mut FpCtx, f: Fmt, a: u64, b: u64) -> u64 {
    add_impl(c, f, a, b, false)
}

pub fn sub(c: &mut FpCtx, f: Fmt, a: u64, b: u64) -> u64 {
    add_impl(c, f, a, b, true)
}

fn mul_impl(c: &mut FpCtx, f: Fmt, xa: u64, xb: u64, mulx: bool) -> u64 {
    let a = unpack(c, f, xa);
    let b = unpack(c, f, xb);
    if let Some(r) = process_nans(c, f, &a, &b, xa, xb) {
        return r;
    }
    let s = a.sign ^ b.sign;
    if (a.ty == Ty::Inf && b.ty == Ty::Zero) || (a.ty == Ty::Zero && b.ty == Ty::Inf) {
        if mulx {
            two(f, s)
        } else {
            c.raise(FPSR_IOC);
            default_nan(f)
        }
    } else if a.ty == Ty::Inf || b.ty == Ty::Inf {
        inf(f, s)
    } else if a.ty == Ty::Zero || b.ty == Ty::Zero {
        zero(f, s)
    } else {
        let rnd = c.rmode();
        round(c, f, s, a.exp + b.exp, a.sig as u128 * b.sig as u128, rnd)
    }
}

pub fn mul(c: &mut FpCtx, f: Fmt, a: u64, b: u64) -> u64 {
    mul_impl(c, f, a, b, false)
}

/// FMULX.
pub fn mulx(c: &mut FpCtx, f: Fmt, a: u64, b: u64) -> u64 {
    mul_impl(c, f, a, b, true)
}

/// Long division of normalized mantissas: returns (exp, sig) of a/b.
fn div_exact(ma: u64, ea: i32, mb: u64, eb: i32) -> (i32, u128) {
    let la = ma.leading_zeros();
    let lb = mb.leading_zeros();
    // Normalize both so the msb is at bit 62.
    let a = ma << (la - 1);
    let b = mb << (lb - 1);
    let ea = ea - (la as i32 - 1);
    let eb = eb - (lb as i32 - 1);
    let mut q: u64 = 0;
    let mut r = a;
    for _ in 0..64 {
        q <<= 1;
        if r >= b {
            r -= b;
            q |= 1;
        }
        r <<= 1;
    }
    let sig = ((q as u128) << 1) | (r != 0) as u128;
    (ea - eb - 64, sig)
}

pub fn div(c: &mut FpCtx, f: Fmt, xa: u64, xb: u64) -> u64 {
    let a = unpack(c, f, xa);
    let b = unpack(c, f, xb);
    if let Some(r) = process_nans(c, f, &a, &b, xa, xb) {
        return r;
    }
    let s = a.sign ^ b.sign;
    if (a.ty == Ty::Inf && b.ty == Ty::Inf) || (a.ty == Ty::Zero && b.ty == Ty::Zero) {
        c.raise(FPSR_IOC);
        default_nan(f)
    } else if a.ty == Ty::Inf || b.ty == Ty::Zero {
        if a.ty != Ty::Inf {
            c.raise(FPSR_DZC);
        }
        inf(f, s)
    } else if a.ty == Ty::Zero || b.ty == Ty::Inf {
        zero(f, s)
    } else {
        let (e, m) = div_exact(a.sig, a.exp, b.sig, b.exp);
        let rnd = c.rmode();
        round(c, f, s, e, m, rnd)
    }
}

/// Integer square root with remainder indication.
fn isqrt(n: u128) -> (u128, bool) {
    let mut x = n;
    let mut res: u128 = 0;
    let mut bit: u128 = 1 << 126;
    while bit > n {
        bit >>= 2;
    }
    while bit != 0 {
        if x >= res + bit {
            x -= res + bit;
            res = (res >> 1) + bit;
        } else {
            res >>= 1;
        }
        bit >>= 2;
    }
    (res, x != 0)
}

pub fn sqrt(c: &mut FpCtx, f: Fmt, xa: u64) -> u64 {
    let a = unpack(c, f, xa);
    match a.ty {
        Ty::QNaN | Ty::SNaN => process_nan(c, f, a.ty, xa),
        Ty::Zero => zero(f, a.sign),
        Ty::Inf if !a.sign => inf(f, false),
        _ if a.sign => {
            c.raise(FPSR_IOC);
            default_nan(f)
        }
        _ => {
            let mut m = a.sig as u128;
            let mut e = a.exp;
            if e & 1 != 0 {
                m <<= 1;
                e -= 1;
            }
            // Normalise (by an even amount) so the radicand has ~125
            // significant bits; denormal inputs need the larger shift.
            let k = (m.leading_zeros() - 2) & !1;
            let (r, inexact) = isqrt(m << k);
            let sig = (r << 1) | inexact as u128;
            let rnd = c.rmode();
            round(c, f, false, (e - k as i32) / 2 - 1, sig, rnd)
        }
    }
}

/// FPMulAdd(addend, op1, op2) = addend + op1 * op2 with a single rounding.
/// `neg_addend`/`neg_op1` apply FPNeg (a sign flip, also of NaNs) first.
pub fn muladd(c: &mut FpCtx, f: Fmt, addend: u64, op1: u64, op2: u64, neg_addend: bool, neg_op1: bool) -> u64 {
    let xa = if neg_addend { addend ^ f.sign_bit() } else { addend };
    let x1 = if neg_op1 { op1 ^ f.sign_bit() } else { op1 };
    let x2 = op2;
    let a = unpack(c, f, xa);
    let p1 = unpack(c, f, x1);
    let p2 = unpack(c, f, x2);
    let inf1 = p1.ty == Ty::Inf;
    let inf2 = p2.ty == Ty::Inf;
    let zero1 = p1.ty == Ty::Zero;
    let zero2 = p2.ty == Ty::Zero;
    let nan = process_nans3(c, f, &a, &p1, &p2, xa, x1, x2);
    let infzero = (inf1 && zero2) || (zero1 && inf2);
    if a.ty == Ty::QNaN && infzero {
        c.raise(FPSR_IOC);
        return default_nan(f);
    }
    if let Some(r) = nan {
        return r;
    }
    let inf_a = a.ty == Ty::Inf;
    let zero_a = a.ty == Ty::Zero;
    let sp = p1.sign ^ p2.sign;
    let inf_p = inf1 || inf2;
    let zero_p = zero1 || zero2;
    if infzero || (inf_a && inf_p && a.sign != sp) {
        c.raise(FPSR_IOC);
        default_nan(f)
    } else if (inf_a && !a.sign) || (inf_p && !sp) {
        inf(f, false)
    } else if (inf_a && a.sign) || (inf_p && sp) {
        inf(f, true)
    } else if zero_a && zero_p && a.sign == sp {
        zero(f, a.sign)
    } else {
        let (pe, pm) = if zero_p { (0, 0u128) } else { (p1.exp + p2.exp, p1.sig as u128 * p2.sig as u128) };
        let rnd = c.rmode();
        match add_exact(a.sign, a.exp, a.sig as u128, sp, pe, pm) {
            None => zero(f, exact_zero_sign(c)),
            Some((s, e, m)) => round(c, f, s, e, m, rnd),
        }
    }
}

/// FRECPS: 2.0 - op1 * op2 (fused).
pub fn recip_step(c: &mut FpCtx, f: Fmt, xa: u64, xb: u64) -> u64 {
    step_fused(c, f, xa, xb, false)
}

/// FRSQRTS: (3.0 - op1 * op2) / 2 (fused).
pub fn rsqrt_step(c: &mut FpCtx, f: Fmt, xa: u64, xb: u64) -> u64 {
    step_fused(c, f, xa, xb, true)
}

fn step_fused(c: &mut FpCtx, f: Fmt, xa: u64, xb: u64, rsqrt: bool) -> u64 {
    let x1 = xa ^ f.sign_bit();
    let a = unpack(c, f, x1);
    let b = unpack(c, f, xb);
    if let Some(r) = process_nans(c, f, &a, &b, x1, xb) {
        return r;
    }
    if (a.ty == Ty::Inf && b.ty == Ty::Zero) || (a.ty == Ty::Zero && b.ty == Ty::Inf) {
        if rsqrt {
            one_point_five(f)
        } else {
            two(f, false)
        }
    } else if a.ty == Ty::Inf || b.ty == Ty::Inf {
        inf(f, a.sign ^ b.sign)
    } else {
        let sp = a.sign ^ b.sign;
        let (pe, pm) = if a.ty == Ty::Zero || b.ty == Ty::Zero {
            (0, 0u128)
        } else {
            (a.exp + b.exp, a.sig as u128 * b.sig as u128)
        };
        let (ce, cm) = if rsqrt { (0, 3u128) } else { (1, 1u128) };
        let rnd = c.rmode();
        match add_exact(false, ce, cm, sp, pe, pm) {
            None => zero(f, exact_zero_sign(c)),
            Some((s, e, m)) => round(c, f, s, if rsqrt { e - 1 } else { e }, m, rnd),
        }
    }
}

/// Signed value ordering key for non-NaN operands (Zero/Num/Inf).
#[inline]
fn order_key(f: Fmt, u: &Un, x: u64) -> i128 {
    let mag = match u.ty {
        Ty::Zero => 0i128,
        _ => (x & (f.mask() >> 1)) as i128,
    };
    if u.sign {
        -mag
    } else {
        mag
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MinMax {
    Max,
    Min,
}

fn minmax(c: &mut FpCtx, f: Fmt, xa: u64, xb: u64, op: MinMax) -> u64 {
    let a = unpack(c, f, xa);
    let b = unpack(c, f, xb);
    if let Some(r) = process_nans(c, f, &a, &b, xa, xb) {
        return r;
    }
    let ka = order_key(f, &a, xa);
    let kb = order_key(f, &b, xb);
    let pick_a = match op {
        MinMax::Max => ka > kb,
        MinMax::Min => ka < kb,
    };
    let (u, x) = if pick_a { (a, xa) } else { (b, xb) };
    match u.ty {
        Ty::Inf => inf(f, u.sign),
        Ty::Zero => {
            let s = match op {
                MinMax::Max => a.sign && b.sign,
                MinMax::Min => a.sign || b.sign,
            };
            zero(f, s)
        }
        _ => x,
    }
}

pub fn max(c: &mut FpCtx, f: Fmt, a: u64, b: u64) -> u64 {
    minmax(c, f, a, b, MinMax::Max)
}

pub fn min(c: &mut FpCtx, f: Fmt, a: u64, b: u64) -> u64 {
    minmax(c, f, a, b, MinMax::Min)
}

fn minmax_num(c: &mut FpCtx, f: Fmt, mut xa: u64, mut xb: u64, op: MinMax) -> u64 {
    let ta = unpack(c, f, xa).ty;
    let tb = unpack(c, f, xb).ty;
    let repl = inf(f, op == MinMax::Max);
    if ta == Ty::QNaN && tb != Ty::QNaN {
        xa = repl;
    } else if ta != Ty::QNaN && tb == Ty::QNaN {
        xb = repl;
    }
    minmax(c, f, xa, xb, op)
}

pub fn maxnum(c: &mut FpCtx, f: Fmt, a: u64, b: u64) -> u64 {
    minmax_num(c, f, a, b, MinMax::Max)
}

pub fn minnum(c: &mut FpCtx, f: Fmt, a: u64, b: u64) -> u64 {
    minmax_num(c, f, a, b, MinMax::Min)
}

/// FPCompare: returns NZCV in bits 31:28.
pub fn compare(c: &mut FpCtx, f: Fmt, xa: u64, xb: u64, signal_nans: bool) -> u64 {
    let a = unpack(c, f, xa);
    let b = unpack(c, f, xb);
    if a.is_nan() || b.is_nan() {
        if a.ty == Ty::SNaN || b.ty == Ty::SNaN || signal_nans {
            c.raise(FPSR_IOC);
        }
        return 0x3 << 28;
    }
    let ka = order_key(f, &a, xa);
    let kb = order_key(f, &b, xb);
    if ka == kb {
        0x6 << 28
    } else if ka < kb {
        0x8 << 28
    } else {
        0x2 << 28
    }
}

/// Vector comparison kinds (FCMEQ / FCMGE / FCMGT).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CmpOp {
    Eq,
    Ge,
    Gt,
}

/// FPCompareEQ/GE/GT. EQ only signals on SNaNs; GE/GT signal on any NaN.
pub fn compare_op(c: &mut FpCtx, f: Fmt, xa: u64, xb: u64, op: CmpOp) -> bool {
    let a = unpack(c, f, xa);
    let b = unpack(c, f, xb);
    if a.is_nan() || b.is_nan() {
        if op != CmpOp::Eq || a.ty == Ty::SNaN || b.ty == Ty::SNaN {
            c.raise(FPSR_IOC);
        }
        return false;
    }
    let ka = order_key(f, &a, xa);
    let kb = order_key(f, &b, xb);
    match op {
        CmpOp::Eq => ka == kb,
        CmpOp::Ge => ka >= kb,
        CmpOp::Gt => ka > kb,
    }
}

#[inline]
pub fn abs(f: Fmt, x: u64) -> u64 {
    x & (f.mask() >> 1)
}

#[inline]
pub fn neg(f: Fmt, x: u64) -> u64 {
    (x ^ f.sign_bit()) & f.mask()
}

/// Magnitude of a numeric value as integer part and rounding-error class,
/// for value = sig * 2^e. Returns None if the integer part is >= 2^64.
fn int_part(sig: u64, e: i32) -> Option<(u64, Err)> {
    if e >= 0 {
        if e >= 64 || (e > 0 && sig.leading_zeros() < e as u32) {
            return None;
        }
        Some((sig << e, Err::Exact))
    } else {
        let sh = (-(e as i64)) as u32;
        let v = sig as u128;
        let ip = shr128(v, sh) as u64;
        Some((ip, rem_class(v, sh)))
    }
}

/// FPToFixed: convert to a (un)signed integer of `isize` bits with `fbits`
/// fraction bits. Result is zero-extended to u64 (masked to isize bits).
pub fn to_fixed(c: &mut FpCtx, f: Fmt, x: u64, fbits: u32, unsigned: bool, isize: u32, rnd: Rounding) -> u64 {
    let u = unpack(c, f, x);
    let imask: u64 = if isize >= 64 { u64::MAX } else { (1u64 << isize) - 1 };
    let (sign, mag, err, mut overflow) = match u.ty {
        Ty::QNaN | Ty::SNaN => {
            c.raise(FPSR_IOC);
            return 0;
        }
        Ty::Zero => return 0,
        Ty::Inf => (u.sign, 0u64, Err::Exact, true),
        Ty::Num => match int_part(u.sig, u.exp + fbits as i32) {
            None => (u.sign, 0, Err::Exact, true),
            Some((ip, err)) => {
                let up = round_up(rnd, u.sign, ip & 1 != 0, err);
                match ip.checked_add(up as u64) {
                    Some(m) => (u.sign, m, err, false),
                    None => (u.sign, 0, err, true),
                }
            }
        },
    };
    let result;
    if unsigned {
        let max = imask;
        if overflow {
            result = if sign { 0 } else { max };
        } else if sign && mag != 0 {
            overflow = true;
            result = 0;
        } else if mag > max {
            overflow = true;
            result = max;
        } else {
            result = mag;
        }
    } else {
        let max_pos: u64 = imask >> 1;
        let min_mag: u64 = max_pos + 1;
        if overflow {
            result = if sign { min_mag } else { max_pos };
        } else if !sign && mag > max_pos {
            overflow = true;
            result = max_pos;
        } else if sign && mag > min_mag {
            overflow = true;
            result = min_mag;
        } else if sign {
            result = mag.wrapping_neg() & imask;
        } else {
            result = mag;
        }
    }
    if overflow {
        c.raise(FPSR_IOC);
    } else if err != Err::Exact {
        c.raise(FPSR_IXC);
    }
    result & imask
}

/// FixedToFP: `val` holds an `isize`-bit integer (signed or unsigned) with
/// `fbits` fraction bits.
pub fn from_fixed(c: &mut FpCtx, f: Fmt, val: u64, fbits: u32, signed: bool, isize: u32, rnd: Rounding) -> u64 {
    let v = if isize >= 64 { val } else { val & ((1u64 << isize) - 1) };
    let neg = signed && isize > 0 && (v >> (isize - 1)) & 1 != 0;
    let mag = if !neg {
        v
    } else if isize >= 64 {
        v.wrapping_neg()
    } else {
        (1u64 << isize) - v
    };
    if mag == 0 {
        return zero(f, false);
    }
    round(c, f, neg, -(fbits as i32), mag as u128, rnd)
}

/// FPRoundInt (FRINTN/P/M/Z/A/X/I).
pub fn round_int(c: &mut FpCtx, f: Fmt, x: u64, rnd: Rounding, exact: bool) -> u64 {
    let u = unpack(c, f, x);
    match u.ty {
        Ty::QNaN | Ty::SNaN => process_nan(c, f, u.ty, x),
        Ty::Inf => inf(f, u.sign),
        Ty::Zero => zero(f, u.sign),
        Ty::Num => {
            if u.exp >= 0 {
                return x;
            }
            let (ip, err) = match int_part(u.sig, u.exp) {
                Some(v) => v,
                None => return x,
            };
            let mag = ip + round_up(rnd, u.sign, ip & 1 != 0, err) as u64;
            let r = if mag == 0 {
                zero(f, u.sign)
            } else {
                round(c, f, u.sign, 0, mag as u128, Rounding::Zero)
            };
            if err != Err::Exact && exact {
                c.raise(FPSR_IXC);
            }
            r
        }
    }
}

/// FPRoundIntN (FRINT32Z/X, FRINT64Z/X).
pub fn round_int_n(c: &mut FpCtx, f: Fmt, x: u64, rnd: Rounding, intsize: u32) -> u64 {
    let u = unpack(c, f, x);
    let min_val = zero(f, true) | (((f.bias() + intsize as i32 - 1) as u64) << f.fbits());
    match u.ty {
        Ty::QNaN | Ty::SNaN | Ty::Inf => {
            c.raise(FPSR_IOC);
            min_val
        }
        Ty::Zero => zero(f, u.sign),
        Ty::Num => {
            let (ip, err) = match int_part(u.sig, u.exp) {
                Some(v) => v,
                None => {
                    c.raise(FPSR_IOC);
                    return min_val;
                }
            };
            let mag = match ip.checked_add(round_up(rnd, u.sign, ip & 1 != 0, err) as u64) {
                Some(m) => m,
                None => {
                    c.raise(FPSR_IOC);
                    return min_val;
                }
            };
            let lim = 1u64 << (intsize - 1);
            if (!u.sign && mag >= lim) || (u.sign && mag > lim) {
                c.raise(FPSR_IOC);
                return min_val;
            }
            let r = if mag == 0 {
                zero(f, u.sign)
            } else {
                round(c, f, u.sign, 0, mag as u128, Rounding::Zero)
            };
            if err != Err::Exact {
                c.raise(FPSR_IXC);
            }
            r
        }
    }
}

/// FPConvertNaN.
fn convert_nan(from: Fmt, to: Fmt, x: u64) -> u64 {
    let ffb = from.fbits();
    let tfb = to.fbits();
    let sign = x & from.sign_bit() != 0;
    let payload = x & ((1u64 << (ffb - 1)) - 1);
    let p = if tfb >= ffb { payload << (tfb - ffb) } else { payload >> (ffb - tfb) };
    zero(to, sign) | (to.emax() << tfb) | (1 << (tfb - 1)) | p
}

/// FPConvert between formats.
pub fn convert(c: &mut FpCtx, from: Fmt, to: Fmt, x: u64, rnd: Rounding) -> u64 {
    let u = unpack(c, from, x);
    let alt_hp = to == Fmt::H && c.ahp();
    match u.ty {
        Ty::QNaN | Ty::SNaN => {
            let r = if alt_hp {
                zero(to, u.sign)
            } else if c.dn() {
                default_nan(to)
            } else {
                convert_nan(from, to, x)
            };
            if u.ty == Ty::SNaN || alt_hp {
                c.raise(FPSR_IOC);
            }
            r
        }
        Ty::Inf => {
            if alt_hp {
                c.raise(FPSR_IOC);
                zero(to, u.sign) | (to.mask() >> 1)
            } else {
                inf(to, u.sign)
            }
        }
        Ty::Zero => zero(to, u.sign),
        Ty::Num => round(c, to, u.sign, u.exp, u.sig as u128, rnd),
    }
}

/// RecipEstimate(a), 256 <= a < 512.
const fn recip_estimate(a: u64) -> u64 {
    let a = a * 2 + 1;
    let b = (1u64 << 19) / a;
    (b + 1) / 2
}

/// RecipSqrtEstimate(a), 128 <= a < 512.
const fn rsqrt_estimate_exact(a0: u64) -> u64 {
    let a = if a0 < 256 { a0 * 2 + 1 } else { (((a0 >> 1) << 1) + 1) * 2 };
    let mut b: u64 = 512;
    while a * (b + 1) * (b + 1) < (1u64 << 28) {
        b += 1;
    }
    (b + 1) / 2
}

pub(crate) const RSQRT_TABLE: [u16; 384] = {
    let mut t = [0u16; 384];
    let mut i = 0;
    while i < 384 {
        t[i] = rsqrt_estimate_exact(i as u64 + 128) as u16;
        i += 1;
    }
    t
};

/// UnsignedRecipEstimate (URECPE) on a 32-bit element.
pub fn unsigned_recip_estimate(x: u32) -> u32 {
    if x >> 31 == 0 {
        return u32::MAX;
    }
    let est = recip_estimate((x >> 23) as u64);
    ((est & 0x1ff) as u32) << 23
}

/// UnsignedRSqrtEstimate (URSQRTE) on a 32-bit element.
pub fn unsigned_rsqrt_estimate(x: u32) -> u32 {
    if x >> 30 == 0 {
        return u32::MAX;
    }
    let a = (x >> 23) as usize; // 128..511
    let est = match RSQRT_TABLE.get(a.wrapping_sub(128)) {
        Some(v) => *v as u32,
        None => 256,
    };
    (est & 0x1ff) << 23
}

/// FPRecipEstimate (FRECPE) for S and D.
pub fn recip_estimate_fp(c: &mut FpCtx, f: Fmt, x: u64) -> u64 {
    let u = unpack(c, f, x);
    match u.ty {
        Ty::QNaN | Ty::SNaN => return process_nan(c, f, u.ty, x),
        Ty::Inf => return zero(f, u.sign),
        Ty::Zero => {
            c.raise(FPSR_DZC);
            return inf(f, u.sign);
        }
        Ty::Num => {}
    }
    let msb = u.exp + (63 - u.sig.leading_zeros() as i32);
    let (tiny, big) = match f {
        Fmt::S => (msb < -128, msb >= 126),
        _ => (msb < -1024, msb >= 1022),
    };
    if tiny {
        let to_inf = match c.rmode() {
            Rounding::TieEven => true,
            Rounding::PosInf => !u.sign,
            Rounding::NegInf => u.sign,
            _ => false,
        };
        c.raise(FPSR_OFC | FPSR_IXC);
        return if to_inf { inf(f, u.sign) } else { max_normal(f, u.sign) };
    }
    if c.fz() && big {
        c.raise(FPSR_UFC);
        return zero(f, u.sign);
    }
    // Work in double layout: 52-bit fraction.
    let (mut fraction, mut exp): (u64, i64) = match f {
        Fmt::S => ((x & 0x7f_ffff) << 29, ((x >> 23) & 0xff) as i64),
        _ => (x & ((1u64 << 52) - 1), ((x >> 52) & 0x7ff) as i64),
    };
    if exp == 0 {
        if (fraction >> 51) & 1 == 0 {
            exp = -1;
            fraction = (fraction & ((1u64 << 50) - 1)) << 2;
        } else {
            fraction = (fraction & ((1u64 << 51) - 1)) << 1;
        }
    }
    let scaled = (1u64 << 8) | ((fraction >> 44) & 0xff);
    let mut result_exp: i64 = match f {
        Fmt::S => 253 - exp,
        _ => 2045 - exp,
    };
    let est = recip_estimate(scaled);
    let mut fr = (est & 0xff) << 44;
    if result_exp == 0 {
        fr = (1u64 << 51) | (fr >> 1);
    } else if result_exp == -1 {
        fr = (1u64 << 50) | (fr >> 2);
        result_exp = 0;
    }
    let sign = zero(f, u.sign);
    match f {
        Fmt::S => sign | (((result_exp as u64) & 0xff) << 23) | (fr >> 29),
        _ => sign | (((result_exp as u64) & 0x7ff) << 52) | fr,
    }
}

/// FPRSqrtEstimate (FRSQRTE) for S and D.
pub fn rsqrt_estimate_fp(c: &mut FpCtx, f: Fmt, x: u64) -> u64 {
    let u = unpack(c, f, x);
    match u.ty {
        Ty::QNaN | Ty::SNaN => return process_nan(c, f, u.ty, x),
        Ty::Zero => {
            c.raise(FPSR_DZC);
            return inf(f, u.sign);
        }
        _ if u.sign => {
            c.raise(FPSR_IOC);
            return default_nan(f);
        }
        Ty::Inf => return zero(f, false),
        Ty::Num => {}
    }
    let (mut fraction, mut exp): (u64, i64) = match f {
        Fmt::S => ((x & 0x7f_ffff) << 29, ((x >> 23) & 0xff) as i64),
        _ => (x & ((1u64 << 52) - 1), ((x >> 52) & 0x7ff) as i64),
    };
    if exp == 0 {
        // Normalize the denormal (fraction != 0 here).
        while (fraction >> 51) & 1 == 0 {
            fraction <<= 1;
            exp -= 1;
        }
        fraction = (fraction << 1) & ((1u64 << 52) - 1);
    }
    let scaled = if exp & 1 == 0 {
        (1u64 << 8) | ((fraction >> 44) & 0xff)
    } else {
        (1u64 << 7) | ((fraction >> 45) & 0x7f)
    };
    let result_exp: i64 = match f {
        Fmt::S => (380 - exp).div_euclid(2),
        _ => (3068 - exp).div_euclid(2),
    };
    let est = match RSQRT_TABLE.get((scaled - 128) as usize) {
        Some(v) => *v as u64,
        None => 256,
    };
    match f {
        Fmt::S => (((result_exp as u64) & 0xff) << 23) | ((est & 0xff) << 15),
        _ => (((result_exp as u64) & 0x7ff) << 52) | ((est & 0xff) << 44),
    }
}

/// FRECPX.
pub fn recpx(c: &mut FpCtx, f: Fmt, x: u64) -> u64 {
    let u = unpack(c, f, x);
    if u.is_nan() {
        return process_nan(c, f, u.ty, x);
    }
    let fb = f.fbits();
    let e = (x >> fb) & f.emax();
    let s = zero(f, u.sign);
    if e == 0 {
        s | ((f.emax() - 1) << fb)
    } else {
        s | ((!e & f.emax()) << fb)
    }
}

/// FJCVTZS: returns (result, Z flag).
pub fn fjcvtzs(c: &mut FpCtx, x: u64) -> (u32, bool) {
    let f = Fmt::D;
    let u = unpack(c, f, x);
    let mut z = true;
    match u.ty {
        Ty::QNaN | Ty::SNaN => {
            c.raise(FPSR_IOC);
            return (0, false);
        }
        Ty::Inf => {
            c.raise(FPSR_IOC);
            return (0, false);
        }
        Ty::Zero => {
            // Negative zero, or a denormal flushed by FZ, clears Z.
            if u.sign || x & ((1u64 << 52) - 1) != 0 {
                z = false;
            }
            return (0, z);
        }
        Ty::Num => {}
    }
    // Truncate toward zero; compute the integer modulo 2^32 and whether it
    // fits in a signed 32-bit integer.
    let (low, fits, err) = if u.exp >= 0 {
        let e = u.exp as u32;
        let low = if e >= 64 { 0 } else { u.sig << e };
        // Magnitude >= 2^52 here, always out of range.
        (low, false, Err::Exact)
    } else {
        let sh = (-(u.exp as i64)) as u32;
        let v = u.sig as u128;
        let ip = shr128(v, sh) as u64;
        let err = rem_class(v, sh);
        let fits = if u.sign { ip <= 1u64 << 31 } else { ip < 1u64 << 31 };
        (ip, fits, err)
    };
    let res = if u.sign { (low as u32).wrapping_neg() } else { low as u32 };
    if !fits {
        c.raise(FPSR_IOC);
        z = false;
    } else if err != Err::Exact {
        c.raise(FPSR_IXC);
        z = false;
    }
    (res, z)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> FpCtx {
        FpCtx::new(0, 0)
    }

    #[test]
    fn basic_double() {
        let mut c = ctx();
        let one = 0x3ff0_0000_0000_0000u64;
        let two_ = 0x4000_0000_0000_0000u64;
        assert_eq!(add(&mut c, Fmt::D, one, one), two_);
        assert_eq!(mul(&mut c, Fmt::D, two_, two_), 0x4010_0000_0000_0000);
        assert_eq!(div(&mut c, Fmt::D, one, 0x4008_0000_0000_0000), 0x3fd5_5555_5555_5555);
        assert_eq!(c.fpsr, FPSR_IXC);
        let mut c = ctx();
        assert_eq!(sqrt(&mut c, Fmt::D, 0x4010_0000_0000_0000), two_);
        assert_eq!(c.fpsr, 0);
        assert_eq!(sqrt(&mut c, Fmt::D, two_), 0x3ff6_a09e_667f_3bcd);
    }

    #[test]
    fn rsqrt_table_sane() {
        for v in RSQRT_TABLE.iter() {
            assert!((256..512).contains(&(*v as u64)));
        }
    }
}
