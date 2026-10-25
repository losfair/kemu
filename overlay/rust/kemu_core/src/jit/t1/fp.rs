// SPDX-License-Identifier: GPL-2.0
//! Tier-1 lowering of scalar floating point and common Advanced SIMD
//! instructions to SSE/AVX2 (VEX-encoded).
//!
//! V registers live in the cache or state page. Results use scratch
//! XMM registers (12..15) and commit in a single host instruction, so
//! every instruction stays restartable. Bit-exactness: whenever a result
//! could differ from AArch64 semantics (NaN results, out-of-range
//! conversions), the fast path branches to the helper, which re-executes
//! the instruction in the exact softfloat interpreter.

use super::*;
use crate::decode::{FcvtOp, Fp1Op, Fp2Op, Index, Simd2Op, SimdOp};

const X13: u8 = 13;
const X14: u8 = 14;
const X15: u8 = 15;

// VEX pp values.
const PP_NONE: u8 = 0;
const PP_66: u8 = 1;
const PP_F3: u8 = 2;
const PP_F2: u8 = 3;

pub(super) fn voff(n: u32) -> i32 {
    OFF_V + (n as i32 & 31) * 16
}

/// Expand an AArch64 FP immediate (VFPExpandImm) for S (32) or D (64).
fn fp_imm(double: bool, imm8: u8) -> u64 {
    let a = (imm8 >> 7) as u64 & 1;
    let b = (imm8 >> 6) as u64 & 1;
    let cdefgh = (imm8 & 0x3f) as u64;
    if double {
        let exp = ((b ^ 1) << 10) | (if b == 1 { 0xff << 2 } else { 0 }) | (cdefgh >> 4);
        (a << 63) | (exp << 52) | ((cdefgh & 0xf) << 48)
    } else {
        let exp = ((b ^ 1) << 7) | (if b == 1 { 0x1f << 2 } else { 0 }) | (cdefgh >> 4);
        (a << 31) | (exp << 23) | ((cdefgh & 0xf) << 19)
    }
}

impl<'s, 'b> Gen<'s, 'b> {
    /// Load a scalar (32/64-bit) from V[n] into xmm `x` (upper zeroed).
    fn ld_scalar(&mut self, double: bool, x: u8, n: u32) {
        if double {
            self.a.vex(1, PP_F3, false, false, 0x7e, x, 0, self.v_rm(n));
        } else if let Some(src) = self.vector_host(n) {
            // Keep only the low word without borrowing a GPR or flags.
            self.a.vex_ib(1, PP_66, false, false, 0x73, 7, x, Rm::R(src), 12);
            self.a.vex_ib(1, PP_66, false, false, 0x73, 3, x, Rm::R(x), 12);
        } else {
            self.a.vmovd_load(x, Mem::gs(voff(n)));
        }
    }

    /// Commit scalar result in xmm `x` to V[d], zeroing the rest.
    fn st_scalar(&mut self, double: bool, x: u8, d: u32) {
        if double {
            // vmovq xmm, xmm zeroes bits 127:64
            self.a.vex(1, PP_F3, false, false, 0x7e, x, 0, Rm::R(x));
        } else {
            self.a.vmov_to_gpr(Sz::D, RAX, x);
            self.a.vmov_from_gpr(Sz::D, x, RAX);
        }
        self.store_vec(d, x);
    }

    /// Commit a vector result: zero the upper half for 64-bit forms.
    fn st_vec(&mut self, q: bool, x: u8, d: u32) {
        if !q {
            self.a.vex(1, PP_F3, false, false, 0x7e, x, 0, Rm::R(x));
        }
        self.store_vec(d, x);
    }

    /// Branch to the slow path if `x` holds a NaN (scalar). Returns the
    /// rel32 placeholder of the branch.
    fn nan_guard_scalar(&mut self, double: bool, x: u8) -> usize {
        self.clobber();
        // vucomiss/vucomisd x, x
        self.a.vex(1, if double { PP_66 } else { PP_NONE }, false, false, 0x2e, x, 0, Rm::R(x));
        self.a.jcc(Cc::P, None)
    }

    /// Branch to the slow path if any lane of `x` is NaN (S or D lanes).
    fn nan_guard_vec(&mut self, double: bool, x: u8) -> usize {
        self.clobber();
        // vcmpunordps/pd x13, x, x ; vptest x13, x13 ; jnz
        self.a.vex_ib(1, if double { PP_66 } else { PP_NONE }, false, false, 0xc2, X13, x, Rm::R(x), 3);
        self.a.vex(2, PP_66, false, false, 0x17, X13, 0, Rm::R(X13));
        self.a.jcc(Cc::Ne, None)
    }

    /// Emit `jmp done; slow: <helper>; done:` given slow-path branches.
    fn slow_paths(&mut self, slow: &[usize]) {
        // The fast path has committed: from here on the instruction is done.
        self.point(kind::DONE, FLAGS_MEM, 0);
        let done = self.a.jmp(None);
        for s in slow {
            self.a.bind32(*s);
        }
        let saved = self.fl;
        self.fl = Flags { host: false, inv: false, mem: saved.mem || !saved.host };
        self.point(kind::INSN, FLAGS_MEM, 0);
        self.helper();
        self.a.bind32(done);
        self.fl = Flags { host: false, inv: false, mem: true };
        self.point(kind::DONE, FLAGS_MEM, 0);
    }

    /// Ensure the guest flags are in memory before an FP fast path whose
    /// slow path calls the helper (which needs them there).
    fn fp_prologue(&mut self) {
        self.flags_to_mem();
    }

    /// ARM's FZ input-denormal/underflow status differs from x86 DAZ/FTZ.
    /// Keep those cases on softfloat until their flags can be reproduced.
    fn fp_fz_guard(&mut self) -> usize {
        self.clobber();
        self.a.test_ri(Sz::D, Rm::M(Mem::gs(OFF_FPCR)), 1 << 24);
        self.a.jcc(Cc::Ne, None)
    }

    pub(super) fn fp_imm_insn(&mut self, ftype: u8, rd: u32, imm8: u8) -> bool {
        let double = match ftype {
            0 => false,
            1 => true,
            _ => return false,
        };
        let v = fp_imm(double, imm8);
        self.mov_imm(RAX, v);
        self.a.vmov_from_gpr(Sz::Q, X14, RAX);
        self.store_vec(rd, X14);
        true
    }

    pub(super) fn fp2(&mut self, ftype: u8, op: Fp2Op, rd: u32, rn: u32, rm: u32) -> bool {
        let double = match ftype {
            0 => false,
            1 => true,
            _ => return false,
        };
        if matches!(op, Fp2Op::Min | Fp2Op::Max | Fp2Op::MinNm | Fp2Op::MaxNm) {
            return self.fp_minmax(double, true, false, matches!(op, Fp2Op::Min | Fp2Op::MinNm), rd, rn, rm);
        }
        let opc = match op {
            Fp2Op::Add => 0x58,
            Fp2Op::Mul | Fp2Op::Nmul => 0x59,
            Fp2Op::Sub => 0x5c,
            Fp2Op::Div => 0x5e,
            _ => return false,
        };
        self.fp_prologue();
        let pp = if double { PP_F2 } else { PP_F3 };
        self.ld_scalar(double, X14, rn);
        self.a.vex(1, pp, false, false, opc, X14, X14, self.v_rm(rm));
        let s = self.nan_guard_scalar(double, X14);
        if op == Fp2Op::Nmul {
            self.a.vmov_to_gpr(Sz::Q, RAX, X14);
            let bit = if double { 63 } else { 31 };
            // btc rax, bit
            self.a.byte(0x48);
            self.a.bytes(&[0x0f, 0xba, 0xf8, bit]);
            self.a.vmov_from_gpr(Sz::Q, X14, RAX);
        }
        self.st_scalar(double, X14, rd);
        self.slow_paths(&[s]);
        true
    }

    /// MIN/MAX choose the second operand on x86 when both operands are
    /// zero. Combine both operand orders to give ARM's -0 for MIN and +0
    /// for MAX. All NaNs go to softfloat, including the numeric variants
    /// (whose signaling-NaN and operand-priority rules differ from x86).
    fn fp_minmax(&mut self, double: bool, scalar: bool, q: bool, min: bool, rd: u32, rn: u32, rm: u32) -> bool {
        self.fp_prologue();
        let fz = self.fp_fz_guard();
        if scalar {
            self.ld_scalar(double, X14, rn);
            self.ld_scalar(double, X15, rm);
        } else if !q {
            self.ld_scalar(true, X14, rn);
            self.ld_scalar(true, X15, rm);
        } else {
            self.ld_vec(X14, rn);
            self.ld_vec(X15, rm);
        }
        self.clobber();
        let slow = if scalar {
            self.a.vex(1, if double { PP_66 } else { PP_NONE }, false, false, 0x2e, X14, 0, Rm::R(X15));
            self.a.jcc(Cc::P, None)
        } else {
            self.a.vex_ib(1, if double { PP_66 } else { PP_NONE }, false, false, 0xc2, X13, X14, Rm::R(X15), 3);
            self.a.vex(2, PP_66, false, false, 0x17, X13, 0, Rm::R(X13));
            self.a.jcc(Cc::Ne, None)
        };
        let pp = match (scalar, double) {
            (true, true) => PP_F2,
            (true, false) => PP_F3,
            (false, true) => PP_66,
            (false, false) => PP_NONE,
        };
        let opc = if min { 0x5d } else { 0x5f };
        self.a.vex(1, pp, false, false, opc, 12, X14, Rm::R(X15));
        self.a.vex(1, pp, false, false, opc, X14, X15, Rm::R(X14));
        self.a.vex(1, PP_66, false, false, if min { 0xeb } else { 0xdb }, X14, X14, Rm::R(12));
        if scalar {
            self.st_scalar(double, X14, rd);
        } else {
            self.st_vec(q, X14, rd);
        }
        self.slow_paths(&[fz, slow]);
        true
    }

    pub(super) fn fp3(&mut self, ftype: u8, neg: bool, sub: bool, rd: u32, rn: u32, rm: u32, ra: u32) -> bool {
        let double = match ftype {
            0 => false,
            1 => true,
            _ => return false,
        };
        // acc in x14, n in x15, m from memory: x14 = +-(x15 * m) +- x14
        let opc = match (neg, sub) {
            (false, false) => 0xb9, // vfmadd231:   n*m + a
            (false, true) => 0xbd,  // vfnmadd231: -(n*m) + a
            (true, false) => 0xbf,  // vfnmsub231: -(n*m) - a
            (true, true) => 0xbb,   // vfmsub231:   n*m - a
        };
        self.fp_prologue();
        self.ld_scalar(double, X14, ra);
        self.ld_scalar(double, X15, rn);
        self.a.vex(2, PP_66, double, false, opc, X14, X15, self.v_rm(rm));
        let s = self.nan_guard_scalar(double, X14);
        self.st_scalar(double, X14, rd);
        self.slow_paths(&[s]);
        true
    }

    pub(super) fn fp1(&mut self, ftype: u8, op: Fp1Op, to: u8, rd: u32, rn: u32) -> bool {
        let double = match ftype {
            0 => false,
            1 => true,
            _ => return false,
        };
        match op {
            Fp1Op::Mov | Fp1Op::Abs | Fp1Op::Neg => {
                // Pure bit operations, never trap.
                self.clobber();
                self.vector_extract(Sz::Q, RAX, rn, 0);
                if !double {
                    self.a.mov_rr(Sz::D, RAX, RAX);
                }
                let bit = if double { 63 } else { 31 };
                match op {
                    // btr / btc rax, bit
                    Fp1Op::Abs => self.a.bytes(&[0x48, 0x0f, 0xba, 0xf0, bit]),
                    Fp1Op::Neg => self.a.bytes(&[0x48, 0x0f, 0xba, 0xf8, bit]),
                    _ => {}
                }
                self.a.vmov_from_gpr(Sz::Q, X14, RAX);
                self.store_vec(rd, X14);
                true
            }
            Fp1Op::Sqrt => {
                self.fp_prologue();
                self.ld_scalar(double, X14, rn);
                self.a.vex(1, if double { PP_F2 } else { PP_F3 }, false, false, 0x51, X14, X14, Rm::R(X14));
                let s = self.nan_guard_scalar(double, X14);
                self.st_scalar(double, X14, rd);
                self.slow_paths(&[s]);
                true
            }
            Fp1Op::RintN | Fp1Op::RintP | Fp1Op::RintM | Fp1Op::RintZ | Fp1Op::RintX | Fp1Op::RintI => {
                let imm = match op {
                    Fp1Op::RintN => 8,
                    Fp1Op::RintM => 9,
                    Fp1Op::RintP => 10,
                    Fp1Op::RintZ => 11,
                    Fp1Op::RintX => 4,
                    _ => 12,
                };
                self.fp_prologue();
                self.ld_scalar(double, X14, rn);
                self.a.vex_ib(3, PP_66, false, false, if double { 0x0b } else { 0x0a }, X14, X14, Rm::R(X14), imm);
                let s = self.nan_guard_scalar(double, X14);
                self.st_scalar(double, X14, rd);
                self.slow_paths(&[s]);
                true
            }
            Fp1Op::Cvt if to <= 1 && to != ftype => {
                // S <-> D
                self.fp_prologue();
                self.ld_scalar(double, X14, rn);
                self.a.vex(1, if double { PP_F2 } else { PP_F3 }, false, false, 0x5a, X14, X14, Rm::R(X14));
                let s = self.nan_guard_scalar(!double, X14);
                self.st_scalar(!double, X14, rd);
                self.slow_paths(&[s]);
                true
            }
            _ => false,
        }
    }

    pub(super) fn fp_cmp(&mut self, ftype: u8, rn: u32, rm: u32, zero: bool, signal: bool) -> bool {
        let double = match ftype {
            0 => false,
            1 => true,
            _ => return false,
        };
        self.clobber();
        self.ld_scalar(double, X14, rn);
        if zero {
            self.a.vex(1, PP_66, false, false, 0xef, X15, X15, Rm::R(X15)); // vpxor
        } else {
            self.ld_scalar(double, X15, rm);
        }
        // (v)comis / (v)ucomis
        let opc = if signal { 0x2f } else { 0x2e };
        self.a.vex(1, if double { PP_66 } else { PP_NONE }, false, false, opc, X14, 0, Rm::R(X15));
        self.a.lahf();
        self.a.shift_ri(Shift::Shr, Sz::D, RAX, 8);
        self.a.mov_ri32(RDX, 0x45);
        self.a.pext(Sz::D, RAX, RAX, Rm::R(RDX));
        self.lea_abs(RDX, self.cfg.stubs.fcmp_table);
        self.a.movzx(Sz::W, RAX, Rm::M(Mem::bisd(RDX, RAX, 1, 0)));
        self.a.store(Sz::W, Mem::gs(OFF_FLAGS_X86), RAX);
        self.fl = Flags { host: false, inv: false, mem: true };
        self.point(kind::DONE, FLAGS_MEM, 0);
        true
    }

    /// `lea dst, [rip + (uaddr - next)]`
    pub(super) fn lea_abs(&mut self, dst: Reg, uaddr: u64) {
        self.a.byte(0x48 | ((dst >> 3) & 1) << 2);
        self.a.byte(0x8d);
        self.a.byte(((dst & 7) << 3) | 5);
        let at = self.a.pos;
        self.a.u32(0);
        self.rel_abs(at, uaddr);
    }

    pub(super) fn fp_csel(&mut self, ftype: u8, rd: u32, rn: u32, rm: u32, cond: u32) -> bool {
        if ftype > 1 {
            return false;
        }
        self.flags_to_host();
        let cc = self.cond_cc(cond);
        self.vector_extract(Sz::Q, RAX, rm, 0);
        match cc {
            Some(cc) if self.vector_host(rn).is_none() => {
                self.a.cmov(cc, Sz::Q, RAX, Rm::M(Mem::gs(voff(rn))));
            }
            Some(cc) => {
                self.vector_extract(Sz::Q, RDX, rn, 0);
                self.a.cmov(cc, Sz::Q, RAX, Rm::R(RDX));
            }
            None => self.vector_extract(Sz::Q, RAX, rn, 0),
        }
        if ftype == 0 {
            self.a.mov_rr(Sz::D, RAX, RAX);
        }
        self.a.vmov_from_gpr(Sz::Q, X14, RAX);
        self.store_vec(rd, X14);
        true
    }

    pub(super) fn fp_cvt(&mut self, ftype: u8, sf: bool, op: FcvtOp, rd: u32, rn: u32) -> bool {
        let double = ftype == 1;
        if ftype > 1 && !matches!(op, FcvtOp::Fmov { .. }) {
            return false;
        }
        match op {
            FcvtOp::Fmov { to_fp, top } => {
                // ftype 0: W<->S, 1: X<->D, 2 (top): X<->V.D[1]
                let (sz, off) = match (ftype, top, sf) {
                    (0, false, false) => (Sz::D, 0),
                    (1, false, true) => (Sz::Q, 0),
                    (2, true, true) => (Sz::Q, 8),
                    _ => return false,
                };
                if to_fp {
                    let r = self.get(rn, false, RAX);
                    if top {
                        self.vector_insert(Sz::Q, rd, 1, r);
                    } else {
                        self.a.vmov_from_gpr(sz, X14, r);
                        self.store_vec(rd, X14);
                    }
                } else {
                    match self.gp(rd, false) {
                        Gp::R(r) => self.vector_extract(sz, r, rn, (off / 8) as u8),
                        Gp::M(o) => {
                            self.vector_extract(sz, RAX, rn, (off / 8) as u8);
                            self.a.store(Sz::Q, Mem::gs(o), RAX);
                        }
                        Gp::Zero => {}
                    }
                }
                true
            }
            FcvtOp::ItoF { unsigned } => {
                self.fp_prologue();
                let src = self.get(rn, false, RDX);
                let mut slow = None;
                let src64 = if !sf {
                    // 32-bit source: extend to 64 bits (exact for both).
                    if unsigned {
                        self.a.mov_rr(Sz::D, RDX, src);
                    } else {
                        self.a.movsx(Sz::D, Sz::Q, RDX, Rm::R(src));
                    }
                    RDX
                } else {
                    if unsigned {
                        self.clobber();
                        self.a.test_rr(Sz::Q, src, src);
                        slow = Some(self.a.jcc(Cc::S, None));
                    }
                    src
                };
                self.a.vex(1, PP_66, false, false, 0xef, X14, X14, Rm::R(X14)); // zero
                // vcvtsi2sd/ss x14, x14, r64
                self.a.vex(1, if double { PP_F2 } else { PP_F3 }, true, false, 0x2a, X14, X14, Rm::R(src64));
                self.st_scalar(double, X14, rd);
                match slow {
                    Some(s) => self.slow_paths(&[s]),
                    None => {}
                }
                true
            }
            FcvtOp::FtoI { round, unsigned } => {
                if round > 3 {
                    return false;
                }
                self.fp_prologue();
                self.clobber();
                self.ld_scalar(double, X14, rn);
                if round != 3 {
                    let imm = match round {
                        0 => 8,
                        1 => 10,
                        _ => 9,
                    };
                    self.a.vex_ib(3, PP_66, false, false, if double { 0x0b } else { 0x0a }, X14, X14, Rm::R(X14), imm);
                }
                // Signed 64-bit conversion, then range checks.
                let wide = sf || unsigned;
                self.a.vex(1, if double { PP_F2 } else { PP_F3 }, wide, false, 0x2c, RAX, 0, Rm::R(X14));
                let mut slow = [0usize; 2];
                let ns;
                if !unsigned {
                    // indefinite = INT_MIN of the destination width
                    if sf {
                        self.a.mov_ri(RDX, 1u64 << 63);
                        self.a.alu_rr(Alu::Cmp, Sz::Q, RAX, RDX);
                    } else {
                        self.a.alu_ri(Alu::Cmp, Sz::D, Rm::R(RAX), i32::MIN);
                    }
                    slow[0] = self.a.jcc(Cc::E, None);
                    ns = 1;
                } else if sf {
                    self.a.test_rr(Sz::Q, RAX, RAX);
                    slow[0] = self.a.jcc(Cc::S, None);
                    ns = 1;
                } else {
                    self.a.mov_rr(Sz::Q, RDX, RAX);
                    self.a.shift_ri(Shift::Shr, Sz::Q, RDX, 32);
                    slow[0] = self.a.jcc(Cc::Ne, None);
                    ns = 1;
                }
                if !sf {
                    self.a.mov_rr(Sz::D, RAX, RAX);
                }
                self.put(rd, false, RAX);
                self.slow_paths(&slow[..ns]);
                true
            }
            _ => false,
        }
    }

    // ---- Advanced SIMD ----

    /// FMUL/FMLA/FMLS by an indexed S/D element. Broadcast before touching
    /// the accumulator, so all source/destination aliases are safe.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn simd_indexed(&mut self, q: bool, u: bool, size: u8, opcode: u8, rd: u32, rn: u32, rm: u32, index: u32, scalar: bool) -> bool {
        if u || !matches!(size, 2 | 3) || !matches!(opcode, 1 | 5 | 9) || (size == 3 && !q && !scalar) {
            return false;
        }
        let double = size == 3;
        self.fp_prologue();
        let fz = self.fp_fz_guard();
        let elem = self.vector_slice(rm, (index << size) as u8, 12);
        self.a.vex(2, PP_66, false, false, if double { 0x59 } else { 0x58 }, 12, 0, elem);
        if scalar {
            self.ld_scalar(double, X15, rn);
        } else if !q {
            self.ld_scalar(true, X15, rn);
            // Inactive lanes must not raise exceptions (e.g. 0 * infinity).
            self.a.vex(1, PP_F3, false, false, 0x7e, 12, 0, Rm::R(12));
        } else {
            self.ld_vec(X15, rn);
        }
        if opcode == 9 {
            let pp = if scalar { if double { PP_F2 } else { PP_F3 } } else if double { PP_66 } else { PP_NONE };
            self.a.vex(1, pp, false, false, 0x59, X14, X15, Rm::R(12));
        } else {
            if scalar {
                self.ld_scalar(double, X14, rd);
            } else if !q {
                self.ld_scalar(true, X14, rd);
            } else {
                self.ld_vec(X14, rd);
            }
            let opc = (if opcode == 1 { 0xb8 } else { 0xbc }) + scalar as u8;
            self.a.vex(2, PP_66, double, false, opc, X14, X15, Rm::R(12));
        }
        let slow = if scalar { self.nan_guard_scalar(double, X14) } else { self.nan_guard_vec(double, X14) };
        if scalar {
            self.st_scalar(double, X14, rd);
        } else {
            self.st_vec(q, X14, rd);
        }
        self.slow_paths(&[fz, slow]);
        true
    }

    /// Splat a 32-bit constant into xmm `x`.
    fn splat32(&mut self, x: u8, v: u32) {
        self.a.mov_ri32(RAX, v);
        self.a.vmov_from_gpr(Sz::D, x, RAX);
        self.a.vex(2, PP_66, false, false, 0x58, x, 0, Rm::R(x)); // vpbroadcastd
    }

    pub(super) fn simd_three(&mut self, q: bool, u: bool, size: u8, op: SimdOp, rd: u32, rn: u32, rm: u32, scalar: bool) -> bool {
        if scalar {
            return false;
        }
        let _ = u;
        // Integer ops: map to a VEX 66 0F opcode by element size.
        let int_op: Option<[u8; 4]> = match op {
            SimdOp::Add => Some([0xfc, 0xfd, 0xfe, 0xd4]),
            SimdOp::Sub => Some([0xf8, 0xf9, 0xfa, 0xfb]),
            SimdOp::CmEq => Some([0x74, 0x75, 0x76, 0]),
            SimdOp::CmGt => Some([0x64, 0x65, 0x66, 0]),
            _ => None,
        };
        if let Some(t) = int_op {
            let opc = t[(size & 3) as usize];
            if opc == 0 {
                // 64-bit compares: pcmpeqq / pcmpgtq (0F38 29 / 37)
                let o = if op == SimdOp::CmEq { 0x29 } else { 0x37 };
                self.ld_vec(X14, rn);
                self.a.vex(2, PP_66, false, false, o, X14, X14, self.v_rm(rm));
            } else {
                self.ld_vec(X14, rn);
                self.a.vex(1, PP_66, false, false, opc, X14, X14, self.v_rm(rm));
            }
            self.st_vec(q, X14, rd);
            return true;
        }
        match op {
            SimdOp::FMin | SimdOp::FMax | SimdOp::FMinNm | SimdOp::FMaxNm if size >= 2 && (q || size == 2) => {
                self.fp_minmax(size == 3, false, q, matches!(op, SimdOp::FMin | SimdOp::FMinNm), rd, rn, rm)
            }
            SimdOp::PMull | SimdOp::PMull2 => self.pmull(size, op == SimdOp::PMull2, rd, rn, rm),
            SimdOp::And | SimdOp::Orr | SimdOp::Eor | SimdOp::Bic => {
                self.ld_vec(X14, rn);
                match op {
                    SimdOp::And => self.a.vex(1, PP_66, false, false, 0xdb, X14, X14, self.v_rm(rm)),
                    SimdOp::Orr => self.a.vex(1, PP_66, false, false, 0xeb, X14, X14, self.v_rm(rm)),
                    SimdOp::Eor => self.a.vex(1, PP_66, false, false, 0xef, X14, X14, self.v_rm(rm)),
                    _ => {
                        // vpandn x14, x15(rm), x14(rn) : ~rm & rn
                        self.ld_vec(X15, rm);
                        self.a.vex(1, PP_66, false, false, 0xdf, X14, X15, Rm::R(X14));
                    }
                }
                self.st_vec(q, X14, rd);
                true
            }
            SimdOp::CmHi | SimdOp::CmHs | SimdOp::CmGe if size < 3 => {
                // unsigned via bias; ge/hs as not(lt)
                self.ld_vec(X14, rn);
                self.ld_vec(X15, rm);
                let unsigned = matches!(op, SimdOp::CmHi | SimdOp::CmHs);
                if unsigned {
                    let bias = match size {
                        0 => 0x8080_8080u32,
                        1 => 0x8000_8000,
                        _ => 0x8000_0000,
                    };
                    self.splat32(X13, bias);
                    self.a.vex(1, PP_66, false, false, 0xef, X14, X14, Rm::R(X13));
                    self.a.vex(1, PP_66, false, false, 0xef, X15, X15, Rm::R(X13));
                }
                let gt = [0x64u8, 0x65, 0x66][size as usize];
                if op == SimdOp::CmHi {
                    self.a.vex(1, PP_66, false, false, gt, X14, X14, Rm::R(X15));
                } else {
                    // a >= b  <=>  !(b > a)
                    self.a.vex(1, PP_66, false, false, gt, X15, X15, Rm::R(X14));
                    self.a.vex(1, PP_66, false, false, 0x76, X13, X13, Rm::R(X13)); // all ones
                    self.a.vex(1, PP_66, false, false, 0xef, X14, X15, Rm::R(X13));
                }
                self.st_vec(q, X14, rd);
                true
            }
            SimdOp::UMax | SimdOp::UMin | SimdOp::SMax | SimdOp::SMin if size < 3 => {
                // (map, opcode): umax b:0F DE w:0F38 3E d:0F38 3F ; umin b:0F DA w:38 3A d:38 3B
                // smax b:0F38 3C w:0F EE d:0F38 3D ; smin b:0F38 38 w:0F EA d:0F38 39
                let (map, opc) = match (op, size) {
                    (SimdOp::UMax, 0) => (1, 0xde),
                    (SimdOp::UMax, 1) => (2, 0x3e),
                    (SimdOp::UMax, _) => (2, 0x3f),
                    (SimdOp::UMin, 0) => (1, 0xda),
                    (SimdOp::UMin, 1) => (2, 0x3a),
                    (SimdOp::UMin, _) => (2, 0x3b),
                    (SimdOp::SMax, 0) => (2, 0x3c),
                    (SimdOp::SMax, 1) => (1, 0xee),
                    (SimdOp::SMax, _) => (2, 0x3d),
                    (SimdOp::SMin, 0) => (2, 0x38),
                    (SimdOp::SMin, 1) => (1, 0xea),
                    (_, _) => (2, 0x39),
                };
                self.ld_vec(X14, rn);
                self.a.vex(map, PP_66, false, false, opc, X14, X14, self.v_rm(rm));
                self.st_vec(q, X14, rd);
                true
            }
            SimdOp::UMaxP | SimdOp::UMinP if size == 0 => {
                // Pairwise over Vn:Vm: evens/odds of 16-bit words, max, pack.
                self.ld_vec(X14, rn);
                self.ld_vec(X15, rm);
                if !q {
                    // vpunpcklqdq x14, x14, x15 ; x15 = 0
                    self.a.vex(1, PP_66, false, false, 0x6c, X14, X14, Rm::R(X15));
                }
                let mx = if op == SimdOp::UMaxP { 0xde } else { 0xda };
                // x13 = 0x00ff mask
                self.splat32(X13, 0x00ff_00ff);
                // for x14: odds = x14 >> 8 ; evens = x14 & mask ; x14 = max
                self.pairwise_bytes(X14, mx);
                if q {
                    self.pairwise_bytes(X15, mx);
                } else {
                    self.a.vex(1, PP_66, false, false, 0xef, X15, X15, Rm::R(X15));
                }
                // vpackuswb x14, x14, x15
                self.a.vex(1, PP_66, false, false, 0x67, X14, X14, Rm::R(X15));
                self.st_vec(q, X14, rd);
                true
            }
            SimdOp::Mul | SimdOp::Mla | SimdOp::Mls if size == 1 || size == 2 => {
                self.ld_vec(X14, rn);
                if size == 1 {
                    self.a.vex(1, PP_66, false, false, 0xd5, X14, X14, self.v_rm(rm)); // vpmullw
                } else {
                    self.a.vex(2, PP_66, false, false, 0x40, X14, X14, self.v_rm(rm)); // vpmulld
                }
                if op != SimdOp::Mul {
                    self.ld_vec(X15, rd);
                    let (add, sub) = if size == 1 { (0xfd, 0xf9) } else { (0xfe, 0xfa) };
                    self.a.vex(1, PP_66, false, false, if op == SimdOp::Mla { add } else { sub }, X15, X15, Rm::R(X14));
                    self.st_vec(q, X15, rd);
                } else {
                    self.st_vec(q, X14, rd);
                }
                true
            }
            SimdOp::AddP if size >= 1 => {
                self.ld_vec(X14, rn);
                self.ld_vec(X15, rm);
                match (size, q) {
                    (3, true) => {
                        // [n0+n1, m0+m1]
                        self.a.vex(1, PP_66, false, false, 0x6c, X13, X14, Rm::R(X15)); // (n0, m0)
                        self.a.vex(1, PP_66, false, false, 0x6d, X14, X14, Rm::R(X15)); // (n1, m1)
                        self.a.vex(1, PP_66, false, false, 0xd4, X14, X14, Rm::R(X13));
                    }
                    (3, false) => return false,
                    (_, true) => {
                        let o = if size == 1 { 0x01 } else { 0x02 }; // vphaddw / vphaddd
                        self.a.vex(2, PP_66, false, false, o, X14, X14, Rm::R(X15));
                    }
                    (_, false) => {
                        let o = if size == 1 { 0x01 } else { 0x02 };
                        self.a.vex(1, PP_66, false, false, 0x6c, X14, X14, Rm::R(X15)); // n_lo : m_lo
                        self.a.vex(2, PP_66, false, false, o, X14, X14, Rm::R(X14));
                    }
                }
                self.st_vec(q, X14, rd);
                true
            }
            SimdOp::SAddW | SimdOp::SAddW2 | SimdOp::UAddW | SimdOp::UAddW2 | SimdOp::SSubW | SimdOp::SSubW2
            | SimdOp::USubW | SimdOp::USubW2
                if size <= 2 =>
            {
                let signed = matches!(op, SimdOp::SAddW | SimdOp::SAddW2 | SimdOp::SSubW | SimdOp::SSubW2);
                let hi = matches!(op, SimdOp::SAddW2 | SimdOp::UAddW2 | SimdOp::SSubW2 | SimdOp::USubW2);
                let sub = matches!(op, SimdOp::SSubW | SimdOp::SSubW2 | SimdOp::USubW | SimdOp::USubW2);
                self.widen(X15, rm, size, signed, hi);
                self.ld_vec(X14, rn);
                let o = if sub { [0xf9u8, 0xfa, 0xfb][size as usize] } else { [0xfdu8, 0xfe, 0xd4][size as usize] };
                self.a.vex(1, PP_66, false, false, o, X14, X14, Rm::R(X15));
                self.st_vec(true, X14, rd);
                true
            }
            SimdOp::SMullL | SimdOp::SMullL2 | SimdOp::UMullL | SimdOp::UMullL2 | SimdOp::SMlaL | SimdOp::SMlaL2
            | SimdOp::UMlaL | SimdOp::UMlaL2
                if size <= 2 =>
            {
                let signed = matches!(op, SimdOp::SMullL | SimdOp::SMullL2 | SimdOp::SMlaL | SimdOp::SMlaL2);
                let hi = matches!(op, SimdOp::SMullL2 | SimdOp::UMullL2 | SimdOp::SMlaL2 | SimdOp::UMlaL2);
                let acc = matches!(op, SimdOp::SMlaL | SimdOp::SMlaL2 | SimdOp::UMlaL | SimdOp::UMlaL2);
                self.widen(X14, rn, size, signed, hi);
                self.widen(X15, rm, size, signed, hi);
                match size {
                    0 => self.a.vex(1, PP_66, false, false, 0xd5, X14, X14, Rm::R(X15)), // vpmullw
                    1 => self.a.vex(2, PP_66, false, false, 0x40, X14, X14, Rm::R(X15)), // vpmulld
                    _ => {
                        if signed {
                            self.a.vex(2, PP_66, false, false, 0x28, X14, X14, Rm::R(X15)) // vpmuldq
                        } else {
                            self.a.vex(1, PP_66, false, false, 0xf4, X14, X14, Rm::R(X15)) // vpmuludq
                        }
                    }
                }
                if acc {
                    self.ld_vec(X15, rd);
                    let o = [0xfdu8, 0xfe, 0xd4][size as usize];
                    self.a.vex(1, PP_66, false, false, o, X14, X14, Rm::R(X15));
                }
                self.st_vec(true, X14, rd);
                true
            }
            SimdOp::FAdd | SimdOp::FSub | SimdOp::FMul | SimdOp::FDiv if size >= 2 => {
                let double = size == 3;
                if double && !q {
                    return false;
                }
                let opc = match op {
                    SimdOp::FAdd => 0x58,
                    SimdOp::FMul => 0x59,
                    SimdOp::FSub => 0x5c,
                    _ => 0x5e,
                };
                self.fp_prologue();
                self.ld_vec(X14, rn);
                self.a.vex(1, if double { PP_66 } else { PP_NONE }, false, false, opc, X14, X14, self.v_rm(rm));
                if !q {
                    self.a.vex(1, PP_F3, false, false, 0x7e, X14, 0, Rm::R(X14));
                }
                let s = self.nan_guard_vec(double, X14);
                self.store_vec(rd, X14);
                self.slow_paths(&[s]);
                true
            }
            SimdOp::FMla | SimdOp::FMls if size >= 2 => {
                let double = size == 3;
                if double && !q {
                    return false;
                }
                self.fp_prologue();
                self.ld_vec(X14, rd);
                self.ld_vec(X15, rn);
                let opc = if op == SimdOp::FMla { 0xb8 } else { 0xbc }; // vfmadd231ps / vfnmadd231ps
                self.a.vex(2, PP_66, double, false, opc, X14, X15, self.v_rm(rm));
                if !q {
                    self.a.vex(1, PP_F3, false, false, 0x7e, X14, 0, Rm::R(X14));
                }
                let s = self.nan_guard_vec(double, X14);
                self.store_vec(rd, X14);
                self.slow_paths(&[s]);
                true
            }
            _ => false,
        }
    }

    /// x = sign/zero-extended lower (or upper) half of V[n] to double width.
    pub(super) fn widen(&mut self, x: u8, n: u32, size: u8, signed: bool, hi: bool) {
        let src = self.vector_slice(n, if hi { 8 } else { 0 }, x);
        // vpmovsx{bw,wd,dq} 0F38 20/23/25 ; vpmovzx 30/33/35 (64-bit memory operand)
        let o = [0x20u8, 0x23, 0x25][(size & 3).min(2) as usize] + if signed { 0 } else { 0x10 };
        self.a.vex(2, PP_66, false, false, o, x, 0, src);
    }

    pub(super) fn simd_permute(&mut self, q: bool, size: u8, opcode: u8, rd: u32, rn: u32, rm: u32) -> bool {
        self.ld_vec(X14, rn);
        self.ld_vec(X15, rm);
        let op = opcode & 7;
        match (size, q, op) {
            // Byte/halfword ZIP1/ZIP2. The high half of a 64-bit input
            // starts at byte 4, unlike PUNPCKH's byte 8.
            (0 | 1, _, 0b011 | 0b111) => {
                let high = op == 0b111;
                if high && !q {
                    self.a.vex_ib(1, PP_66, false, false, 0x73, 3, X14, Rm::R(X14), 4);
                    self.a.vex_ib(1, PP_66, false, false, 0x73, 3, X15, Rm::R(X15), 4);
                }
                let opc = (if high && q { 0x68 } else { 0x60 }) + size;
                self.a.vex(1, PP_66, false, false, opc, X14, X14, Rm::R(X15));
            }
            (0 | 1, _, 0b001 | 0b101) => {
                // Gather even/odd elements to each source's low half,
                // then concatenate. PSHUFB's high bit zeroes unused bytes.
                let bytes = if q { 8 } else { 4 };
                let mut mask = [0x80u8; 16];
                for i in 0..bytes {
                    mask[i] = (((i >> size) * 2 + (op >> 2) as usize) << size
                        | (i & ((1 << size) - 1))) as u8;
                }
                self.mov_imm(RAX, u64::from_le_bytes(mask[..8].try_into().unwrap()));
                self.a.vmov_from_gpr(Sz::Q, X13, RAX);
                self.mov_imm(RAX, u64::from_le_bytes(mask[8..].try_into().unwrap()));
                self.a.vex_ib(3, PP_66, true, false, 0x22, X13, X13, Rm::R(RAX), 1); // vpinsrq
                self.a.vex(2, PP_66, false, false, 0x00, X14, X14, Rm::R(X13));
                self.a.vex(2, PP_66, false, false, 0x00, X15, X15, Rm::R(X13));
                self.a.vex(1, PP_66, false, false, if q { 0x6c } else { 0x62 }, X14, X14, Rm::R(X15));
            }
            // UZP1/UZP2 .4S
            (2, true, 0b001) => self.a.vex_ib(1, PP_NONE, false, false, 0xc6, X14, X14, Rm::R(X15), 0x88),
            (2, true, 0b101) => self.a.vex_ib(1, PP_NONE, false, false, 0xc6, X14, X14, Rm::R(X15), 0xdd),
            // ZIP1/ZIP2 .4S, ZIP1 .2S
            (2, _, 0b011) => self.a.vex(1, PP_66, false, false, 0x62, X14, X14, Rm::R(X15)),
            (2, true, 0b111) => self.a.vex(1, PP_66, false, false, 0x6a, X14, X14, Rm::R(X15)),
            // .2D: UZP1 = ZIP1 = (n0, m0); UZP2 = ZIP2 = (n1, m1)
            (3, true, 0b001) | (3, true, 0b011) => self.a.vex(1, PP_66, false, false, 0x6c, X14, X14, Rm::R(X15)),
            (3, true, 0b101) | (3, true, 0b111) => self.a.vex(1, PP_66, false, false, 0x6d, X14, X14, Rm::R(X15)),
            _ => return false,
        }
        self.st_vec(q, X14, rd);
        true
    }

    /// TBL/TBX over 1..4 registers. PSHUFB only checks index bit 7;
    /// saturating-add 0x70 to each table-relative index so every index
    /// outside 0..15 is zeroed instead of wrapping modulo 16.
    pub(super) fn simd_tbl(&mut self, q: bool, len: u8, tbx: bool, rd: u32, rn: u32, rm: u32) -> bool {
        self.ld_vec(X15, rm);
        self.splat32(12, 0x7070_7070);
        if len != 0 { self.splat32(10, 0x1010_1010); }
        for k in 0..=len {
            self.a.vex(1, PP_66, false, false, 0xdc, X13, X15, Rm::R(12)); // vpaddusb
            self.ld_vec(11, (rn + k as u32) & 31);
            self.a.vex(2, PP_66, false, false, 0x00, if k == 0 { X14 } else { 11 }, 11, Rm::R(X13));
            if k != 0 {
                self.a.vex(1, PP_66, false, false, 0xeb, X14, X14, Rm::R(11));
            }
            if k != len {
                self.a.vex(1, PP_66, false, false, 0xf8, X15, X15, Rm::R(10)); // vpsubb
            }
        }
        if tbx {
            self.ld_vec(X15, rm);
            self.splat32(12, ((len as u32 + 1) * 16 - 1) * 0x0101_0101);
            self.a.vex(1, PP_66, false, false, 0xda, X13, X15, Rm::R(12)); // vpminub
            self.a.vex(1, PP_66, false, false, 0x74, X13, X13, Rm::R(X15)); // valid indices
            self.a.vex(1, PP_66, false, false, 0xdf, X13, X13, self.v_rm(rd));
            self.a.vex(1, PP_66, false, false, 0xeb, X14, X14, Rm::R(X13));
        }
        self.st_vec(q, X14, rd);
        true
    }

    /// x = pairwise op of adjacent bytes as 16-bit words (low byte), using
    /// x13 = 0x00ff mask; result bytes in the low byte of each word.
    fn pairwise_bytes(&mut self, x: u8, opc: u8) {
        // x12 = x >> 8 (words)
        self.a.vex_ib(1, PP_66, false, false, 0x71, 2, 12, Rm::R(x), 8); // vpsrlw x12, x, 8
        self.a.vex(1, PP_66, false, false, 0xdb, x, x, Rm::R(X13)); // vpand x, x, mask
        self.a.vex(1, PP_66, false, false, opc, x, x, Rm::R(12));
    }

    pub(super) fn simd_misc(&mut self, q: bool, u: bool, size: u8, op: Simd2Op, rd: u32, rn: u32, scalar: bool) -> bool {
        if scalar {
            return false;
        }
        match op {
            Simd2Op::Rev16 | Simd2Op::Rev32 | Simd2Op::Rev64 => {
                let container = match op {
                    Simd2Op::Rev16 => 1,
                    Simd2Op::Rev32 => 2,
                    _ => 3,
                };
                if size >= container {
                    return false;
                }
                // Reverse element order within each container while
                // preserving byte order within an element. SHA-256 uses
                // REV32.16B for every input vector before its rounds.
                let swap = (1u64 << container) - (1u64 << size);
                let mut mask = 0u64;
                for byte in 0..8 {
                    mask |= (byte ^ swap) << (byte * 8);
                }
                self.mov_imm(RAX, mask);
                self.a.vmov_from_gpr(Sz::Q, X15, RAX);
                self.mov_imm(RAX, mask | 0x0808_0808_0808_0808);
                self.a.vmov_from_gpr(Sz::Q, X13, RAX);
                self.a.vex(1, PP_66, false, false, 0x6c, X15, X15, Rm::R(X13)); // vpunpcklqdq
                self.ld_vec(X14, rn);
                self.a.vex(2, PP_66, false, false, 0x00, X14, X14, Rm::R(X15)); // vpshufb
                self.st_vec(q, X14, rd);
                return true;
            }
            Simd2Op::Not => {}
            Simd2Op::NotOrRbit if !u => {}
            Simd2Op::CmEq0 if size < 3 => {
                self.ld_vec(X14, rn);
                self.a.vex(1, PP_66, false, false, 0xef, X15, X15, Rm::R(X15));
                let opc = [0x74u8, 0x75, 0x76][size as usize];
                self.a.vex(1, PP_66, false, false, opc, X14, X14, Rm::R(X15));
                self.st_vec(q, X14, rd);
                return true;
            }
            Simd2Op::Abs if size < 3 => {
                let opc = [0x1cu8, 0x1d, 0x1e][size as usize];
                self.a.vex(2, PP_66, false, false, opc, X14, 0, self.v_rm(rn));
                self.st_vec(q, X14, rd);
                return true;
            }
            Simd2Op::Neg => {
                let opc = [0xf8u8, 0xf9, 0xfa, 0xfb][(size & 3) as usize];
                self.a.vex(1, PP_66, false, false, 0xef, X14, X14, Rm::R(X14));
                self.a.vex(1, PP_66, false, false, opc, X14, X14, self.v_rm(rn));
                self.st_vec(q, X14, rd);
                return true;
            }
            _ => return false,
        }
        // NOT
        self.ld_vec(X14, rn);
        self.a.vex(1, PP_66, false, false, 0x76, X15, X15, Rm::R(X15));
        self.a.vex(1, PP_66, false, false, 0xef, X14, X14, Rm::R(X15));
        self.st_vec(q, X14, rd);
        true
    }

    pub(super) fn simd_dup(&mut self, q: bool, imm5: u32, rd: u32, rn: u32, from_gpr: bool) -> bool {
        let size = imm5.trailing_zeros();
        if size > 3 {
            return false;
        }
        // vpbroadcast{b,w,d,q}: 0F38 78 79 58 59
        let opc = [0x78u8, 0x79, 0x58, 0x59][size as usize];
        if from_gpr {
            let r = self.get(rn, false, RAX);
            self.a.vmov_from_gpr(Sz::Q, X14, r);
            self.a.vex(2, PP_66, false, false, opc, X14, 0, Rm::R(X14));
        } else {
            let idx = imm5 >> (size + 1);
            let src = self.vector_slice(rn, (idx << size) as u8, X14);
            self.a.vex(2, PP_66, false, false, opc, X14, 0, src);
        }
        self.st_vec(q, X14, rd);
        true
    }

    pub(super) fn simd_scalar_copy(&mut self, imm5: u32, rd: u32, rn: u32) -> bool {
        let size = imm5.trailing_zeros();
        if size > 3 {
            return false;
        }
        let idx = imm5 >> (size + 1);
        let sz = [Sz::B, Sz::W, Sz::D, Sz::Q][size as usize];
        if self.vector_host(rn).is_none() && size >= 2 {
            let m = Mem::gs(voff(rn) + (idx << size) as i32);
            if size == 3 { self.a.vmovq_load(X14, m); } else { self.a.vmovd_load(X14, m); }
        } else {
            self.vector_extract(sz, RAX, rn, idx as u8);
            self.a.vmov_from_gpr(if size == 3 { Sz::Q } else { Sz::D }, X14, RAX);
        }
        self.store_vec(rd, X14);
        true
    }

    pub(super) fn simd_mod_imm(&mut self, q: bool, op: u8, cmode: u8, rd: u32, imm: u64, fp: bool) -> bool {
        // MOVI / MVNI forms only (ORR/BIC immediate use the helper).
        let orr_bic = (cmode & 1 == 1) && cmode < 0b1100;
        if orr_bic {
            return false;
        }
        let v = if op == 1 && cmode < 0b1110 { !imm } else { imm };
        if fp && op == 1 && cmode == 0b1111 && !q {
            return false;
        }
        self.mov_imm(RAX, v);
        self.a.vmov_from_gpr(Sz::Q, X14, RAX);
        if q {
            self.a.vex(2, PP_66, false, false, 0x59, X14, 0, Rm::R(X14)); // vpbroadcastq
        }
        self.store_vec(rd, X14);
        true
    }

    pub(super) fn simd_shift(&mut self, q: bool, u: bool, immh: u32, immb: u32, opcode: u8, rd: u32, rn: u32, scalar: bool) -> bool {
        if immh == 0 {
            return false;
        }
        let esize = 31 - immh.leading_zeros(); // log2 bytes
        let ebits = 8u32 << esize;
        let immhb = (immh << 3) | immb;
        // Scalar SHL Dd,Dn,#imm is used in GHASH reduction. Other scalar
        // shift families still use the interpreter.
        if scalar && !(opcode == 0b01010 && !u && esize == 3) {
            return false;
        }
        match opcode {
            0b01010 if !u && esize == 0 => {
                // Byte SHL: word shifts plus a per-byte mask prevent
                // bits from spilling into the neighboring lane.
                let amt = (immhb - ebits) as u8;
                self.ld_vec(X14, rn);
                self.a.vex_ib(1, PP_66, false, false, 0x71, 6, X14, Rm::R(X14), amt);
                self.splat32(X13, ((0xffu32 << amt) & 0xff) * 0x0101_0101);
                self.a.vex(1, PP_66, false, false, 0xdb, X14, X14, Rm::R(X13));
                self.st_vec(q, X14, rd);
                true
            }
            0b00000 | 0b01010 if esize >= 1 => {
                // SSHR/USHR (op 0) or SHL (op 01010, u=0)
                if opcode == 0b01010 && u {
                    return false; // SLI
                }
                let (ext, amt) = if opcode == 0b01010 {
                    (6u8, immhb - ebits) // psll
                } else {
                    (if u { 2u8 } else { 4u8 }, 2 * ebits - immhb) // psrl / psra
                };
                if !u && opcode == 0 && esize == 3 {
                    return false; // no vpsraq in AVX2
                }
                // group opcode by element size: w 71, d 72, q 73
                let g = [0u8, 0x71, 0x72, 0x73][esize as usize];
                let amt = amt.min(ebits) as u8;
                // shift-by-immediate forms only take register operands
                self.ld_vec(X14, rn);
                self.a.vex_ib(1, PP_66, false, false, g, ext, X14, Rm::R(X14), amt);
                self.st_vec(q && !scalar, X14, rd);
                true
            }
            0b10000 if !u && esize <= 2 => {
                // SHRN / SHRN2: narrow (2*esize -> esize) after logical shift right.
                let src = esize + 1;
                let shr = (2 * ebits - immhb) as u8;
                let g = [0u8, 0x71, 0x72, 0x73][src as usize];
                self.ld_vec(X14, rn);
                self.a.vex_ib(1, PP_66, false, false, g, 2, X14, Rm::R(X14), shr);
                // keep low half of each source element, then pack
                let mask = match esize {
                    0 => 0x00ff_00ffu32,
                    1 => 0x0000_ffff,
                    _ => 0,
                };
                if esize < 2 {
                    self.splat32(X13, mask);
                    self.a.vex(1, PP_66, false, false, 0xdb, X14, X14, Rm::R(X13));
                    // vpackuswb (0F 67) / vpackusdw (0F38 2B)
                    if esize == 0 {
                        self.a.vex(1, PP_66, false, false, 0x67, X14, X14, Rm::R(X14));
                    } else {
                        self.a.vex(2, PP_66, false, false, 0x2b, X14, X14, Rm::R(X14));
                    }
                } else {
                    // 64 -> 32: vpshufd 0b1000 picks dwords 0 and 2
                    self.a.vex_ib(1, PP_66, false, false, 0x70, X14, 0, Rm::R(X14), 0b1000);
                }
                if q {
                    // SHRN2: insert into upper half of Vd
                    self.ld_vec(X15, rd);
                    self.a.vex(1, PP_66, false, false, 0x6c, X15, X15, Rm::R(X14)); // punpcklqdq
                    self.store_vec(rd, X15);
                } else {
                    self.st_vec(false, X14, rd);
                }
                true
            }
            _ => false,
        }
    }

    pub(super) fn simd_ext(&mut self, q: bool, imm4: u32, rd: u32, rn: u32, rm: u32) -> bool {
        if !q {
            return false;
        }
        // EXT: bytes imm4.. of Vm:Vn  ==  vpalignr x14, vm, vn, imm4
        self.ld_vec(X15, rm);
        self.a.vex_ib(3, PP_66, false, false, 0x0f, X14, X15, self.v_rm(rn), imm4 as u8);
        self.st_vec(true, X14, rd);
        true
    }

    pub(super) fn simd_umov(&mut self, imm5: u32, rd: u32, rn: u32) -> bool {
        let size = imm5.trailing_zeros();
        if size > 3 {
            return false;
        }
        let idx = imm5 >> (size + 1);
        let dst = match self.gp(rd, false) {
            Gp::R(r) => r,
            Gp::Zero => return true,
            Gp::M(_) => RAX,
        };
        self.vector_extract([Sz::B, Sz::W, Sz::D, Sz::Q][size as usize], dst, rn, idx as u8);
        if dst == RAX {
            self.put(rd, false, RAX);
        }
        true
    }

    pub(super) fn simd_ins_gpr(&mut self, imm5: u32, rd: u32, rn: u32) -> bool {
        let size = imm5.trailing_zeros();
        if size > 3 {
            return false;
        }
        let idx = imm5 >> (size + 1);
        let sz = [Sz::B, Sz::W, Sz::D, Sz::Q][size as usize];
        let r = self.get(rn, false, RAX);
        self.vector_insert(sz, rd, idx as u8, r);
        true
    }

    pub(super) fn simd_ins_elt(&mut self, imm5: u32, imm4: u32, rd: u32, rn: u32) -> bool {
        let size = imm5.trailing_zeros();
        if size > 3 {
            return false;
        }
        let di = imm5 >> (size + 1);
        let si = imm4 >> size;
        let sz = [Sz::B, Sz::W, Sz::D, Sz::Q][size as usize];
        self.vector_extract(sz, RAX, rn, si as u8);
        self.vector_insert(sz, rd, di as u8, RAX);
        true
    }

    /// LD1/ST1 (multiple structures, 1-4 consecutive registers).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn simd_ldst(&mut self, load: bool, q: bool, opcode: u8, rt: u32, rn: u32, rm: u32, single: bool, post: bool) -> bool {
        if single {
            return false;
        }
        self.simd_ldst_multi(load, q, opcode, rt, rn, rm, post)
    }

    /// LD1R (replicate one element to all lanes).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn simd_ld1r(&mut self, q: bool, size: u8, rt: u32, rn: u32, rm: u32, post: bool) -> bool {
        if size > 3 {
            return false;
        }
        let base = self.base(rn);
        let opc = [0x78u8, 0x79, 0x58, 0x59][size as usize];
        self.a.vex(2, PP_66, false, false, opc, X14, 0, Rm::M(Mem::b(base)));
        self.st_vec(q, X14, rt);
        if post {
            self.post_index(rn, base, rm, 1i64 << size);
        }
        true
    }

    fn post_index(&mut self, rn: u32, base: Reg, rm: u32, imm: i64) {
        if rm == 31 {
            self.writeback(rn, base, imm);
        } else {
            let m = self.get(rm, false, RAX);
            match self.gp(rn, true) {
                Gp::R(r) => self.a.lea(Sz::Q, r, Mem::bisd(r, m, 0, 0)),
                Gp::M(o) => {
                    if self.cfg.tbi {
                        // `base` holds the untagged copy; keep the tag.
                        self.a.load(Sz::Q, base, Mem::gs(o));
                    }
                    self.a.lea(Sz::Q, base, Mem::bisd(base, m, 0, 0));
                    self.a.store(Sz::Q, Mem::gs(o), base);
                }
                Gp::Zero => {}
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn simd_ldst_multi(&mut self, load: bool, q: bool, opcode: u8, rt: u32, rn: u32, rm: u32, post: bool) -> bool {
        let nregs = match opcode {
            0b0111 => 1,
            0b1010 => 2,
            0b0110 => 3,
            0b0010 => 4,
            _ => return false,
        };
        let bytes = if q { 16 } else { 8 };
        let base = self.base(rn);
        for i in 0..nregs {
            let r = (rt + i) & 31;
            let m = Mem::bd(base, (i * bytes) as i32);
            if load {
                if q {
                    self.a.vmovdqu_load(X14, m);
                } else {
                    self.a.vmovq_load(X14, m);
                }
                self.store_vec(r, X14);
            } else if q {
                self.ld_vec(X14, r);
                self.a.vmovdqu_store(m, X14);
            } else {
                self.vector_extract(Sz::Q, RAX, r, 0);
                self.a.store(Sz::Q, m, RAX);
            }
        }
        if post {
            if rm == 31 {
                self.writeback(rn, base, (nregs * bytes) as i64);
            } else {
                // register post-index: base += Xm
                let m = self.get(rm, false, RAX);
                match self.gp(rn, true) {
                    Gp::R(r) => self.a.lea(Sz::Q, r, Mem::bisd(r, m, 0, 0)),
                    Gp::M(o) => {
                        if self.cfg.tbi {
                            // `base` holds the untagged copy; keep the tag.
                            self.a.load(Sz::Q, base, Mem::gs(o));
                        }
                        self.a.lea(Sz::Q, base, Mem::bisd(base, m, 0, 0));
                        self.a.store(Sz::Q, Mem::gs(o), base);
                    }
                    Gp::Zero => {}
                }
            }
        }
        let _ = Index::Post;
        true
    }
}
