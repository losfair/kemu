// SPDX-License-Identifier: GPL-2.0
//! FP comparisons, unary operations, rounding and horizontal operations.
use super::*;

impl<'s, 'b> Gen<'s, 'b> {
    pub(super) fn fp_zero(&mut self, x: u8) {
        self.a.vex(1, PP_66, false, false, 0xef, x, x, Rm::R(x));
    }

    pub(super) fn fp_bits(&mut self, x: u8, double: bool, bits: u64) {
        self.mov_imm(RAX, bits);
        self.a.vmov_from_gpr(Sz::Q, x, RAX);
        self.a.vex(2, PP_66, false, false, if double { 0x59 } else { 0x58 }, x, 0, Rm::R(x));
    }

    pub(super) fn fp_power(&mut self, x: u8, double: bool, exponent: i32) {
        self.fp_bits(
            x,
            double,
            if double {
                ((1023 + exponent) as u64) << 52
            } else {
                ((127 + exponent) as u64) << 23
            },
        );
    }

    pub(super) fn fp_active(&mut self, x: u8, double: bool, scalar: bool, q: bool, n: u32) {
        if scalar {
            self.ld_scalar(double, x, n);
        } else if !q {
            self.ld_scalar(true, x, n);
        } else {
            self.ld_vec(x, n);
        }
    }

    pub(super) fn fp_commit(&mut self, double: bool, scalar: bool, q: bool, rd: u32) {
        if scalar {
            self.st_scalar(double, X14, rd);
        } else {
            self.st_vec(q, X14, rd);
        }
    }

    pub(super) fn fp_nan(&mut self, double: bool, scalar: bool, x: u8) -> usize {
        if scalar {
            self.nan_guard_scalar(double, x)
        } else {
            self.nan_guard_vec(double, x)
        }
    }

    pub(super) fn fp_abs_bits(&mut self, double: bool, x: u8) {
        self.fp_bits(12, double, if double { 0x7fff_ffff_ffff_ffff } else { 0x7fff_ffff });
        self.a.vex(1, PP_66, false, false, 0xdb, x, x, Rm::R(12));
    }

    pub(super) fn fp_test_mask(&mut self, x: u8) -> usize {
        self.clobber();
        self.a.vex(2, PP_66, false, false, 0x17, x, 0, Rm::R(x));
        self.a.jcc(Cc::Ne, None)
    }

    /// x86 detects tininess after rounding; ARM detects it before rounding.
    /// A result rounded up to the smallest normal may therefore lack UFC.
    pub(super) fn fp_underflow_boundary(&mut self, double: bool, x: u8) -> usize {
        self.fp_bits(12, double, if double { 0x7fff_ffff_ffff_ffff } else { 0x7fff_ffff });
        self.a.vex(1, PP_66, false, false, 0xdb, X13, x, Rm::R(12));
        self.fp_power(12, double, if double { -1022 } else { -126 });
        self.a.vex(
            if double { 2 } else { 1 },
            PP_66,
            false,
            false,
            if double { 0x29 } else { 0x76 },
            X13,
            X13,
            Rm::R(12),
        );
        self.fp_test_mask(X13)
    }

    /// Round X14 to nearest, ties away, without changing FPSR. Mask large
    /// integral values (including infinities) before subtracting the
    /// truncated value, avoiding infinity-infinity and double rounding.
    pub(super) fn fp_round_away(&mut self, double: bool) {
        let pp = if double { PP_66 } else { PP_NONE };
        self.fp_bits(12, double, if double { 0x7fff_ffff_ffff_ffff } else { 0x7fff_ffff });
        self.a.vex(1, PP_66, false, false, 0xdb, 12, X14, Rm::R(12));
        self.fp_power(X15, double, if double { 52 } else { 23 });
        self.a.vex_ib(1, pp, false, false, 0xc2, 10, 12, Rm::R(X15), 1); // abs < 2^fraction_bits
        self.a.vex(1, PP_66, false, false, 0xdb, 12, 12, Rm::R(10));
        self.a
            .vex_ib(3, PP_66, false, false, if double { 0x09 } else { 0x08 }, X13, 0, Rm::R(12), 11);
        self.a.vex(1, pp, false, false, 0x5c, X15, 12, Rm::R(X13));
        self.fp_power(12, double, -1);
        self.a.vex_ib(1, pp, false, false, 0xc2, X15, X15, Rm::R(12), 13); // remainder >= 0.5
        self.fp_power(12, double, 0);
        self.a.vex(1, PP_66, false, false, 0xdb, X15, X15, Rm::R(12));
        self.a.vex(1, pp, false, false, 0x58, X13, X13, Rm::R(X15));
        self.a.vex(1, PP_66, false, false, 0xdf, 12, 10, Rm::R(X14)); // large original lanes
        self.fp_bits(X15, double, if double { 1 << 63 } else { 1 << 31 });
        self.a.vex(1, PP_66, false, false, 0xdb, X15, X14, Rm::R(X15));
        self.a.vex(1, PP_66, false, false, 0xeb, X14, X13, Rm::R(12));
        self.a.vex(1, PP_66, false, false, 0xeb, X14, X14, Rm::R(X15));
    }

    /// Set IXC iff original (X11) differs from the integral result (X14).
    /// Called only after range validation: invalid conversions must not
    /// acquire an extra inexact exception from a speculative host round.
    pub(super) fn fp_inexact(&mut self, double: bool) {
        self.a
            .vex_ib(1, if double { PP_66 } else { PP_NONE }, false, false, 0xc2, X13, 11, Rm::R(X14), 4);
        self.clobber();
        self.a.vex(2, PP_66, false, false, 0x17, X13, 0, Rm::R(X13));
        let exact = self.a.jcc(Cc::E, None);
        self.a.alu_ri(Alu::Or, Sz::D, Rm::M(Mem::gs(OFF_FPSR)), 1 << 4);
        self.a.bind32(exact);
    }

    pub(super) fn fp_round_insn(&mut self, double: bool, scalar: bool, q: bool, op: Fp1Op, rd: u32, rn: u32) -> bool {
        self.fp_prologue();
        let mut slow = Slow::new();
        slow.push(self.fp_fz_guard());
        self.fp_active(X14, double, scalar, q, rn);
        slow.push(self.fp_nan(double, scalar, X14));
        self.a.vex(1, PP_F3, false, false, 0x6f, 11, 0, Rm::R(X14));
        let intsize = match op {
            Fp1Op::Rint32X | Fp1Op::Rint32Z => Some(32),
            Fp1Op::Rint64X | Fp1Op::Rint64Z => Some(64),
            _ => None,
        };
        if op == Fp1Op::RintA {
            self.fp_round_away(double);
        } else {
            let imm = match op {
                Fp1Op::RintN => 8,
                Fp1Op::RintM => 9,
                Fp1Op::RintP => 10,
                Fp1Op::RintZ | Fp1Op::Rint32Z | Fp1Op::Rint64Z => 11,
                Fp1Op::RintX => 4,
                _ => 12,
            };
            self.a
                .vex_ib(3, PP_66, false, false, if double { 0x09 } else { 0x08 }, X14, 0, Rm::R(X14), imm);
        }
        if let Some(bits) = intsize {
            self.fp_range(double, bits, false, &mut slow);
            self.fp_inexact(double);
        }
        self.fp_commit(double, scalar, q, rd);
        self.slow_paths(slow.as_slice());
        true
    }

    /// Integral X14 must fit in the requested signed/unsigned type.
    pub(super) fn fp_range(&mut self, double: bool, bits: u32, unsigned: bool, slow: &mut Slow) {
        let pp = if double { PP_66 } else { PP_NONE };
        self.fp_power(X15, double, (bits - !unsigned as u32) as i32);
        self.a.vex_ib(1, pp, false, false, 0xc2, X13, X14, Rm::R(X15), 13); // >= upper limit
        slow.push(self.fp_test_mask(X13));
        if unsigned {
            self.fp_zero(X15);
        } else {
            self.fp_bits(
                X15,
                double,
                if double {
                    ((1023 + bits as u64 - 1) << 52) | 1 << 63
                } else {
                    ((127 + bits as u64 - 1) << 23) | 1 << 31
                },
            );
        }
        self.a.vex_ib(1, pp, false, false, 0xc2, X13, X14, Rm::R(X15), 1); // < lower limit
        slow.push(self.fp_test_mask(X13));
    }

    pub(super) fn fp_misc_extra(&mut self, q: bool, size: u8, op: Simd2Op, rd: u32, rn: u32, scalar: bool) -> Option<bool> {
        use Simd2Op::*;
        if matches!(op, FcvtN | FcvtN2 | FcvtXn | FcvtXn2 | FcvtL | FcvtL2) {
            let narrow = !matches!(op, FcvtL | FcvtL2);
            let high = matches!(op, FcvtN2 | FcvtXn2 | FcvtL2);
            return Some(self.fp_precision(
                size + narrow as u8,
                size + !narrow as u8,
                scalar,
                high,
                matches!(op, FcvtXn | FcvtXn2),
                rd,
                rn,
            ));
        }
        if matches!(op, Frecpe | Frsqrte | Frecpx) {
            return Some(self.fp_estimate(q, size, scalar, op, rd, rn));
        }
        let cvt = match op {
            Scvtf => Some((true, false, 0)),
            Ucvtf => Some((true, true, 0)),
            Fcvtns => Some((false, false, 0)),
            Fcvtnu => Some((false, true, 0)),
            Fcvtps => Some((false, false, 1)),
            Fcvtpu => Some((false, true, 1)),
            Fcvtms => Some((false, false, 2)),
            Fcvtmu => Some((false, true, 2)),
            Fcvtzs => Some((false, false, 3)),
            Fcvtzu => Some((false, true, 3)),
            Fcvtas => Some((false, false, 4)),
            Fcvtau => Some((false, true, 4)),
            _ => None,
        };
        if let Some((to_fp, unsigned, round)) = cvt {
            return Some(self.fp_simd_int(q, size, scalar, to_fp, unsigned, round, 0, rd, rn));
        }
        let round = match op {
            FrintN => Some(Fp1Op::RintN),
            FrintP => Some(Fp1Op::RintP),
            FrintM => Some(Fp1Op::RintM),
            FrintZ => Some(Fp1Op::RintZ),
            FrintA => Some(Fp1Op::RintA),
            FrintX => Some(Fp1Op::RintX),
            FrintI => Some(Fp1Op::RintI),
            Frint32Z => Some(Fp1Op::Rint32Z),
            Frint32X => Some(Fp1Op::Rint32X),
            Frint64Z => Some(Fp1Op::Rint64Z),
            Frint64X => Some(Fp1Op::Rint64X),
            _ => None,
        };
        if let Some(round) = round {
            return Some(self.fp_round_insn(size == 3, scalar, q, round, rd, rn));
        }
        if matches!(op, FCmEq0 | FCmGe0 | FCmGt0 | FCmLe0 | FCmLt0) {
            let cmp = match op {
                FCmEq0 => SimdOp::FCmEq,
                FCmGe0 | FCmLe0 => SimdOp::FCmGe,
                _ => SimdOp::FCmGt,
            };
            return Some(self.fp_compare_mask(q, size, cmp, rd, rn, None, scalar, matches!(op, FCmLe0 | FCmLt0)));
        }
        if !matches!(op, Fabs | Fneg | Fsqrt) {
            return None;
        }
        let double = size == 3;
        let mut slow = Slow::new();
        if op == Fsqrt {
            self.fp_prologue();
            slow.push(self.fp_fz_guard());
        }
        self.fp_active(X14, double, scalar, q, rn);
        if op == Fsqrt {
            self.a
                .vex(1, if double { PP_66 } else { PP_NONE }, false, false, 0x51, X14, 0, Rm::R(X14));
            slow.push(self.fp_nan(double, scalar, X14));
        } else if op == Fabs {
            self.fp_abs_bits(double, X14);
        } else {
            self.fp_bits(12, double, if double { 1 << 63 } else { 1 << 31 });
            self.a.vex(1, PP_66, false, false, 0xef, X14, X14, Rm::R(12));
        }
        self.fp_commit(double, scalar, q, rd);
        if slow.len != 0 {
            self.slow_paths(slow.as_slice());
        }
        Some(true)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn fp_compare_mask(
        &mut self,
        q: bool,
        size: u8,
        op: SimdOp,
        rd: u32,
        rn: u32,
        rm: Option<u32>,
        scalar: bool,
        reverse: bool,
    ) -> bool {
        if size < 2 {
            return false;
        }
        let double = size == 3;
        self.fp_prologue();
        let slow = self.fp_fz_guard();
        self.fp_active(X14, double, scalar, q, rn);
        if let Some(rm) = rm {
            self.fp_active(X15, double, scalar, q, rm);
        } else {
            self.fp_zero(X15);
        }
        if matches!(op, SimdOp::FAcGe | SimdOp::FAcGt) {
            self.fp_abs_bits(double, X14);
            self.fp_abs_bits(double, X15);
        }
        let pred = match (op, reverse) {
            (SimdOp::FCmEq, _) => 0, // ordered quiet: only sNaNs raise IOC
            (SimdOp::FCmGe | SimdOp::FAcGe, false) => 13,
            (SimdOp::FCmGe, true) => 2,
            (_, false) => 14,
            (_, true) => 1,
        };
        self.a.vex_ib(
            1,
            if double { PP_66 } else { PP_NONE },
            false,
            false,
            0xc2,
            X14,
            X14,
            Rm::R(X15),
            pred,
        );
        self.fp_commit(double, scalar, q, rd);
        self.slow_paths(&[slow]);
        true
    }

    /// Combine scratch operands; inputs and result have identical lane layouts.
    pub(super) fn fp_pair_op(&mut self, double: bool, op: SimdOp, slow: &mut Slow) {
        let pp = if double { PP_66 } else { PP_NONE };
        if op == SimdOp::FAddP {
            self.a.vex(1, pp, false, false, 0x58, X14, X14, Rm::R(X15));
            slow.push(self.nan_guard_vec(double, X14));
        } else {
            self.a.vex_ib(1, pp, false, false, 0xc2, X13, X14, Rm::R(X15), 3);
            slow.push(self.fp_test_mask(X13));
            let min = matches!(op, SimdOp::FMinP | SimdOp::FMinNmP);
            let opc = if min { 0x5d } else { 0x5f };
            self.a.vex(1, pp, false, false, opc, 12, X14, Rm::R(X15));
            self.a.vex(1, pp, false, false, opc, X14, X15, Rm::R(X14));
            self.a
                .vex(1, PP_66, false, false, if min { 0xeb } else { 0xdb }, X14, X14, Rm::R(12));
        }
    }

    pub(super) fn fp_pair(&mut self, q: bool, size: u8, op: SimdOp, rd: u32, rn: u32, rm: u32) -> bool {
        if size < 2 {
            return false;
        }
        let double = size == 3;
        self.fp_prologue();
        let mut slow = Slow::new();
        slow.push(self.fp_fz_guard());
        self.fp_active(X14, double, false, q, rn);
        self.fp_active(X15, double, false, q, rm);
        if double {
            self.a.vex(1, PP_66, false, false, 0x6c, 12, X14, Rm::R(X15));
            self.a.vex(1, PP_66, false, false, 0x6d, X15, X14, Rm::R(X15));
            self.a.vex(1, PP_F3, false, false, 0x6f, X14, 0, Rm::R(12));
        } else {
            if !q {
                self.a.vex(1, PP_66, false, false, 0x6c, X14, X14, Rm::R(X15));
                self.a.vex(1, PP_F3, false, false, 0x6f, X15, 0, Rm::R(X14));
            }
            self.a.vex_ib(1, PP_NONE, false, false, 0xc6, 12, X14, Rm::R(X15), 0x88);
            self.a.vex_ib(1, PP_NONE, false, false, 0xc6, X15, X14, Rm::R(X15), 0xdd);
            self.a.vex(1, PP_F3, false, false, 0x6f, X14, 0, Rm::R(12));
        }
        self.fp_pair_op(double, op, &mut slow);
        self.st_vec(q, X14, rd);
        self.slow_paths(slow.as_slice());
        true
    }

    pub(in super::super) fn fp_across(&mut self, q: bool, size: u8, op: AcrossOp, rd: u32, rn: u32) -> bool {
        if op == AcrossOp::UMinV && size < 3 {
            return self.simd_uminv(q, size, rd, rn);
        }
        if op == AcrossOp::AddP && size == 3 {
            self.ld_vec(X14, rn);
            self.a.vex_ib(1, PP_66, false, false, 0x73, 3, X15, Rm::R(X14), 8);
            self.a.vex(1, PP_66, false, false, 0xd4, X14, X14, Rm::R(X15));
            self.st_scalar(true, X14, rd);
            return true;
        }
        if op == AcrossOp::AddV && size < 3 {
            if size < 2 { self.clobber(); }
            if q { self.ld_vec(X14, rn); } else { self.ld_scalar(true, X14, rn); }
            if size == 0 {
                self.a.vex(1, PP_66, false, false, 0xef, X15, X15, Rm::R(X15));
                self.a.vex(1, PP_66, false, false, 0xf6, X14, X14, Rm::R(X15)); // vpsadbw
                self.a.vex_ib(1, PP_66, false, false, 0x73, 3, X15, Rm::R(X14), 8);
                self.a.vex(1, PP_66, false, false, 0xd4, X14, X14, Rm::R(X15));
            } else {
                for _ in 0..(4 - size) {
                    self.a.vex(2, PP_66, false, false, size, X14, X14, Rm::R(X14)); // vphaddw/d
                }
            }
            self.a.vmov_to_gpr(Sz::D, RAX, X14);
            if size < 2 {
                self.a.alu_ri(Alu::And, Sz::D, Rm::R(RAX), if size == 0 { 0xff } else { 0xffff });
            }
            self.a.vmov_from_gpr(Sz::D, X14, RAX);
            self.store_vec(rd, X14);
            return true;
        }
        let pair = match op {
            AcrossOp::FAddP => SimdOp::FAddP,
            AcrossOp::FMinP | AcrossOp::FMinV => SimdOp::FMinP,
            AcrossOp::FMaxP | AcrossOp::FMaxV => SimdOp::FMaxP,
            AcrossOp::FMinNmP | AcrossOp::FMinNmV => SimdOp::FMinNmP,
            AcrossOp::FMaxNmP | AcrossOp::FMaxNmV => SimdOp::FMaxNmP,
            _ => return false,
        };
        let double = size == 3;
        self.fp_prologue();
        let mut slow = Slow::new();
        slow.push(self.fp_fz_guard());
        self.fp_active(X14, double, false, q, rn);
        if double {
            self.a.vex_ib(1, PP_66, false, false, 0x73, 3, X15, Rm::R(X14), 8);
            self.a.vex(1, PP_F3, false, false, 0x7e, X14, 0, Rm::R(X14));
        } else {
            self.a.vex_ib(1, PP_NONE, false, false, 0xc6, X15, X14, Rm::R(X14), 0xdd);
            self.a.vex_ib(1, PP_NONE, false, false, 0xc6, X14, X14, Rm::R(X14), 0x88);
        }
        self.fp_pair_op(double, pair, &mut slow);
        if !double && q {
            self.a.vex_ib(1, PP_66, false, false, 0x73, 3, X15, Rm::R(X14), 4);
            self.fp_pair_op(false, pair, &mut slow);
        }
        self.st_scalar(double, X14, rd);
        self.slow_paths(slow.as_slice());
        true
    }

    pub(in super::super) fn fp_ccmp(&mut self, ftype: u8, rn: u32, rm: u32, nzcv: u32, cond: u32, signal: bool) -> bool {
        if ftype > 1 {
            return false;
        }
        self.flags_to_host();
        self.flags_to_mem();
        let otherwise = self.cond_cc(cond).map(|cc| self.a.jcc(cc.invert(), None));
        let slow = self.fp_fz_guard();
        self.fp_cmp(ftype, rn, rm, false, signal);
        if let Some(otherwise) = otherwise {
            let done = self.a.jmp(None);
            self.a.bind32(otherwise);
            self.point(kind::INSN, FLAGS_MEM, 0);
            self.a
                .store_imm(Sz::W, Mem::gs(OFF_FLAGS_X86), image_from_nzcv((nzcv as u64) << 28) as i32);
            self.point(kind::DONE, FLAGS_MEM, 0);
            self.a.bind32(done);
        }
        self.slow_paths(&[slow]);
        true
    }
}
