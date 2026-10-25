// SPDX-License-Identifier: GPL-2.0
//! Integer, fixed-point and precision conversions. Freeze the source in
//! X8, accumulate in X9, and publish only after every lane has succeeded.
use super::*;

impl<'s, 'b> Gen<'s, 'b> {
    pub(super) fn fp_lane(&mut self, bytes: u8, lane: u8) {
        self.a.vex_ib(1, PP_66, false, false, 0x73, 3, X14, Rm::R(8), bytes * lane);
        self.a.vmov_to_gpr(if bytes == 8 { Sz::Q } else { Sz::D }, RAX, X14);
        if bytes == 2 {
            self.a.alu_ri(Alu::And, Sz::D, Rm::R(RAX), 0xffff);
        }
        self.a.vmov_from_gpr(if bytes == 8 { Sz::Q } else { Sz::D }, X14, RAX);
    }

    pub(super) fn fp_pack(&mut self, bytes: u8, lane: u8) {
        // Conversion instructions may preserve source bits above the scalar.
        self.a.vmov_to_gpr(if bytes == 8 { Sz::Q } else { Sz::D }, RAX, X14);
        if bytes == 2 {
            self.a.alu_ri(Alu::And, Sz::D, Rm::R(RAX), 0xffff);
        }
        self.a.vmov_from_gpr(if bytes == 8 { Sz::Q } else { Sz::D }, X14, RAX);
        self.a.vex_ib(1, PP_66, false, false, 0x73, 7, X14, Rm::R(X14), bytes * lane);
        self.a.vex(1, PP_66, false, false, 0xeb, 9, 9, Rm::R(X14));
    }

    /// RAX integer -> X14 FP. The sticky low bit makes the high-u64 path
    /// exact under all four rounding modes, including halfway cases.
    fn fp_from_int(&mut self, double: bool, wide: bool, unsigned: bool, fbits: u32) {
        self.fp_zero(X14);
        if !wide {
            if unsigned {
                self.a.mov_rr(Sz::D, RAX, RAX);
            } else {
                self.a.movsx(Sz::D, Sz::Q, RAX, Rm::R(RAX));
            }
        }
        let pp = if double { PP_F2 } else { PP_F3 };
        if wide && unsigned {
            self.a.test_rr(Sz::Q, RAX, RAX);
            let small = self.a.jcc(Cc::Ns, None);
            self.a.mov_rr(Sz::Q, RDX, RAX);
            self.a.alu_ri(Alu::And, Sz::D, Rm::R(RDX), 1);
            self.a.shift_ri(Shift::Shr, Sz::Q, RAX, 1);
            self.a.alu_rr(Alu::Or, Sz::Q, RAX, RDX);
            self.a.vex(1, pp, true, false, 0x2a, X14, X14, Rm::R(RAX));
            self.a.vex(1, pp, false, false, 0x58, X14, X14, Rm::R(X14));
            let done = self.a.jmp(None);
            self.a.bind32(small);
            self.a.vex(1, pp, true, false, 0x2a, X14, X14, Rm::R(RAX));
            self.a.bind32(done);
        } else {
            self.a.vex(1, pp, true, false, 0x2a, X14, X14, Rm::R(RAX));
        }
        if fbits != 0 {
            self.fp_power(X15, double, -(fbits as i32));
            self.a.vex(1, pp, false, false, 0x59, X14, X14, Rm::R(X15));
        }
    }

    /// X14 FP -> RAX integer. Round without exceptions, validate, then
    /// accrue IXC. Invalid/saturating conversions must raise IOC alone.
    fn fp_to_int(&mut self, double: bool, wide: bool, unsigned: bool, round: u8, fbits: u32, slow: &mut Slow) {
        slow.push(self.nan_guard_scalar(double, X14));
        if fbits != 0 {
            self.fp_bits(12, double, if double { 0x7fff_ffff_ffff_ffff } else { 0x7fff_ffff });
            self.a.vex(1, PP_66, false, false, 0xdb, 12, X14, Rm::R(12));
            self.fp_power(X15, double, (if wide { 64 } else { 32 }) - fbits as i32);
            self.a
                .vex(1, if double { PP_66 } else { PP_NONE }, false, false, 0x2e, 12, 0, Rm::R(X15));
            slow.push(self.a.jcc(Cc::Ae, None));
            self.fp_power(X15, double, fbits as i32);
            self.a
                .vex(1, if double { PP_F2 } else { PP_F3 }, false, false, 0x59, X14, X14, Rm::R(X15));
        }
        self.a.vex(1, PP_F3, false, false, 0x6f, 11, 0, Rm::R(X14));
        if round == 4 {
            self.fp_round_away(double);
        } else {
            let imm = [8, 10, 9, 11][round as usize];
            self.a
                .vex_ib(3, PP_66, false, false, if double { 0x0b } else { 0x0a }, X14, X14, Rm::R(X14), imm);
        }
        self.fp_range(double, if wide { 64 } else { 32 }, unsigned, slow);
        self.fp_inexact(double);
        let pp = if double { PP_F2 } else { PP_F3 };
        if wide && unsigned {
            self.fp_power(X15, double, 63);
            self.a
                .vex(1, if double { PP_66 } else { PP_NONE }, false, false, 0x2e, X14, 0, Rm::R(X15));
            let small = self.a.jcc(Cc::B, None);
            self.a.vex(1, pp, false, false, 0x5c, X14, X14, Rm::R(X15));
            self.a.vex(1, pp, true, false, 0x2c, RAX, 0, Rm::R(X14));
            self.mov_imm(RDX, 1 << 63);
            self.a.alu_rr(Alu::Or, Sz::Q, RAX, RDX);
            let done = self.a.jmp(None);
            self.a.bind32(small);
            self.a.vex(1, pp, true, false, 0x2c, RAX, 0, Rm::R(X14));
            self.a.bind32(done);
        } else {
            self.a.vex(1, pp, wide || unsigned, false, 0x2c, RAX, 0, Rm::R(X14));
        }
        if !wide {
            self.a.mov_rr(Sz::D, RAX, RAX);
        }
    }

    pub(super) fn fp_cvt_int(&mut self, double: bool, wide: bool, op: FcvtOp, rd: u32, rn: u32) -> bool {
        let (to_fp, unsigned, round, fbits) = match op {
            FcvtOp::ItoF { unsigned } => (true, unsigned, 0, 0),
            FcvtOp::FixedToF { unsigned, fbits } => (true, unsigned, 0, fbits),
            FcvtOp::FtoI { unsigned, round } => (false, unsigned, round, 0),
            FcvtOp::FtoFixed { unsigned, fbits } => (false, unsigned, 3, fbits),
            FcvtOp::Fjcvt => return self.fp_jcvt(rd, rn),
            _ => return false,
        };
        self.fp_prologue();
        self.clobber();
        let mut slow = Slow::new();
        if to_fp {
            let r = self.get(rn, false, RAX);
            self.a.mov_rr(Sz::Q, RAX, r);
            self.fp_from_int(double, wide, unsigned, fbits);
            self.st_scalar(double, X14, rd);
        } else {
            slow.push(self.fp_fz_guard());
            self.ld_scalar(double, X14, rn);
            self.fp_to_int(double, wide, unsigned, round, fbits, &mut slow);
            self.put(rd, false, RAX);
        }
        if slow.len != 0 {
            self.slow_paths(slow.as_slice());
        }
        true
    }

    /// Common signed int32 vectors have native packed conversions. Keep
    /// these packed through rounding/range checks instead of scalarizing.
    fn fp_simd_signed32(&mut self, q: bool, scalar: bool, to_fp: bool, round: u8, fbits: u32, rd: u32, rn: u32) -> bool {
        self.fp_prologue();
        let mut slow = Slow::new();
        if !to_fp {
            slow.push(self.fp_fz_guard());
        }
        self.fp_active(X14, false, scalar, q, rn);
        if to_fp {
            self.a.vex(1, PP_NONE, false, false, 0x5b, X14, 0, Rm::R(X14));
            if fbits != 0 {
                self.fp_power(X15, false, -(fbits as i32));
                self.a.vex(1, PP_NONE, false, false, 0x59, X14, X14, Rm::R(X15));
            }
        } else {
            slow.push(self.nan_guard_vec(false, X14));
            if fbits != 0 {
                self.fp_bits(12, false, 0x7fff_ffff);
                self.a.vex(1, PP_66, false, false, 0xdb, 12, X14, Rm::R(12));
                self.fp_power(X15, false, 32 - fbits as i32);
                self.a.vex_ib(1, PP_NONE, false, false, 0xc2, X13, 12, Rm::R(X15), 13);
                slow.push(self.fp_test_mask(X13));
                self.fp_power(X15, false, fbits as i32);
                self.a.vex(1, PP_NONE, false, false, 0x59, X14, X14, Rm::R(X15));
            }
            self.a.vex(1, PP_F3, false, false, 0x6f, 11, 0, Rm::R(X14));
            if round == 4 {
                self.fp_round_away(false);
            } else {
                self.a
                    .vex_ib(3, PP_66, false, false, 0x08, X14, 0, Rm::R(X14), [8, 10, 9, 11][round as usize]);
            }
            self.fp_range(false, 32, false, &mut slow);
            self.fp_inexact(false);
            self.a.vex(1, PP_F3, false, false, 0x5b, X14, 0, Rm::R(X14));
        }
        self.fp_commit(false, scalar, q, rd);
        if slow.len != 0 {
            self.slow_paths(slow.as_slice());
        }
        true
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn fp_simd_int(
        &mut self,
        q: bool,
        size: u8,
        scalar: bool,
        to_fp: bool,
        unsigned: bool,
        round: u8,
        fbits: u32,
        rd: u32,
        rn: u32,
    ) -> bool {
        if size < 2 {
            return false;
        }
        if size == 2 && !unsigned {
            return self.fp_simd_signed32(q, scalar, to_fp, round, fbits, rd, rn);
        }
        let double = size == 3;
        self.fp_prologue();
        self.clobber();
        let mut slow = Slow::new();
        if !to_fp {
            slow.push(self.fp_fz_guard());
        }
        self.ld_vec(8, rn);
        self.fp_zero(9);
        let bytes = 1 << size;
        let lanes = if scalar { 1 } else { (if q { 16 } else { 8 }) / bytes };
        for lane in 0..lanes {
            self.fp_lane(bytes, lane);
            if to_fp {
                self.fp_from_int(double, double, unsigned, fbits);
            } else {
                self.fp_to_int(double, double, unsigned, round, fbits, &mut slow);
                self.a.vmov_from_gpr(if double { Sz::Q } else { Sz::D }, X14, RAX);
            }
            self.fp_pack(bytes, lane);
        }
        self.store_vec(rd, 9);
        if slow.len != 0 {
            self.slow_paths(slow.as_slice());
        }
        true
    }

    fn fp_jcvt(&mut self, rd: u32, rn: u32) -> bool {
        self.fp_prologue();
        let mut slow = Slow::new();
        slow.push(self.fp_fz_guard());
        self.ld_scalar(true, X14, rn);
        slow.push(self.nan_guard_scalar(true, X14));
        // The uncommon modulo-2^32 cases stay on the exact helper.
        self.a.vex(1, PP_F2, false, false, 0x2c, RAX, 0, Rm::R(X14));
        self.a.alu_ri(Alu::Cmp, Sz::D, Rm::R(RAX), i32::MIN);
        slow.push(self.a.jcc(Cc::E, None));
        self.fp_zero(X15);
        self.a.vex(1, PP_F2, false, false, 0x2a, X15, X15, Rm::R(RAX));
        // Bit equality also distinguishes -0 (Z=0) from +0 (Z=1).
        self.a.vex(2, PP_66, false, false, 0x29, X15, X15, Rm::R(X14));
        self.a.vmov_to_gpr(Sz::D, RDX, X15);
        self.a.alu_ri(Alu::And, Sz::D, Rm::R(RDX), 1 << 14);
        self.put(rd, false, RAX);
        self.a.store(Sz::W, Mem::gs(OFF_FLAGS_X86), RDX);
        self.fl = Flags {
            host: false,
            inv: false,
            mem: true,
        };
        self.slow_paths(slow.as_slice());
        true
    }
}
