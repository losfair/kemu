// SPDX-License-Identifier: GPL-2.0
//! Precision conversion, including IEEE half storage (no FP16 arithmetic).
use super::*;

impl<'s, 'b> Gen<'s, 'b> {
    fn fp_half(&mut self, double: bool, to_half: bool, slow: &mut Slow) {
        let fb = if double { 52 } else { 23 };
        let bias = if double { 1023 } else { 127 };
        let sign = if double { 63 } else { 31 };
        self.a.vmov_to_gpr(Sz::Q, RAX, X14);
        self.a.vmov_from_gpr(Sz::Q, 11, RAX);
        if !to_half {
            self.a.mov_rr(Sz::D, RDX, RAX);
            self.a.alu_ri(Alu::And, Sz::D, Rm::R(RDX), 0x7fff);
            self.a.alu_ri(Alu::Cmp, Sz::D, Rm::R(RDX), 0x7c00);
            slow.push(self.a.jcc(Cc::Ae, None));
            self.a.test_rr(Sz::D, RDX, RDX);
            let zero = self.a.jcc(Cc::E, None);
            self.a.alu_ri(Alu::Cmp, Sz::D, Rm::R(RDX), 0x400);
            slow.push(self.a.jcc(Cc::B, None));
            self.a.alu_ri(Alu::Add, Sz::Q, Rm::R(RDX), (bias - 15) << 10);
            self.a.shift_ri(Shift::Shl, Sz::Q, RDX, fb - 10);
            self.a.bind32(zero);
            self.a.alu_ri(Alu::And, Sz::D, Rm::R(RAX), 0x8000);
            self.a.shift_ri(Shift::Shl, Sz::Q, RAX, sign - 15);
            self.a.alu_rr(Alu::Or, Sz::Q, RAX, RDX);
            self.a.vmov_from_gpr(Sz::Q, X14, RAX);
            return;
        }
        // Preserve sign separately; arithmetic below is on the magnitude.
        self.mov_imm(RDX, (1u64 << sign) - 1);
        self.a.alu_rr(Alu::And, Sz::Q, RAX, RDX);
        self.a.test_rr(Sz::Q, RAX, RAX);
        let nonzero = self.a.jcc(Cc::Ne, None);
        self.a.vmov_to_gpr(Sz::Q, RAX, 11);
        self.a.shift_ri(Shift::Shr, Sz::Q, RAX, sign - 15);
        self.a.alu_ri(Alu::And, Sz::D, Rm::R(RAX), 0x8000);
        self.a.vmov_from_gpr(Sz::D, X14, RAX);
        let zero_done = self.a.jmp(None);
        self.a.bind32(nonzero);
        self.a.mov_rr(Sz::Q, RDX, RAX);
        self.a.shift_ri(Shift::Shr, Sz::Q, RDX, fb);
        self.a.alu_ri(Alu::Cmp, Sz::D, Rm::R(RDX), bias - 14);
        slow.push(self.a.jcc(Cc::B, None));
        self.a.alu_ri(Alu::Cmp, Sz::D, Rm::R(RDX), bias + 15);
        slow.push(self.a.jcc(Cc::A, None));
        self.a.mov_rr(Sz::Q, RDX, RAX);
        self.a.shift_ri(Shift::Shr, Sz::Q, RDX, fb - 10);
        self.a.alu_ri(Alu::Sub, Sz::D, Rm::R(RDX), (bias - 15) << 10);
        self.a.vmov_from_gpr(Sz::D, 10, RDX); // truncated half magnitude
        self.mov_imm(RDX, (1u64 << (fb - 10)) - 1);
        self.a.alu_rr(Alu::And, Sz::Q, RAX, RDX);
        self.a.vmov_from_gpr(Sz::Q, 12, RAX); // discarded bits
        self.a.test_rr(Sz::Q, RAX, RAX);
        let exact = self.a.jcc(Cc::E, None);
        self.a.load(Sz::D, RDX, Mem::gs(OFF_FPCR));
        self.a.shift_ri(Shift::Shr, Sz::D, RDX, 22);
        self.a.alu_ri(Alu::And, Sz::D, Rm::R(RDX), 3);
        let nearest = self.a.jcc(Cc::E, None);
        self.a.alu_ri(Alu::Cmp, Sz::D, Rm::R(RDX), 3);
        let truncate = self.a.jcc(Cc::E, None);
        // Round toward +inf iff positive, toward -inf iff negative.
        self.a.vmov_to_gpr(Sz::Q, RAX, 11);
        self.a.shift_ri(Shift::Shr, Sz::Q, RAX, sign);
        self.a.alu_ri(Alu::Add, Sz::D, Rm::R(RAX), 1);
        self.a.alu_rr(Alu::Cmp, Sz::D, RAX, RDX);
        let directed_down = self.a.jcc(Cc::Ne, None);
        let directed_up = self.a.jmp(None);
        self.a.bind32(nearest);
        self.mov_imm(RDX, 1u64 << (fb - 11));
        self.a.vmov_to_gpr(Sz::Q, RAX, 12);
        self.a.alu_rr(Alu::Cmp, Sz::Q, RAX, RDX);
        let below = self.a.jcc(Cc::B, None);
        let above = self.a.jcc(Cc::A, None);
        self.a.vmov_to_gpr(Sz::D, RAX, 10);
        self.a.test_ri(Sz::D, Rm::R(RAX), 1);
        let even = self.a.jcc(Cc::E, None);
        self.a.bind32(above);
        self.a.bind32(directed_up);
        self.a.vmov_to_gpr(Sz::D, RAX, 10);
        self.a.alu_ri(Alu::Add, Sz::D, Rm::R(RAX), 1);
        self.a.vmov_from_gpr(Sz::D, 10, RAX);
        for b in [truncate, directed_down, below, even] {
            self.a.bind32(b);
        }
        self.a.vmov_to_gpr(Sz::D, RAX, 10);
        self.a.alu_ri(Alu::Cmp, Sz::D, Rm::R(RAX), 0x7c00);
        slow.push(self.a.jcc(Cc::Ae, None));
        self.a.alu_ri(Alu::Or, Sz::D, Rm::M(Mem::gs(OFF_FPSR)), 1 << 4);
        self.a.bind32(exact);
        self.a.vmov_to_gpr(Sz::Q, RAX, 11);
        self.a.shift_ri(Shift::Shr, Sz::Q, RAX, sign - 15);
        self.a.alu_ri(Alu::And, Sz::D, Rm::R(RAX), 0x8000);
        self.a.vmov_to_gpr(Sz::D, RDX, 10);
        self.a.alu_rr(Alu::Or, Sz::D, RAX, RDX);
        self.a.vmov_from_gpr(Sz::D, X14, RAX);
        self.a.bind32(zero_done);
    }

    fn fp_precision_lane(&mut self, from: u8, to: u8, odd: bool, slow: &mut Slow) {
        if from == 1 || to == 1 {
            self.fp_half(from == 3 || to == 3, to == 1, slow);
            return;
        }
        let double = from == 3;
        slow.push(self.nan_guard_scalar(double, X14));
        if odd {
            // The boundary cases need ARM's tininess/overflow rules. In the
            // normal range, the two adjacent floats bracket the exact value.
            self.fp_abs_bits(true, X14);
            self.fp_power(X15, true, -126);
            self.a.vex(1, PP_66, false, false, 0x2e, X14, 0, Rm::R(X15));
            slow.push(self.a.jcc(Cc::B, None));
            self.fp_power(X15, true, 127);
            self.a.vex(1, PP_66, false, false, 0x2e, X14, 0, Rm::R(X15));
            slow.push(self.a.jcc(Cc::Ae, None));
            // Restore signed source from the frozen input lane (X11).
            self.a.vex(1, PP_F3, false, false, 0x6f, X14, 0, Rm::R(11));
        }
        self.a
            .vex(1, if double { PP_F2 } else { PP_F3 }, false, false, 0x5a, X14, X14, Rm::R(X14));
        if double && !odd {
            slow.push(self.fp_underflow_boundary(false, X14));
        }
        if odd {
            self.a.vmov_to_gpr(Sz::D, RAX, X14);
            self.a.test_ri(Sz::D, Rm::R(RAX), 1);
            let already_odd = self.a.jcc(Cc::Ne, None);
            self.a.vex(1, PP_F3, false, false, 0x5a, X15, X15, Rm::R(X14));
            self.fp_abs_bits(true, X15);
            self.fp_abs_bits(true, 11);
            self.a.vex(1, PP_66, false, false, 0x2e, X15, 0, Rm::R(11));
            let exact = self.a.jcc(Cc::E, None);
            let below = self.a.jcc(Cc::B, None);
            self.a.vmov_to_gpr(Sz::D, RAX, X14);
            self.a.alu_ri(Alu::Sub, Sz::D, Rm::R(RAX), 1);
            let done = self.a.jmp(None);
            self.a.bind32(below);
            self.a.vmov_to_gpr(Sz::D, RAX, X14);
            self.a.alu_ri(Alu::Or, Sz::D, Rm::R(RAX), 1);
            self.a.bind32(done);
            self.a.vmov_from_gpr(Sz::D, X14, RAX);
            self.a.bind32(exact);
            self.a.bind32(already_odd);
        }
    }

    pub(super) fn fp_precision(&mut self, from: u8, to: u8, scalar: bool, high: bool, odd: bool, rd: u32, rn: u32) -> bool {
        if !(1..=3).contains(&from) || !(1..=3).contains(&to) || from == to {
            return false;
        }
        self.fp_prologue();
        self.clobber();
        let mut slow = Slow::new();
        slow.push(self.fp_fz_guard());
        if from == 1 || to == 1 {
            self.a.test_ri(Sz::D, Rm::M(Mem::gs(OFF_FPCR)), 1 << 26);
            slow.push(self.a.jcc(Cc::Ne, None));
        }
        self.ld_vec(8, rn);
        let narrow = from > to;
        if !scalar && high && narrow {
            self.ld_scalar(true, 9, rd);
        } else {
            self.fp_zero(9);
        }
        let lanes = if scalar { 1 } else { 16 >> from.max(to) };
        for i in 0..lanes {
            self.fp_lane(1 << from, i + if high && !narrow { lanes } else { 0 });
            if odd {
                self.a.vex(1, PP_F3, false, false, 0x6f, 11, 0, Rm::R(X14));
            }
            self.fp_precision_lane(from, to, odd, &mut slow);
            self.fp_pack(1 << to, i + if high && narrow { lanes } else { 0 });
        }
        self.store_vec(rd, 9);
        self.slow_paths(slow.as_slice());
        true
    }
}
