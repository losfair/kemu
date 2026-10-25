// SPDX-License-Identifier: GPL-2.0
//! ARM reciprocal estimates use specified lookup values, not x86 RCP/RSQRT
//! approximations. Embed each table once per block; RIP addressing survives
//! code-cache relocation without an external pointer or relocation entry.
use super::*;

impl<'s, 'b> Gen<'s, 'b> {
    fn fp_estimate_table(&mut self, sqrt: bool) -> usize {
        let which = sqrt as usize;
        if let Some(off) = self.fp_tables[which] {
            return off;
        }
        let skip = self.a.jmp(None);
        let off = self.a.pos;
        if sqrt {
            for v in crate::softfloat::RSQRT_TABLE {
                self.a.u16(v);
            }
        } else {
            for a in 256..512 {
                self.a.u16((((1u32 << 19) / (2 * a + 1) + 1) / 2) as u16);
            }
        }
        self.a.bind32(skip);
        self.fp_tables[which] = Some(off);
        off
    }

    pub(super) fn fp_estimate(&mut self, q: bool, size: u8, scalar: bool, op: Simd2Op, rd: u32, rn: u32) -> bool {
        if size < 2 {
            return false;
        }
        let double = size == 3;
        let sqrt = op == Simd2Op::Frsqrte;
        let exp_only = op == Simd2Op::Frecpx;
        let fb = if double { 52 } else { 23 };
        let emax = if double { 2047 } else { 255 };
        self.fp_prologue();
        self.clobber();
        let mut slow = Slow::new();
        slow.push(self.fp_fz_guard());
        let table = if exp_only { 0 } else { self.fp_estimate_table(sqrt) };
        self.ld_vec(8, rn);
        self.fp_zero(9);
        let lanes = if scalar { 1 } else { (if q { 16 } else { 8 }) >> size };
        for i in 0..lanes {
            self.fp_lane(1 << size, i);
            if exp_only {
                slow.push(self.nan_guard_scalar(double, X14));
            }
            self.a.vmov_to_gpr(Sz::Q, RAX, X14);
            self.a.vmov_from_gpr(Sz::Q, 11, RAX);
            if sqrt {
                self.a.test_rr(if double { Sz::Q } else { Sz::D }, RAX, RAX);
                slow.push(self.a.jcc(Cc::S, None));
            }
            self.a.shift_ri(Shift::Shr, Sz::Q, RAX, fb);
            self.a.alu_ri(Alu::And, Sz::D, Rm::R(RAX), emax);
            if exp_only {
                let normal = self.a.jcc(Cc::Ne, None);
                self.a.mov_ri32(RAX, 1);
                self.a.bind32(normal);
                self.a.alu_ri(Alu::Xor, Sz::D, Rm::R(RAX), emax);
            } else {
                slow.push(self.a.jcc(Cc::E, None));
                self.a.alu_ri(Alu::Cmp, Sz::D, Rm::R(RAX), if sqrt { emax } else { emax - 2 });
                slow.push(self.a.jcc(Cc::Ae, None));
                self.a.vmov_from_gpr(Sz::D, 10, RAX); // original exponent/parity
                self.a.mov_ri32(
                    RDX,
                    if sqrt {
                        if double {
                            3068
                        } else {
                            380
                        }
                    } else {
                        (emax - 2) as u32
                    },
                );
                self.a.alu_rr(Alu::Sub, Sz::D, RDX, RAX);
                if sqrt {
                    self.a.shift_ri(Shift::Shr, Sz::D, RDX, 1);
                }
                self.a.mov_rr(Sz::D, RAX, RDX);
            }
            self.a.shift_ri(Shift::Shl, Sz::Q, RAX, fb);
            self.a.vmov_from_gpr(Sz::Q, 12, RAX); // output exponent
            if !exp_only {
                self.a.vmov_to_gpr(Sz::Q, RAX, 11);
                self.a.shift_ri(Shift::Shr, Sz::Q, RAX, fb - 8);
                self.a.alu_ri(Alu::And, Sz::D, Rm::R(RAX), 255);
                if sqrt {
                    self.a.vmov_to_gpr(Sz::D, RDX, 10);
                    self.a.test_ri(Sz::D, Rm::R(RDX), 1);
                    let even = self.a.jcc(Cc::E, None);
                    self.a.shift_ri(Shift::Shr, Sz::D, RAX, 1);
                    let indexed = self.a.jmp(None);
                    self.a.bind32(even);
                    self.a.alu_ri(Alu::Add, Sz::D, Rm::R(RAX), 128);
                    self.a.bind32(indexed);
                }
                self.a.lea(Sz::Q, RDX, Mem::rip(table as i32));
                self.a.movzx(Sz::W, RAX, Rm::M(Mem::bisd(RDX, RAX, 1, 0)));
                self.a.alu_ri(Alu::And, Sz::D, Rm::R(RAX), 255);
                self.a.shift_ri(Shift::Shl, Sz::Q, RAX, fb - 8);
                self.a.vmov_to_gpr(Sz::Q, RDX, 12);
                self.a.alu_rr(Alu::Or, Sz::Q, RAX, RDX);
            } else {
                self.a.vmov_to_gpr(Sz::Q, RAX, 12);
            }
            if !sqrt {
                self.a.vmov_to_gpr(Sz::Q, RDX, 11);
                self.a.shift_ri(Shift::Shr, Sz::Q, RDX, if double { 63 } else { 31 });
                self.a.shift_ri(Shift::Shl, Sz::Q, RDX, if double { 63 } else { 31 });
                self.a.alu_rr(Alu::Or, Sz::Q, RAX, RDX);
            }
            self.a.vmov_from_gpr(Sz::Q, X14, RAX);
            self.fp_pack(1 << size, i);
        }
        self.store_vec(rd, 9);
        self.slow_paths(slow.as_slice());
        true
    }

    /// Guard before arithmetic: FMULX and reciprocal-step instructions
    /// define 0*infinity without IOC, unlike an ordinary host multiply.
    pub(super) fn fp_finite(&mut self, double: bool, x: u8) -> usize {
        self.fp_bits(10, double, if double { 0x7ff0_0000_0000_0000 } else { 0x7f80_0000 });
        self.a.vex(1, PP_66, false, false, 0xdb, X13, x, Rm::R(10));
        self.a.vex(
            if double { 2 } else { 1 },
            PP_66,
            false,
            false,
            if double { 0x29 } else { 0x76 },
            X13,
            X13,
            Rm::R(10),
        );
        self.fp_test_mask(X13)
    }

    pub(super) fn fp_special(&mut self, q: bool, size: u8, scalar: bool, op: SimdOp, rd: u32, rn: u32, rm: u32) -> bool {
        if size < 2 {
            return false;
        }
        let double = size == 3;
        self.fp_prologue();
        let mut slow = Slow::new();
        slow.push(self.fp_fz_guard());
        self.fp_active(X14, double, scalar, q, rn);
        self.fp_active(X15, double, scalar, q, rm);
        let pp = if scalar {
            if double {
                PP_F2
            } else {
                PP_F3
            }
        } else if double {
            PP_66
        } else {
            PP_NONE
        };
        if op == SimdOp::FAbd {
            self.a.vex(1, pp, false, false, 0x5c, X14, X14, Rm::R(X15));
            self.fp_abs_bits(double, X14);
            slow.push(self.fp_nan(double, scalar, X14));
        } else {
            slow.push(self.fp_finite(double, X14));
            slow.push(self.fp_finite(double, X15));
            if op == SimdOp::FMulx {
                self.a.vex(1, pp, false, false, 0x59, X14, X14, Rm::R(X15));
            } else {
                if op == SimdOp::FRsqrts {
                    // Halve one factor exactly before the fused operation.
                    // Subnormal/tiny inputs need the softfloat path.
                    self.fp_bits(10, double, if double { 0x7fff_ffff_ffff_ffff } else { 0x7fff_ffff });
                    self.a.vex(1, PP_66, false, false, 0xdb, 10, X14, Rm::R(10));
                    self.fp_power(12, double, if double { -1021 } else { -125 });
                    self.a
                        .vex_ib(1, if double { PP_66 } else { PP_NONE }, false, false, 0xc2, X13, 10, Rm::R(12), 1);
                    // Ignore inactive lanes and genuine zero factors.
                    self.fp_zero(12);
                    self.a
                        .vex_ib(1, if double { PP_66 } else { PP_NONE }, false, false, 0xc2, 10, 10, Rm::R(12), 4);
                    self.a.vex(1, PP_66, false, false, 0xdb, X13, X13, Rm::R(10));
                    slow.push(self.fp_test_mask(X13));
                    self.fp_power(12, double, -1);
                    self.a.vex(1, pp, false, false, 0x59, X14, X14, Rm::R(12));
                }
                self.fp_bits(
                    12,
                    double,
                    if op == SimdOp::FRecps {
                        if double {
                            0x4000_0000_0000_0000
                        } else {
                            0x4000_0000
                        }
                    } else if double {
                        0x3ff8_0000_0000_0000
                    } else {
                        0x3fc0_0000
                    },
                );
                self.a.vex(2, PP_66, double, false, 0xbc + scalar as u8, 12, X14, Rm::R(X15)); // VFN MADD231
                self.a.vex(1, PP_F3, false, false, 0x6f, X14, 0, Rm::R(12));
            }
        }
        slow.push(self.fp_underflow_boundary(double, X14));
        self.fp_commit(double, scalar, q, rd);
        self.slow_paths(slow.as_slice());
        true
    }
}
