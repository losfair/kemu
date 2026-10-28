// SPDX-License-Identifier: GPL-2.0
//! Integer NEON operations used by JSON parsing, GC bitsets and deflate.

use super::*;

impl<'s, 'b> Gen<'s, 'b> {
    pub(super) fn simd_cmtst(&mut self, q: bool, size: u8, rd: u32, rn: u32, rm: u32) -> bool {
        self.ld_vec(X14, rn);
        if rn != rm {
            self.a.vex(1, PP_66, false, false, 0xdb, X14, X14, self.v_rm(rm));
        }
        self.a.vex(1, PP_66, false, false, 0xef, X15, X15, Rm::R(X15));
        // Compare each AND result with zero, then invert the lane masks.
        let (map, op) = if size == 3 { (2, 0x29) } else { (1, 0x74 + size) };
        self.a.vex(map, PP_66, false, false, op, X14, X14, Rm::R(X15));
        self.a.vex(1, PP_66, false, false, 0x76, X15, X15, Rm::R(X15));
        self.a.vex(1, PP_66, false, false, 0xef, X14, X14, Rm::R(X15));
        self.st_vec(q, X14, rd);
        true
    }

    pub(super) fn simd_uminv(&mut self, q: bool, size: u8, rd: u32, rn: u32) -> bool {
        if size < 2 { self.clobber(); }
        self.ld_vec(X14, rn);
        let (map, op) = if size == 0 { (1, 0xda) } else { (2, 0x39 + size) };
        // Only the low lane is needed; avoid including inactive upper lanes
        // in the 64-bit forms (their contents need not be zero).
        let mut bytes = if q { 8 } else { 4 };
        while bytes >= 1 << size {
            self.a.vex_ib(1, PP_66, false, false, 0x73, 3, X15, Rm::R(X14), bytes);
            self.a.vex(map, PP_66, false, false, op, X14, X14, Rm::R(X15));
            bytes >>= 1;
        }
        self.a.vmov_to_gpr(Sz::D, RAX, X14);
        if size < 2 {
            self.a.alu_ri(Alu::And, Sz::D, Rm::R(RAX), if size == 0 { 0xff } else { 0xffff });
        }
        self.a.vmov_from_gpr(Sz::D, X14, RAX);
        self.store_vec(rd, X14);
        true
    }

    pub(super) fn simd_uqsub(&mut self, q: bool, size: u8, rd: u32, rn: u32, rm: u32) -> bool {
        // Unlike x86 packed saturation, ARM also sets sticky FPSR.QC.
        // Compute the new FPSR before committing either architectural value.
        self.flags_to_mem();
        self.clobber();
        self.ld_vec(X14, rn);
        self.ld_vec(X15, rm);
        self.a.vex(1, PP_66, false, false, 0xd8 + size, X13, X14, Rm::R(X15)); // vpsubusb/w
        self.a.vex(1, PP_66, false, false, 0xf8 + size, X14, X14, Rm::R(X15)); // wrapping subtract
        self.a.vex(1, PP_66, false, false, 0x74 + size, X14, X14, Rm::R(X13));
        self.a.vex(1, PP_66, false, false, 0xd7, RAX, 0, Rm::R(X14)); // vpmovmskb
        let mask = if q { 0xffff } else { 0xff };
        if !q { self.a.alu_ri(Alu::And, Sz::D, Rm::R(RAX), mask); }
        self.a.alu_ri(Alu::Cmp, Sz::D, Rm::R(RAX), mask);
        self.a.setcc(Cc::Ne, RAX);
        self.a.movzx(Sz::B, RAX, Rm::R(RAX));
        self.a.shift_ri(Shift::Shl, Sz::D, RAX, 27);
        self.a.alu_rm(Alu::Or, Sz::D, RAX, Rm::M(Mem::gs(OFF_FPSR)));
        self.st_vec(q, X13, rd);
        // An interrupt after the vector commit must also commit FPSR, even
        // when Rd aliases an input: restarting would subtract twice.
        self.point(kind::ROLL_FP, 1, RAX);
        self.a.store(Sz::D, Mem::gs(OFF_FPSR), RAX);
        true
    }

    pub(super) fn simd_ushl(&mut self, q: bool, size: u8, rd: u32, rn: u32, rm: u32) -> bool {
        self.ld_vec(X15, rm);
        let qword = size == 3;
        let group = if qword { 0x73 } else { 0x72 };
        let shift = if qword { 56 } else { 24 };
        // ARM uses only the signed low byte of each shift count. For a
        // negative byte, the zero-extended count is >=128, so AVX2 zeros
        // the left shift. 256-count is its right-shift magnitude; for a
        // nonnegative byte it is out of range and the right shift is zero.
        self.a.vex_ib(1, PP_66, false, false, group, 6, X15, Rm::R(X15), shift);
        self.a.vex_ib(1, PP_66, false, false, group, 2, X15, Rm::R(X15), shift);
        self.ld_vec(X14, rn);
        self.a.vex(2, PP_66, qword, false, 0x47, X13, X14, Rm::R(X15));
        if qword {
            self.a.mov_ri32(RAX, 256);
            self.a.vmov_from_gpr(Sz::Q, X14, RAX);
            self.a.vex(2, PP_66, false, false, 0x59, X14, 0, Rm::R(X14));
        } else {
            self.splat32(X14, 256);
        }
        self.a.vex(1, PP_66, false, false, if qword { 0xfb } else { 0xfa }, X15, X14, Rm::R(X15));
        self.ld_vec(X14, rn);
        self.a.vex(2, PP_66, qword, false, 0x45, X14, X14, Rm::R(X15));
        self.a.vex(1, PP_66, false, false, 0xeb, X14, X14, Rm::R(X13));
        self.st_vec(q, X14, rd);
        true
    }
}
