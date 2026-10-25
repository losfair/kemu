// SPDX-License-Identifier: GPL-2.0
//! System registers used by libc. FP control/status writes update live
//! MXCSR before committing the state-page register. Recovery rolls that
//! write forward once MXCSR changes, preserving atomic control/status
//! updates even when a signal arrives between the two host instructions.

use super::*;
use crate::{softfloat, sysregs};

impl<'s, 'b> Gen<'s, 'b> {
    pub(super) fn mrs(&mut self, rt: u32, enc: u32) -> bool {
        let (off, sz) = match enc {
            0xde82 => (OFF_TPIDR, Sz::Q),
            0xde83 => (OFF_TPIDRRO, Sz::Q),
            0xda20 => (OFF_FPCR, Sz::D),
            0xda21 => {
                self.clobber();
                self.save_mxcsr();
                self.a.load(Sz::D, RAX, Mem::gs(OFF_MXCSR));
                self.a.mov_rr(Sz::D, RDX, RAX);
                self.a.alu_ri(Alu::And, Sz::D, Rm::R(RAX), 0x3c);
                self.a.shift_ri(Shift::Shr, Sz::D, RAX, 1);
                self.a.alu_ri(Alu::And, Sz::D, Rm::R(RDX), 1);
                self.a.alu_rr(Alu::Or, Sz::D, RAX, RDX);
                self.a.alu_rm(Alu::Or, Sz::D, RAX, Rm::M(Mem::gs(OFF_FPSR)));
                self.put(rt, false, RAX);
                return true;
            }
            0xd801 | 0xd807 => {
                self.mov_imm(RAX, if enc == 0xd801 { sysregs::CTR_EL0 } else { sysregs::DCZID_EL0 });
                self.put(rt, false, RAX);
                return true;
            }
            _ => return false,
        };
        match self.gp(rt, false) {
            Gp::R(r) => self.a.load(sz, r, Mem::gs(off)),
            Gp::M(o) => {
                self.a.load(sz, RAX, Mem::gs(off));
                self.a.store(Sz::Q, Mem::gs(o), RAX);
            }
            Gp::Zero => {}
        }
        true
    }

    fn save_mxcsr(&mut self) {
        self.a.vex(1, 0, false, false, 0xae, 3, 0, Rm::M(Mem::gs(OFF_MXCSR)));
    }

    /// Add a shifted subset of the saved source to the new MXCSR in RDX.
    fn mxcsr_bits(&mut self, mask: i32, shift: i8) {
        self.a.vmov_to_gpr(Sz::D, RAX, 15);
        self.a.alu_ri(Alu::And, Sz::D, Rm::R(RAX), mask);
        if shift != 0 {
            self.a.shift_ri(if shift > 0 { Shift::Shl } else { Shift::Shr },
                            Sz::D, RAX, shift.unsigned_abs());
        }
        self.a.alu_rr(Alu::Or, Sz::D, RDX, RAX);
    }

    pub(super) fn msr(&mut self, rt: u32, enc: u32) -> bool {
        if enc == 0xde82 {
            let v = self.get(rt, false, RAX);
            self.a.store(Sz::Q, Mem::gs(OFF_TPIDR), v);
            return true;
        }
        if !matches!(enc, 0xda20 | 0xda21) { return false; }
        self.clobber();
        self.get_into(rt, false, Sz::D, RAX);
        self.a.alu_ri(Alu::And, Sz::D, Rm::R(RAX),
                      if enc == 0xda20 { softfloat::FPCR_MASK } else { softfloat::FPSR_MASK } as i32);
        self.a.vmov_from_gpr(Sz::D, 15, RAX);
        self.save_mxcsr();
        self.a.load(Sz::D, RDX, Mem::gs(OFF_MXCSR));
        if enc == 0xda20 {
            // Preserve cumulative exceptions, replace rounding and DAZ/FTZ.
            self.a.alu_ri(Alu::And, Sz::D, Rm::R(RDX), !0xe040);
            self.mxcsr_bits(1 << 22, -8);
            self.mxcsr_bits(1 << 23, -10);
            self.mxcsr_bits(1 << 24, -9);
            self.mxcsr_bits(1 << 24, -18);
        } else {
            // Replace exception bits (DE is not an ARM exception flag).
            self.a.alu_ri(Alu::And, Sz::D, Rm::R(RDX), !0x3f);
            self.mxcsr_bits(1, 0);
            self.mxcsr_bits(0x1e, 1);
        }
        self.a.store(Sz::D, Mem::gs(OFF_MXCSR), RDX);
        self.a.vmov_to_gpr(Sz::D, RAX, 15);
        self.a.vex(1, 0, false, false, 0xae, 2, 0, Rm::M(Mem::gs(OFF_MXCSR)));
        self.point(kind::ROLL_FP, (enc == 0xda21) as u8, RAX);
        self.a.store(Sz::D, Mem::gs(if enc == 0xda20 { OFF_FPCR } else { OFF_FPSR }), RAX);
        true
    }
}
