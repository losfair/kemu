// SPDX-License-Identifier: GPL-2.0
//! Block-local vector register cache. A fixed allocation keeps recovery
//! simple: the page is authoritative while filling, XMM0..7 while live
//! (including while spilling). Scratch results commit in one instruction.

use super::*;
use super::fp::voff;
use crate::decode::FcvtOp;

pub(super) fn choose(insns: &[Insn], sha: bool) -> [u8; meta::VECTOR_REGS] {
    let mut uses = [0u16; 32];
    let has_loop = insns.iter().enumerate().any(|(idx, i)| match i {
        Insn::B { imm } | Insn::BCond { imm, .. } | Insn::Cbz { imm, .. }
        | Insn::Tbz { imm, .. } => *imm == -(idx as i64 * 4),
        _ => false,
    });
    for &i in insns {
        let mut add = |r: u32| uses[(r & 31) as usize] += 1;
        match i {
            Insn::FpImm { rd, .. } | Insn::SimdModImm { rd, .. }
            | Insn::SimdInsGpr { rd, .. } | Insn::SimdDup { from_gpr: true, rd, .. } => add(rd),
            Insn::FpCmp { rn, rm, zero, .. } => { add(rn); if !zero { add(rm); } }
            Insn::FpCCmp { rn, rm, .. } => { add(rn); add(rm); }
            Insn::SimdUmov { rn, .. } | Insn::SimdSmov { rn, .. } => add(rn),
            Insn::FpCvt { op, rd, rn, .. } => match op {
                FcvtOp::Fmov { to_fp: true, .. } | FcvtOp::ItoF { .. } | FcvtOp::FixedToF { .. } => add(rd),
                _ => add(rn),
            },
            Insn::Fp1 { rd, rn, .. } | Insn::SimdMisc { rd, rn, .. }
            | Insn::SimdAcross { rd, rn, .. } | Insn::SimdDup { rd, rn, .. }
            | Insn::SimdInsElt { rd, rn, .. } | Insn::SimdShift { rd, rn, .. }
            | Insn::SimdScalarCopy { rd, rn, .. } | Insn::Aese { rd, rn }
            | Insn::Aesd { rd, rn } | Insn::Aesmc { rd, rn } | Insn::Aesimc { rd, rn } => {
                add(rd); add(rn);
            }
            Insn::FpCSel { rd, rn, rm, .. } | Insn::Fp2 { rd, rn, rm, .. }
            | Insn::SimdThree { rd, rn, rm, .. } | Insn::SimdExt { rd, rn, rm, .. }
            | Insn::SimdPermute { rd, rn, rm, .. } | Insn::SimdIndexed { rd, rn, rm, .. }
            | Insn::Sha1 { rd, rn, rm, .. } | Insn::Sha256 { rd, rn, rm, .. } => {
                add(rd); add(rn); add(rm);
            }
            Insn::Fp3 { rd, rn, rm, ra, .. } => { add(rd); add(rn); add(rm); add(ra); }
            Insn::LdSt { fp: true, rt, .. } | Insn::LdStLiteral { fp: true, rt, .. }
            | Insn::LdStReg { fp: true, rt, .. } => add(rt),
            Insn::LdStPair { fp: true, rt, rt2, .. } => { add(rt); add(rt2); }
            Insn::SimdLdSt { rt, opcode, single: false, .. } => {
                let n = match opcode { 7 => 1, 10 => 2, 6 => 3, 2 => 4, _ => 0 };
                for j in 0..n { add(rt + j); }
            }
            Insn::SimdLdSt { rt, replicate: true, .. } => add(rt),
            Insn::SimdTbl { rd, rn, rm, len, .. } => {
                add(rd); add(rm);
                for j in 0..=len as u32 { add(rn + j); }
            }
            _ => {}
        }
    }
    let mut map = [meta::NO_VECTOR; meta::VECTOR_REGS];
    // SHA256RNDS2 implicitly reads XMM0. Do not keep a guest value there
    // in blocks using it, so interrupt recovery needs no special spills.
    let reserve = usize::from(sha && insns.iter().any(|i| matches!(i, Insn::Sha256 { op: 4 | 5, .. })));
    for slot in &mut map[reserve..] {
        let mut best = 0;
        for r in 1..32 {
            if uses[r] > uses[best] { best = r; }
        }
        // A fill and a spill cost two memory accesses. In a self-loop
        // they are amortized across iterations, so even an operand used
        // only once per iteration is worth caching. Ties favor low Vn.
        if uses[best] <= if has_loop { 0 } else { 2 } { break; }
        *slot = best as u8;
        uses[best] = 0;
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn promote_single_use_loop_input() {
        let mut insns = [decode::decode(0x4ee18400), decode::decode(0xb5ffffe0)];
        // add v0.2d,v0.2d,v1.2d; cbnz x0,pc0. V1 is read just once.
        assert_eq!(choose(&insns, false)[..3], [0, 1, meta::NO_VECTOR]);
        insns[1] = Insn::Ret { rn: 30 };
        assert_eq!(choose(&insns, false), [meta::NO_VECTOR; meta::VECTOR_REGS]);
    }
}

impl<'s, 'b> Gen<'s, 'b> {
    pub(super) fn vector_prologue(&mut self) {
        if self.vlive || self.vectors.iter().all(|&v| v == meta::NO_VECTOR) { return; }
        for (x, &g) in self.vectors.iter().enumerate() {
            if g < 32 { self.a.vmovdqu_load(x as u8, Mem::gs(voff(g as u32))); }
        }
        self.vlive = true;
        self.point(kind::VSTATE, 1, 0);
    }

    pub(super) fn vector_epilogue(&mut self) {
        if !self.vlive { return; }
        for (x, &g) in self.vectors.iter().enumerate() {
            if g < 32 { self.a.vmovdqu_store(Mem::gs(voff(g as u32)), x as u8); }
        }
        self.vlive = false;
        self.point(kind::VSTATE, 0, 0);
    }

    pub(super) fn vector_host(&self, n: u32) -> Option<u8> {
        if !self.vlive { return None; }
        self.vectors.iter().position(|&g| g as u32 == n).map(|x| x as u8)
    }

    pub(super) fn v_rm(&self, n: u32) -> Rm {
        self.vector_host(n).map(Rm::R).unwrap_or(Rm::M(Mem::gs(voff(n))))
    }

    pub(super) fn ld_vec(&mut self, x: u8, n: u32) {
        self.a.vex(1, 2, false, false, 0x6f, x, 0, self.v_rm(n));
    }

    pub(super) fn store_vec(&mut self, n: u32, x: u8) {
        match self.vector_host(n) {
            Some(d) => self.a.vex(1, 2, false, false, 0x6f, d, 0, Rm::R(x)),
            None => self.a.vmovdqu_store(Mem::gs(voff(n)), x),
        }
    }

    /// Return a vector operand starting at a byte offset, using `tmp`
    /// when a cached value needs shifting. Does not change guest flags.
    pub(super) fn vector_slice(&mut self, n: u32, off: u8, tmp: u8) -> Rm {
        match self.vector_host(n) {
            Some(x) if off != 0 => {
                self.a.vex_ib(1, 1, false, false, 0x73, 3, tmp, Rm::R(x), off);
                Rm::R(tmp)
            }
            Some(x) => Rm::R(x),
            None => Rm::M(Mem::gs(voff(n) + off as i32)),
        }
    }

    /// Zero-extend one lane into a host GPR, without modifying flags.
    pub(super) fn vector_extract(&mut self, sz: Sz, dst: Reg, n: u32, lane: u8) {
        if let Some(x) = self.vector_host(n) {
            if lane == 0 && matches!(sz, Sz::D | Sz::Q) {
                self.a.vmov_to_gpr(sz, dst, x);
            } else {
                let opc = match sz { Sz::B => 0x14, Sz::W => 0x15, _ => 0x16 };
                self.a.vex_ib(3, 1, sz == Sz::Q, false, opc, x, 0, Rm::R(dst), lane);
            }
        } else {
            let bytes = match sz { Sz::B => 1, Sz::W => 2, Sz::D => 4, Sz::Q => 8 };
            let m = Mem::gs(voff(n) + lane as i32 * bytes);
            match sz {
                Sz::B | Sz::W => self.a.movzx(sz, dst, Rm::M(m)),
                _ => self.a.load(sz, dst, m),
            }
        }
    }

    /// Insert one lane in a single commit; all other lanes are preserved.
    pub(super) fn vector_insert(&mut self, sz: Sz, n: u32, lane: u8, src: Reg) {
        if let Some(x) = self.vector_host(n) {
            let (map, opc) = match sz { Sz::B => (3, 0x20), Sz::W => (1, 0xc4), _ => (3, 0x22) };
            self.a.vex_ib(map, 1, sz == Sz::Q, false, opc, x, x, Rm::R(src), lane);
        } else {
            let bytes = match sz { Sz::B => 1, Sz::W => 2, Sz::D => 4, Sz::Q => 8 };
            self.a.store(sz, Mem::gs(voff(n) + lane as i32 * bytes), src);
        }
    }
}
