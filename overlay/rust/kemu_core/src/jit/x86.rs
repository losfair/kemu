// SPDX-License-Identifier: GPL-2.0
//! Minimal x86-64 machine code encoder for the JIT.
//!
//! Emits into a caller-provided buffer; never allocates or panics. On
//! overflow the assembler sets `err` and keeps counting `pos`, so callers
//! check `ok()` once at the end.

pub type Reg = u8;

pub const RAX: Reg = 0;
pub const RCX: Reg = 1;
pub const RDX: Reg = 2;
pub const RBX: Reg = 3;
pub const RSP: Reg = 4;
pub const RBP: Reg = 5;
pub const RSI: Reg = 6;
pub const RDI: Reg = 7;
pub const R8: Reg = 8;
pub const R9: Reg = 9;
pub const R10: Reg = 10;
pub const R11: Reg = 11;
pub const R12: Reg = 12;
pub const R13: Reg = 13;
pub const R14: Reg = 14;
pub const R15: Reg = 15;

/// Operand size.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sz {
    B,
    W,
    D,
    Q,
}

impl Sz {
    pub fn from_sf(sf: bool) -> Sz {
        if sf {
            Sz::Q
        } else {
            Sz::D
        }
    }
    pub fn bytes(self) -> u32 {
        match self {
            Sz::B => 1,
            Sz::W => 2,
            Sz::D => 4,
            Sz::Q => 8,
        }
    }
}

/// x86 condition codes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Cc {
    O = 0,
    No = 1,
    B = 2,
    Ae = 3,
    E = 4,
    Ne = 5,
    Be = 6,
    A = 7,
    S = 8,
    Ns = 9,
    P = 10,
    Np = 11,
    L = 12,
    Ge = 13,
    Le = 14,
    G = 15,
}

impl Cc {
    pub fn invert(self) -> Cc {
        Cc::from_u8(self as u8 ^ 1)
    }
    pub fn from_u8(v: u8) -> Cc {
        match v & 15 {
            0 => Cc::O,
            1 => Cc::No,
            2 => Cc::B,
            3 => Cc::Ae,
            4 => Cc::E,
            5 => Cc::Ne,
            6 => Cc::Be,
            7 => Cc::A,
            8 => Cc::S,
            9 => Cc::Ns,
            10 => Cc::P,
            11 => Cc::Np,
            12 => Cc::L,
            13 => Cc::Ge,
            14 => Cc::Le,
            _ => Cc::G,
        }
    }
}

/// ALU operations sharing the classic 8-op encoding.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Alu {
    Add = 0,
    Or = 1,
    Adc = 2,
    Sbb = 3,
    And = 4,
    Sub = 5,
    Xor = 6,
    Cmp = 7,
}

/// Shift/rotate group-2 operations.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Shift {
    Rol = 0,
    Ror = 1,
    Shl = 4,
    Shr = 5,
    Sar = 7,
}

const NO_REG: u8 = 0xff;

/// Memory operand.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Mem {
    pub base: u8,
    pub index: u8,
    pub scale: u8,
    pub disp: i32,
    pub gs: bool,
    pub rip: bool,
}

impl Mem {
    pub const fn b(base: Reg) -> Mem {
        Mem { base, index: NO_REG, scale: 0, disp: 0, gs: false, rip: false }
    }
    pub const fn bd(base: Reg, disp: i32) -> Mem {
        Mem { base, index: NO_REG, scale: 0, disp, gs: false, rip: false }
    }
    /// `[base + index << scale + disp]`, scale in 0..=3.
    pub const fn bisd(base: Reg, index: Reg, scale: u8, disp: i32) -> Mem {
        Mem { base, index, scale: scale & 3, disp, gs: false, rip: false }
    }
    /// `[index << scale + disp]` without base.
    pub const fn isd(index: Reg, scale: u8, disp: i32) -> Mem {
        Mem { base: NO_REG, index, scale: scale & 3, disp, gs: false, rip: false }
    }
    /// `gs:[disp]` (absolute displacement in the GS segment).
    pub const fn gs(disp: i32) -> Mem {
        Mem { base: NO_REG, index: NO_REG, scale: 0, disp, gs: true, rip: false }
    }
    /// `[rip + disp]`, disp relative to the end of the instruction.
    pub const fn rip(disp: i32) -> Mem {
        Mem { base: NO_REG, index: NO_REG, scale: 0, disp, gs: false, rip: true }
    }
}

/// Register-or-memory operand.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Rm {
    R(Reg),
    M(Mem),
}

impl From<Reg> for Rm {
    fn from(r: Reg) -> Rm {
        Rm::R(r)
    }
}

impl From<Mem> for Rm {
    fn from(m: Mem) -> Rm {
        Rm::M(m)
    }
}

pub struct Asm<'a> {
    buf: &'a mut [u8],
    pub pos: usize,
    pub err: bool,
    /// Position just after the last emitted instruction's displacement,
    /// used to fix up RIP-relative operands with trailing immediates.
    rip_fixup: Option<(usize, usize)>,
}

impl<'a> Asm<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Asm { buf, pos: 0, err: false, rip_fixup: None }
    }

    pub fn ok(&self) -> bool {
        !self.err && self.pos <= self.buf.len()
    }

    pub fn code(&self) -> &[u8] {
        let n = if self.pos <= self.buf.len() { self.pos } else { self.buf.len() };
        self.buf.get(..n).unwrap_or(&[])
    }

    #[inline]
    pub fn byte(&mut self, b: u8) {
        match self.buf.get_mut(self.pos) {
            Some(x) => *x = b,
            None => self.err = true,
        }
        self.pos = self.pos.wrapping_add(1);
    }

    pub fn bytes(&mut self, bs: &[u8]) {
        for b in bs {
            self.byte(*b);
        }
    }

    pub fn u16(&mut self, v: u16) {
        self.bytes(&v.to_le_bytes());
    }
    pub fn u32(&mut self, v: u32) {
        self.bytes(&v.to_le_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.bytes(&v.to_le_bytes());
    }

    /// Overwrite a 32-bit little-endian field at `at`.
    pub fn patch_u32(&mut self, at: usize, v: u32) {
        for (i, b) in v.to_le_bytes().iter().enumerate() {
            match self.buf.get_mut(at.wrapping_add(i)) {
                Some(x) => *x = *b,
                None => self.err = true,
            }
        }
    }

    /// Patch a rel32 field at `at` (pointing at the field) to jump to `target`.
    pub fn patch_rel32(&mut self, at: usize, target: usize) {
        let rel = (target as i64).wrapping_sub(at as i64 + 4);
        self.patch_u32(at, rel as i32 as u32);
    }

    /// Pad with int3 (not executed).
    pub fn align(&mut self, a: usize) {
        while self.pos % a != 0 {
            self.byte(0xcc);
        }
    }

    /// Pad with nops (falls through).
    pub fn align_nop(&mut self, a: usize) {
        while self.pos % a != 0 {
            self.byte(0x90);
        }
    }

    // ---- prefix / ModRM machinery ----

    fn rex_rm(&mut self, w: bool, reg: u8, rm: &Rm, byte_reg: bool) {
        let r = (reg >> 3) & 1;
        let (x, b) = match rm {
            Rm::R(rr) => (0, (rr >> 3) & 1),
            Rm::M(m) => {
                let x = if m.index != NO_REG { (m.index >> 3) & 1 } else { 0 };
                let b = if m.base != NO_REG && !m.rip { (m.base >> 3) & 1 } else { 0 };
                (x, b)
            }
        };
        let force = byte_reg
            && ((4..8).contains(&reg) || matches!(rm, Rm::R(rr) if (4..8).contains(rr)));
        let rex = 0x40 | ((w as u8) << 3) | (r << 2) | (x << 1) | b;
        if rex != 0x40 || force {
            self.byte(rex);
        }
    }

    fn modrm(&mut self, reg: u8, rm: &Rm) {
        let reg = reg & 7;
        match *rm {
            Rm::R(r) => self.byte(0xc0 | (reg << 3) | (r & 7)),
            Rm::M(m) => {
                if m.rip {
                    self.byte((reg << 3) | 5);
                    let at = self.pos;
                    self.u32(m.disp as u32);
                    self.rip_fixup = Some((at, m.disp as usize));
                    return;
                }
                if m.base == NO_REG {
                    // [index*s + disp32] or absolute [disp32]
                    self.byte((reg << 3) | 4);
                    let idx = if m.index == NO_REG { 4 } else { m.index & 7 };
                    self.byte((m.scale << 6) | (idx << 3) | 5);
                    self.u32(m.disp as u32);
                    return;
                }
                let need_sib = m.index != NO_REG || (m.base & 7) == 4;
                let md = if m.disp == 0 && (m.base & 7) != 5 {
                    0
                } else if (-128..=127).contains(&m.disp) {
                    1
                } else {
                    2
                };
                if need_sib {
                    self.byte((md << 6) | (reg << 3) | 4);
                    let idx = if m.index == NO_REG { 4 } else { m.index & 7 };
                    self.byte((m.scale << 6) | (idx << 3) | (m.base & 7));
                } else {
                    self.byte((md << 6) | (reg << 3) | (m.base & 7));
                }
                match md {
                    1 => self.byte(m.disp as i8 as u8),
                    2 => self.u32(m.disp as u32),
                    _ => {}
                }
            }
        }
    }

    fn seg(&mut self, rm: &Rm) {
        if let Rm::M(m) = rm {
            if m.gs {
                self.byte(0x65);
            }
        }
    }

    /// Fix up a RIP-relative displacement once the full instruction
    /// length is known (the displacement was given relative to the
    /// instruction end, but immediates may follow it).
    fn end_insn(&mut self) {
        if let Some((at, disp)) = self.rip_fixup.take() {
            // disp was the absolute target offset in the buffer.
            let rel = (disp as i64).wrapping_sub(self.pos as i64);
            self.patch_u32(at, rel as i32 as u32);
        }
    }

    /// Generic legacy-encoded instruction: [seg] [mandatory/66] [REX] op modrm.
    fn op_rm(&mut self, prefix: Option<u8>, sz: Sz, opc: &[u8], reg: u8, rm: Rm) {
        self.seg(&rm);
        if sz == Sz::W {
            self.byte(0x66);
        }
        if let Some(p) = prefix {
            self.byte(p);
        }
        self.rex_rm(sz == Sz::Q, reg, &rm, sz == Sz::B);
        self.bytes(opc);
        self.modrm(reg, &rm);
    }

    // ---- integer instructions ----

    /// `op r/m, reg`
    pub fn alu_mr(&mut self, op: Alu, sz: Sz, dst: Rm, src: Reg) {
        let opc = if sz == Sz::B { (op as u8) << 3 } else { ((op as u8) << 3) | 1 };
        self.op_rm(None, sz, &[opc], src, dst);
        self.end_insn();
    }

    /// `op reg, r/m`
    pub fn alu_rm(&mut self, op: Alu, sz: Sz, dst: Reg, src: Rm) {
        let opc = if sz == Sz::B { ((op as u8) << 3) | 2 } else { ((op as u8) << 3) | 3 };
        self.op_rm(None, sz, &[opc], dst, src);
        self.end_insn();
    }

    pub fn alu_rr(&mut self, op: Alu, sz: Sz, dst: Reg, src: Reg) {
        self.alu_mr(op, sz, Rm::R(dst), src);
    }

    /// `op r/m, imm` (imm sign-extended to the operand size).
    pub fn alu_ri(&mut self, op: Alu, sz: Sz, dst: Rm, imm: i32) {
        if sz == Sz::B {
            self.op_rm(None, sz, &[0x80], op as u8, dst);
            self.byte(imm as u8);
        } else if (-128..=127).contains(&imm) {
            self.op_rm(None, sz, &[0x83], op as u8, dst);
            self.byte(imm as i8 as u8);
        } else {
            self.op_rm(None, sz, &[0x81], op as u8, dst);
            if sz == Sz::W {
                self.u16(imm as u16);
            } else {
                self.u32(imm as u32);
            }
        }
        self.end_insn();
    }

    pub fn test_rr(&mut self, sz: Sz, a: Reg, b: Reg) {
        let opc = if sz == Sz::B { 0x84 } else { 0x85 };
        self.op_rm(None, sz, &[opc], b, Rm::R(a));
    }

    pub fn test_ri(&mut self, sz: Sz, a: Rm, imm: i32) {
        if sz == Sz::B {
            self.op_rm(None, sz, &[0xf6], 0, a);
            self.byte(imm as u8);
        } else {
            self.op_rm(None, sz, &[0xf7], 0, a);
            if sz == Sz::W {
                self.u16(imm as u16);
            } else {
                self.u32(imm as u32);
            }
        }
        self.end_insn();
    }

    pub fn mov_rr(&mut self, sz: Sz, dst: Reg, src: Reg) {
        let opc = if sz == Sz::B { 0x88 } else { 0x89 };
        self.op_rm(None, sz, &[opc], src, Rm::R(dst));
    }

    /// Load `dst <- [m]` (32-bit loads zero-extend).
    pub fn load(&mut self, sz: Sz, dst: Reg, m: Mem) {
        let opc = if sz == Sz::B { 0x8a } else { 0x8b };
        self.op_rm(None, sz, &[opc], dst, Rm::M(m));
        self.end_insn();
    }

    /// Store `[m] <- src`.
    pub fn store(&mut self, sz: Sz, m: Mem, src: Reg) {
        let opc = if sz == Sz::B { 0x88 } else { 0x89 };
        self.op_rm(None, sz, &[opc], src, Rm::M(m));
        self.end_insn();
    }

    /// Store an immediate (sign-extended for Q).
    pub fn store_imm(&mut self, sz: Sz, m: Mem, imm: i32) {
        match sz {
            Sz::B => {
                self.op_rm(None, sz, &[0xc6], 0, Rm::M(m));
                self.byte(imm as u8);
            }
            Sz::W => {
                self.op_rm(None, sz, &[0xc7], 0, Rm::M(m));
                self.u16(imm as u16);
            }
            _ => {
                self.op_rm(None, sz, &[0xc7], 0, Rm::M(m));
                self.u32(imm as u32);
            }
        }
        self.end_insn();
    }

    /// Materialize a 64-bit constant with the shortest encoding.
    pub fn mov_ri(&mut self, dst: Reg, imm: u64) {
        if imm == 0 {
            self.alu_rr(Alu::Xor, Sz::D, dst, dst);
        } else if imm <= u32::MAX as u64 {
            self.mov_ri32(dst, imm as u32);
        } else if imm as i64 >= i32::MIN as i64 && imm as i64 <= i32::MAX as i64 {
            self.op_rm(None, Sz::Q, &[0xc7], 0, Rm::R(dst));
            self.u32(imm as u32);
        } else {
            self.mov_ri64(dst, imm);
        }
    }

    /// `mov r32, imm32` (zero-extends).
    pub fn mov_ri32(&mut self, dst: Reg, imm: u32) {
        if dst >= 8 {
            self.byte(0x41);
        }
        self.byte(0xb8 + (dst & 7));
        self.u32(imm);
    }

    /// `movabs r64, imm64` (always 10 bytes; used for patchable constants).
    pub fn mov_ri64(&mut self, dst: Reg, imm: u64) {
        self.byte(0x48 | ((dst >> 3) & 1));
        self.byte(0xb8 + (dst & 7));
        self.u64(imm);
    }

    /// Zero-extending load of 8/16 bits (`movzx r32, byte/word [m]`).
    pub fn movzx(&mut self, src_sz: Sz, dst: Reg, src: Rm) {
        let opc = if src_sz == Sz::B { 0xb6 } else { 0xb7 };
        self.seg(&src);
        self.rex_rm(false, dst, &src, src_sz == Sz::B);
        self.bytes(&[0x0f, opc]);
        self.modrm(dst, &src);
        self.end_insn();
    }

    /// Sign-extending move from 8/16/32 bits to `dst_sz` (D or Q).
    pub fn movsx(&mut self, src_sz: Sz, dst_sz: Sz, dst: Reg, src: Rm) {
        self.seg(&src);
        match src_sz {
            Sz::B | Sz::W => {
                let opc = if src_sz == Sz::B { 0xbe } else { 0xbf };
                self.rex_rm(dst_sz == Sz::Q, dst, &src, src_sz == Sz::B);
                self.bytes(&[0x0f, opc]);
            }
            _ => {
                self.rex_rm(true, dst, &src, false);
                self.byte(0x63);
            }
        }
        self.modrm(dst, &src);
        self.end_insn();
    }

    pub fn lea(&mut self, sz: Sz, dst: Reg, m: Mem) {
        self.op_rm(None, sz, &[0x8d], dst, Rm::M(m));
        self.end_insn();
    }

    /// Shift/rotate by immediate.
    pub fn shift_ri(&mut self, op: Shift, sz: Sz, dst: Reg, imm: u8) {
        if imm == 1 {
            let opc = if sz == Sz::B { 0xd0 } else { 0xd1 };
            self.op_rm(None, sz, &[opc], op as u8, Rm::R(dst));
        } else {
            let opc = if sz == Sz::B { 0xc0 } else { 0xc1 };
            self.op_rm(None, sz, &[opc], op as u8, Rm::R(dst));
            self.byte(imm);
        }
    }

    /// Shift/rotate by CL.
    pub fn shift_cl(&mut self, op: Shift, sz: Sz, dst: Reg) {
        let opc = if sz == Sz::B { 0xd2 } else { 0xd3 };
        self.op_rm(None, sz, &[opc], op as u8, Rm::R(dst));
    }

    /// `shld/shrd dst, src, imm`
    pub fn shrd_ri(&mut self, sz: Sz, dst: Reg, src: Reg, imm: u8) {
        self.op_rm(None, sz, &[0x0f, 0xac], src, Rm::R(dst));
        self.byte(imm);
    }

    /// Group-3 unary ops: 2=not, 3=neg, 4=mul, 5=imul, 6=div, 7=idiv.
    pub fn grp3(&mut self, sz: Sz, ext: u8, rm: Rm) {
        let opc = if sz == Sz::B { 0xf6 } else { 0xf7 };
        self.op_rm(None, sz, &[opc], ext, rm);
        self.end_insn();
    }

    pub fn not(&mut self, sz: Sz, r: Reg) {
        self.grp3(sz, 2, Rm::R(r));
    }
    pub fn neg(&mut self, sz: Sz, r: Reg) {
        self.grp3(sz, 3, Rm::R(r));
    }

    /// `imul dst, src`
    pub fn imul_rr(&mut self, sz: Sz, dst: Reg, src: Rm) {
        self.op_rm(None, sz, &[0x0f, 0xaf], dst, src);
        self.end_insn();
    }

    /// `cdq` / `cqo`
    pub fn cqo(&mut self, sz: Sz) {
        if sz == Sz::Q {
            self.byte(0x48);
        }
        self.byte(0x99);
    }

    /// F3-prefixed bit ops: 0xbd=lzcnt, 0xbc=tzcnt, 0xb8=popcnt.
    pub fn bitcnt(&mut self, opc: u8, sz: Sz, dst: Reg, src: Rm) {
        self.op_rm(Some(0xf3), sz, &[0x0f, opc], dst, src);
        self.end_insn();
    }

    pub fn bswap(&mut self, sz: Sz, r: Reg) {
        self.rex_rm(sz == Sz::Q, 0, &Rm::R(r), false);
        self.bytes(&[0x0f, 0xc8 + (r & 7)]);
    }

    /// 16-bit byte swap: `rol r16, 8`.
    pub fn bswap16(&mut self, r: Reg) {
        self.shift_ri(Shift::Rol, Sz::W, r, 8);
    }

    /// `crc32 dst, src` (CRC32C, as AArch64 CRC32C*).
    pub fn crc32(&mut self, sz: Sz, dst: Reg, src: Rm) {
        let opc = if sz == Sz::B { 0xf0 } else { 0xf1 };
        self.op_rm(Some(0xf2), sz, &[0x0f, 0x38, opc], dst, src);
        self.end_insn();
    }

    pub fn cmov(&mut self, cc: Cc, sz: Sz, dst: Reg, src: Rm) {
        self.op_rm(None, sz, &[0x0f, 0x40 + cc as u8], dst, src);
        self.end_insn();
    }

    pub fn setcc(&mut self, cc: Cc, dst: Reg) {
        self.op_rm(None, Sz::B, &[0x0f, 0x90 + cc as u8], 0, Rm::R(dst));
    }

    /// `bt r/m, imm8`
    pub fn bt_ri(&mut self, sz: Sz, rm: Rm, bit: u8) {
        self.op_rm(None, sz, &[0x0f, 0xba], 4, rm);
        self.byte(bit);
        self.end_insn();
    }

    pub fn xchg(&mut self, sz: Sz, m: Rm, r: Reg) {
        let opc = if sz == Sz::B { 0x86 } else { 0x87 };
        self.op_rm(None, sz, &[opc], r, m);
        self.end_insn();
    }

    /// `lock cmpxchg [m], r` (compares with rax).
    pub fn lock_cmpxchg(&mut self, sz: Sz, m: Mem, r: Reg) {
        self.byte(0xf0);
        let opc = if sz == Sz::B { 0xb0 } else { 0xb1 };
        self.op_rm(None, sz, &[0x0f, opc], r, Rm::M(m));
        self.end_insn();
    }

    /// `lock xadd [m], r`
    pub fn lock_xadd(&mut self, sz: Sz, m: Mem, r: Reg) {
        self.byte(0xf0);
        let opc = if sz == Sz::B { 0xc0 } else { 0xc1 };
        self.op_rm(None, sz, &[0x0f, opc], r, Rm::M(m));
        self.end_insn();
    }

    /// `lock op [m], r` for add/or/and/xor/sub.
    pub fn lock_alu_mr(&mut self, op: Alu, sz: Sz, m: Mem, r: Reg) {
        self.byte(0xf0);
        self.alu_mr(op, sz, Rm::M(m), r);
    }

    /// `lock cmpxchg16b [m]` (rdx:rax vs mem, rcx:rbx new).
    pub fn lock_cmpxchg16b(&mut self, m: Mem) {
        self.byte(0xf0);
        self.op_rm(None, Sz::Q, &[0x0f, 0xc7], 1, Rm::M(m));
        self.end_insn();
    }

    pub fn push(&mut self, r: Reg) {
        if r >= 8 {
            self.byte(0x41);
        }
        self.byte(0x50 + (r & 7));
    }

    pub fn pop(&mut self, r: Reg) {
        if r >= 8 {
            self.byte(0x41);
        }
        self.byte(0x58 + (r & 7));
    }

    pub fn lahf(&mut self) {
        self.byte(0x9f);
    }
    pub fn sahf(&mut self) {
        self.byte(0x9e);
    }
    pub fn cmc(&mut self) {
        self.byte(0xf5);
    }
    pub fn clc(&mut self) {
        self.byte(0xf8);
    }
    pub fn stc(&mut self) {
        self.byte(0xf9);
    }
    pub fn ret(&mut self) {
        self.byte(0xc3);
    }
    pub fn int3(&mut self) {
        self.byte(0xcc);
    }
    pub fn ud2(&mut self) {
        self.bytes(&[0x0f, 0x0b]);
    }
    pub fn syscall(&mut self) {
        self.bytes(&[0x0f, 0x05]);
    }
    pub fn mfence(&mut self) {
        self.bytes(&[0x0f, 0xae, 0xf0]);
    }
    pub fn lfence(&mut self) {
        self.bytes(&[0x0f, 0xae, 0xe8]);
    }
    pub fn pause(&mut self) {
        self.bytes(&[0xf3, 0x90]);
    }
    pub fn rdtsc(&mut self) {
        self.bytes(&[0x0f, 0x31]);
    }
    pub fn pushfq(&mut self) {
        self.byte(0x9c);
    }
    pub fn popfq(&mut self) {
        self.byte(0x9d);
    }

    /// Full barrier cheaper than mfence for WB memory.
    pub fn lock_or_rsp(&mut self) {
        self.bytes(&[0xf0, 0x48, 0x83, 0x0c, 0x24, 0x00]);
    }

    /// `rdrand r64`
    pub fn rdrand(&mut self, r: Reg) {
        self.op_rm(None, Sz::Q, &[0x0f, 0xc7], 6, Rm::R(r));
    }

    // ---- control flow ----

    /// `jmp rel32` to buffer offset `target` (or a placeholder if None).
    /// Returns the position of the rel32 field.
    pub fn jmp(&mut self, target: Option<usize>) -> usize {
        self.byte(0xe9);
        let at = self.pos;
        self.u32(0);
        if let Some(t) = target {
            self.patch_rel32(at, t);
        }
        at
    }

    /// `jcc rel32`; returns the position of the rel32 field.
    pub fn jcc(&mut self, cc: Cc, target: Option<usize>) -> usize {
        self.bytes(&[0x0f, 0x80 + cc as u8]);
        let at = self.pos;
        self.u32(0);
        if let Some(t) = target {
            self.patch_rel32(at, t);
        }
        at
    }

    /// Short `jcc rel8` forward; returns position of the rel8 byte.
    pub fn jcc8(&mut self, cc: Cc) -> usize {
        self.byte(0x70 + cc as u8);
        let at = self.pos;
        self.byte(0);
        at
    }

    /// Short `jmp rel8` forward; returns position of the rel8 byte.
    pub fn jmp8(&mut self) -> usize {
        self.byte(0xeb);
        let at = self.pos;
        self.byte(0);
        at
    }

    /// Bind a rel8 placeholder at `at` to the current position.
    pub fn bind8(&mut self, at: usize) {
        let rel = (self.pos as i64).wrapping_sub(at as i64 + 1);
        if !(-128..=127).contains(&rel) {
            self.err = true;
        }
        match self.buf.get_mut(at) {
            Some(x) => *x = rel as i8 as u8,
            None => self.err = true,
        }
    }

    /// Bind a rel32 placeholder at `at` to the current position.
    pub fn bind32(&mut self, at: usize) {
        let p = self.pos;
        self.patch_rel32(at, p);
    }

    /// `call rel32`; returns position of the rel32 field.
    pub fn call(&mut self, target: Option<usize>) -> usize {
        self.byte(0xe8);
        let at = self.pos;
        self.u32(0);
        if let Some(t) = target {
            self.patch_rel32(at, t);
        }
        at
    }

    pub fn jmp_rm(&mut self, rm: Rm) {
        self.op_rm(None, Sz::D, &[0xff], 4, rm);
        self.end_insn();
    }

    pub fn call_rm(&mut self, rm: Rm) {
        self.op_rm(None, Sz::D, &[0xff], 2, rm);
        self.end_insn();
    }

    // ---- VEX ----

    /// Emit a VEX-encoded instruction.
    /// `map`: 1 = 0F, 2 = 0F38, 3 = 0F3A; `pp`: 0 none, 1 = 66, 2 = F3, 3 = F2.
    #[allow(clippy::too_many_arguments)]
    pub fn vex(&mut self, map: u8, pp: u8, w: bool, l: bool, opc: u8, reg: u8, vvvv: u8, rm: Rm) {
        self.seg(&rm);
        let r = (reg >> 3) & 1;
        let (x, b) = match rm {
            Rm::R(rr) => (0, (rr >> 3) & 1),
            Rm::M(m) => {
                let x = if m.index != NO_REG { (m.index >> 3) & 1 } else { 0 };
                let b = if m.base != NO_REG && !m.rip { (m.base >> 3) & 1 } else { 0 };
                (x, b)
            }
        };
        if x == 0 && b == 0 && !w && map == 1 {
            self.byte(0xc5);
            self.byte(((r ^ 1) << 7) | ((!vvvv & 15) << 3) | ((l as u8) << 2) | (pp & 3));
        } else {
            self.byte(0xc4);
            self.byte(((r ^ 1) << 7) | ((x ^ 1) << 6) | ((b ^ 1) << 5) | (map & 31));
            self.byte(((w as u8) << 7) | ((!vvvv & 15) << 3) | ((l as u8) << 2) | (pp & 3));
        }
        self.byte(opc);
        self.modrm(reg, &rm);
        self.end_insn();
    }

    /// VEX instruction followed by an imm8.
    #[allow(clippy::too_many_arguments)]
    pub fn vex_ib(
        &mut self,
        map: u8,
        pp: u8,
        w: bool,
        l: bool,
        opc: u8,
        reg: u8,
        vvvv: u8,
        rm: Rm,
        ib: u8,
    ) {
        // Emit without RIP fixup finalization, then the immediate.
        let saved = self.rip_fixup.take();
        self.seg(&rm);
        let r = (reg >> 3) & 1;
        let (x, b) = match rm {
            Rm::R(rr) => (0, (rr >> 3) & 1),
            Rm::M(m) => {
                let x = if m.index != NO_REG { (m.index >> 3) & 1 } else { 0 };
                let b = if m.base != NO_REG && !m.rip { (m.base >> 3) & 1 } else { 0 };
                (x, b)
            }
        };
        self.byte(0xc4);
        self.byte(((r ^ 1) << 7) | ((x ^ 1) << 6) | ((b ^ 1) << 5) | (map & 31));
        self.byte(((w as u8) << 7) | ((!vvvv & 15) << 3) | ((l as u8) << 2) | (pp & 3));
        self.byte(opc);
        self.modrm(reg, &rm);
        self.byte(ib);
        self.end_insn();
        if self.rip_fixup.is_none() {
            self.rip_fixup = saved;
        }
    }

    /// Legacy SHA256RNDS2/MSG1/MSG2 (no mandatory prefix or VEX form).
    pub fn sha256(&mut self, op: u8, dst: u8, src: u8) {
        // SHA-NI has only legacy SSE encodings. The guest may have left
        // dirty YMM upper halves (e.g. DC ZVA); avoid the AVX/SSE assist.
        // Guest vectors are 128-bit, so this preserves every live value.
        self.bytes(&[0xc5, 0xf8, 0x77]); // vzeroupper
        self.op_rm(None, Sz::D, &[0x0f, 0x38, op], dst, Rm::R(src));
    }

    // BMI1/BMI2 (operate on 32/64-bit GPRs).

    /// `shlx/sarx/shrx dst, src, cnt` (pp: 1=shlx, 2=sarx, 3=shrx)
    pub fn shiftx(&mut self, pp: u8, sz: Sz, dst: Reg, src: Rm, cnt: Reg) {
        self.vex(2, pp, sz == Sz::Q, false, 0xf7, dst, cnt, src);
    }
    pub fn shlx(&mut self, sz: Sz, dst: Reg, src: Rm, cnt: Reg) {
        self.shiftx(1, sz, dst, src, cnt);
    }
    pub fn sarx(&mut self, sz: Sz, dst: Reg, src: Rm, cnt: Reg) {
        self.shiftx(2, sz, dst, src, cnt);
    }
    pub fn shrx(&mut self, sz: Sz, dst: Reg, src: Rm, cnt: Reg) {
        self.shiftx(3, sz, dst, src, cnt);
    }
    /// `rorx dst, src, imm`
    pub fn rorx(&mut self, sz: Sz, dst: Reg, src: Rm, imm: u8) {
        self.vex_ib(3, 3, sz == Sz::Q, false, 0xf0, dst, 0, src, imm);
    }
    /// `andn dst, a, b` : dst = ~a & b
    pub fn andn(&mut self, sz: Sz, dst: Reg, a: Reg, b: Rm) {
        self.vex(2, 0, sz == Sz::Q, false, 0xf2, dst, a, b);
    }
    /// `bzhi dst, src, idx`
    pub fn bzhi(&mut self, sz: Sz, dst: Reg, src: Rm, idx: Reg) {
        self.vex(2, 0, sz == Sz::Q, false, 0xf5, dst, idx, src);
    }
    /// `pext dst, src, mask` / `pdep dst, src, mask`
    pub fn pext(&mut self, sz: Sz, dst: Reg, src: Reg, mask: Rm) {
        self.vex(2, 2, sz == Sz::Q, false, 0xf5, dst, src, mask);
    }
    pub fn pdep(&mut self, sz: Sz, dst: Reg, src: Reg, mask: Rm) {
        self.vex(2, 3, sz == Sz::Q, false, 0xf5, dst, src, mask);
    }
    /// `mulx hi, lo, src` (rdx implicit)
    pub fn mulx(&mut self, sz: Sz, hi: Reg, lo: Reg, src: Rm) {
        self.vex(2, 3, sz == Sz::Q, false, 0xf6, hi, lo, src);
    }

    // SSE/AVX (VEX.128 unless noted). `x*` are xmm register numbers.

    /// `vmovdqu xmm, [m]`
    pub fn vmovdqu_load(&mut self, x: u8, m: Mem) {
        self.vex(1, 2, false, false, 0x6f, x, 0, Rm::M(m));
    }
    /// `vmovdqu [m], xmm`
    pub fn vmovdqu_store(&mut self, m: Mem, x: u8) {
        self.vex(1, 2, false, false, 0x7f, x, 0, Rm::M(m));
    }
    /// `vmovq xmm, [m]` (zero upper)
    pub fn vmovq_load(&mut self, x: u8, m: Mem) {
        self.vex(1, 2, false, false, 0x7e, x, 0, Rm::M(m));
    }
    /// `vmovq [m], xmm`
    pub fn vmovq_store(&mut self, m: Mem, x: u8) {
        self.vex(1, 1, false, false, 0xd6, x, 0, Rm::M(m));
    }
    /// `vmovd xmm, [m]`
    pub fn vmovd_load(&mut self, x: u8, m: Mem) {
        self.vex(1, 1, false, false, 0x6e, x, 0, Rm::M(m));
    }
    /// `vmovd [m], xmm`
    pub fn vmovd_store(&mut self, m: Mem, x: u8) {
        self.vex(1, 1, false, false, 0x7e, x, 0, Rm::M(m));
    }
    /// `vmovq xmm, r64` / `vmovd xmm, r32`
    pub fn vmov_from_gpr(&mut self, sz: Sz, x: u8, r: Reg) {
        self.vex(1, 1, sz == Sz::Q, false, 0x6e, x, 0, Rm::R(r));
    }
    /// `vmovq r64, xmm` / `vmovd r32, xmm`
    pub fn vmov_to_gpr(&mut self, sz: Sz, r: Reg, x: u8) {
        self.vex(1, 1, sz == Sz::Q, false, 0x7e, x, 0, Rm::R(r));
    }
    /// Generic three-operand VEX op in map 0F with prefix 66 (most integer SIMD).
    pub fn vop66(&mut self, opc: u8, dst: u8, a: u8, b: Rm) {
        self.vex(1, 1, false, false, opc, dst, a, b);
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use std::format;
    use std::process::Command;
    use std::string::String;
    use std::vec::Vec;

    fn disasm(code: &[u8]) -> String {
        let dir = std::env::temp_dir().join(format!("kemu-x86-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("code.bin");
        std::fs::write(&f, code).unwrap();
        let out = Command::new("objdump")
            .args(["-D", "-b", "binary", "-mi386:x86-64", "-M", "intel", "--no-show-raw-insn"])
            .arg(&f)
            .output()
            .unwrap();
        let s = String::from_utf8_lossy(&out.stdout);
        let mut v: Vec<String> = Vec::new();
        for line in s.lines() {
            if let Some((_, ins)) = line.split_once(":\t") {
                v.push(ins.split_whitespace().collect::<Vec<_>>().join(" "));
            }
        }
        v.join("\n")
    }

    fn check(f: impl FnOnce(&mut Asm), expect: &str) {
        let mut buf = [0u8; 64];
        let mut a = Asm::new(&mut buf);
        f(&mut a);
        assert!(a.ok());
        let got = disasm(a.code());
        assert_eq!(got.trim(), expect.trim(), "bytes: {:02x?}", a.code());
    }

    #[test]
    fn encodings() {
        check(|a| a.alu_rr(Alu::Add, Sz::Q, RDI, R8), "add rdi,r8");
        check(|a| a.alu_rr(Alu::Sub, Sz::D, R12, RCX), "sub r12d,ecx");
        check(|a| a.alu_ri(Alu::Cmp, Sz::Q, Rm::R(RBX), 0x1000), "cmp rbx,0x1000");
        check(|a| a.alu_ri(Alu::And, Sz::D, Rm::R(R9), -8), "and r9d,0xfffffff8");
        check(|a| a.load(Sz::Q, RAX, Mem::gs(256)), "mov rax,QWORD PTR gs:0x100");
        check(|a| a.store(Sz::Q, Mem::gs(8), R15), "mov QWORD PTR gs:0x8,r15");
        check(|a| a.load(Sz::Q, RSI, Mem::bisd(RBX, R13, 3, 16)), "mov rsi,QWORD PTR [rbx+r13*8+0x10]");
        check(|a| a.load(Sz::D, RDX, Mem::bd(R12, 0)), "mov edx,DWORD PTR [r12]");
        check(|a| a.load(Sz::Q, RDX, Mem::bd(R13, 0)), "mov rdx,QWORD PTR [r13+0x0]");
        check(|a| a.load(Sz::Q, RDX, Mem::bd(RBP, -8)), "mov rdx,QWORD PTR [rbp-0x8]");
        check(|a| a.store(Sz::B, Mem::b(RAX), RSI), "mov BYTE PTR [rax],sil");
        check(|a| a.store(Sz::W, Mem::b(R10), RDI), "mov WORD PTR [r10],di");
        check(|a| a.movzx(Sz::B, RAX, Rm::M(Mem::b(RDI))), "movzx eax,BYTE PTR [rdi]");
        check(|a| a.movsx(Sz::W, Sz::Q, R11, Rm::M(Mem::b(RCX))), "movsx r11,WORD PTR [rcx]");
        check(|a| a.movsx(Sz::D, Sz::Q, RAX, Rm::R(RDX)), "movsxd rax,edx");
        check(|a| a.mov_ri(R9, 0x1234_5678_9abc), "movabs r9,0x123456789abc");
        check(|a| a.mov_ri(RCX, 5), "mov ecx,0x5");
        check(|a| a.mov_ri(RCX, u64::MAX), "mov rcx,0xffffffffffffffff");
        check(|a| a.lea(Sz::Q, RAX, Mem::bisd(RCX, RDX, 2, 3)), "lea rax,[rcx+rdx*4+0x3]");
        check(|a| a.shlx(Sz::Q, RAX, Rm::R(RCX), RDX), "shlx rax,rcx,rdx");
        check(|a| a.sarx(Sz::D, R8, Rm::R(R9), R10), "sarx r8d,r9d,r10d");
        check(|a| a.rorx(Sz::Q, R11, Rm::R(RBX), 13), "rorx r11,rbx,0xd");
        check(|a| a.andn(Sz::Q, RAX, RCX, Rm::R(R12)), "andn rax,rcx,r12");
        check(|a| a.cmov(Cc::Ae, Sz::Q, RDI, Rm::R(RSI)), "cmovae rdi,rsi");
        check(|a| a.setcc(Cc::Ne, RSI), "setne sil");
        check(|a| a.bitcnt(0xbd, Sz::Q, RAX, Rm::R(R14)), "lzcnt rax,r14");
        check(|a| a.lock_cmpxchg(Sz::Q, Mem::b(R8), RCX), "lock cmpxchg QWORD PTR [r8],rcx");
        check(|a| a.lock_xadd(Sz::D, Mem::b(RDI), RAX), "lock xadd DWORD PTR [rdi],eax");
        check(|a| a.lock_cmpxchg16b(Mem::b(RSI)), "lock cmpxchg16b OWORD PTR [rsi]");
        check(|a| a.vmovdqu_load(3, Mem::gs(512)), "vmovdqu xmm3,XMMWORD PTR gs:0x200");
        check(|a| a.vmovdqu_store(Mem::bd(R9, 16), 12), "vmovdqu XMMWORD PTR [r9+0x10],xmm12");
        check(|a| a.vmov_from_gpr(Sz::Q, 1, R10), "vmovq xmm1,r10");
        check(|a| { a.lahf(); a.sahf(); a.cmc(); }, "lahf\nsahf\ncmc");
        check(|a| a.bswap(Sz::Q, R13), "bswap r13");
        check(|a| a.imul_rr(Sz::Q, RAX, Rm::R(R15)), "imul rax,r15");
        check(|a| a.grp3(Sz::Q, 6, Rm::R(RCX)), "div rcx");
        check(|a| a.jmp_rm(Rm::M(Mem::bd(RDX, 8))), "jmp QWORD PTR [rdx+0x8]");
        check(|a| a.alu_rm(Alu::Add, Sz::Q, RDX, Rm::M(Mem::rip(0))), "add rdx,QWORD PTR [rip+0xfffffffffffffff9] # 0x0");
        check(|a| a.test_ri(Sz::Q, Rm::R(RBX), 0xf), "test rbx,0xf");
        check(|a| a.shift_ri(Shift::Shr, Sz::Q, R10, 3), "shr r10,0x3");
        check(|a| a.pext(Sz::D, RAX, RDX, Rm::R(RCX)), "pext eax,edx,ecx");
        check(|a| a.mulx(Sz::Q, RAX, RDX, Rm::R(R8)), "mulx rax,rdx,r8");
        check(|a| a.lock_or_rsp(), "lock or QWORD PTR [rsp],0x0");
        check(|a| a.crc32(Sz::Q, RAX, Rm::R(R9)), "crc32 rax,r9");
        check(|a| a.crc32(Sz::B, RAX, Rm::R(RSI)), "crc32 eax,sil");
        check(|a| a.crc32(Sz::W, RAX, Rm::M(Mem::gs(8))), "crc32 eax,WORD PTR gs:0x8");
    }
}
