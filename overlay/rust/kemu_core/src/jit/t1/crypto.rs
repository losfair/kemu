// SPDX-License-Identifier: GPL-2.0
//! Crypto lowering using AVX2, with optional AES-NI, PCLMULQDQ and SHA-NI.
//! Keep intermediate state in scratch XMM registers and
//! commit Vd once, so an interrupted instruction can restart. Integer
//! vector operations leave NZCV, FPCR and FPSR untouched.

use super::*;

/// Optional host crypto features. AVX state support is already required
/// by the JIT; the 128-bit VEX forms need AES/PCLMUL, not VAES/VPCLMUL.
#[derive(Clone, Copy, Debug, Default)]
pub struct HostCrypto {
    pub aes: bool,
    pub pclmul: bool,
    pub sha: bool,
}

// XMM0..7 cache guest vectors; these host registers are scratch.
const X: u8 = 8;
const Y: u8 = 9;
const W: u8 = 10;
const T: u8 = 11;
const U: u8 = 12;
const V: u8 = 13;
const S: u8 = 14;
const R: u8 = 15;

const ADD: u8 = 0xfe;
const XOR: u8 = 0xef;
const AND: u8 = 0xdb;
const OR: u8 = 0xeb;

fn bin(a: &mut Asm<'_>, op: u8, d: u8, n: u8, m: u8) {
    a.vex(1, 1, false, false, op, d, n, Rm::R(m));
}

fn shr(a: &mut Asm<'_>, d: u8, n: u8, bits: u8) {
    a.vex_ib(1, 1, false, false, 0x72, 2, d, Rm::R(n), bits);
}

fn ror(a: &mut Asm<'_>, d: u8, n: u8, bits: u8, tmp: u8) {
    a.vex_ib(1, 1, false, false, 0x72, 6, tmp, Rm::R(n), 32 - bits);
    shr(a, d, n, bits);
    bin(a, OR, d, d, tmp);
}

/// ROTR(n, a) ^ ROTR(n, b) ^ (last_shift ? SHR(n, c) : ROTR(n, c)).
/// The input, output, and two temporaries must be distinct.
#[allow(clippy::too_many_arguments)]
fn sigma(a: &mut Asm<'_>, d: u8, n: u8, shifts: [u8; 3], last_shift: bool, t0: u8, t1: u8) {
    ror(a, d, n, shifts[0], t0);
    ror(a, t0, n, shifts[1], t1);
    bin(a, XOR, d, d, t0);
    if last_shift {
        shr(a, t0, n, shifts[2]);
    } else {
        ror(a, t0, n, shifts[2], t1);
    }
    bin(a, XOR, d, d, t0);
}

fn shuffle(a: &mut Asm<'_>, d: u8, n: u8, lanes: u8) {
    a.vex_ib(1, 1, false, false, 0x70, d, 0, Rm::R(n), lanes);
}

fn align(a: &mut Asm<'_>, d: u8, hi: u8, lo: u8, bytes: u8) {
    a.vex_ib(3, 1, false, false, 0x0f, d, hi, Rm::R(lo), bytes);
}

fn shift_bytes(a: &mut Asm<'_>, d: u8, n: u8, left: bool, bytes: u8) {
    a.vex_ib(1, 1, false, false, 0x73, if left { 7 } else { 3 }, d, Rm::R(n), bytes);
}

fn blend(a: &mut Asm<'_>, d: u8, n: u8, m: u8, lanes: u8) {
    a.vex_ib(3, 1, false, false, 0x02, d, n, Rm::R(m), lanes);
}

impl<'s, 'b> Gen<'s, 'b> {
    pub(super) fn aes(&mut self, decrypt: bool, rd: u32, rn: u32) -> bool {
        if !self.cfg.crypto.aes {
            return false;
        }
        self.ld_vec(X, rd);
        self.ld_vec(Y, rn);
        let a = &mut self.a;
        // Arm adds the round key before SubBytes/ShiftRows; x86 adds it
        // afterwards. XOR first, then use a last round with a zero key.
        bin(a, XOR, X, X, Y);
        bin(a, XOR, Y, Y, Y);
        a.vex(2, 1, false, false, if decrypt { 0xdf } else { 0xdd }, X, X, Rm::R(Y));
        self.store_vec(rd, X);
        true
    }

    pub(super) fn aes_mix(&mut self, inverse: bool, rd: u32, rn: u32) -> bool {
        if !self.cfg.crypto.aes {
            return false;
        }
        self.ld_vec(X, rn);
        let a = &mut self.a;
        if inverse {
            a.vex(2, 1, false, false, 0xdb, X, 0, Rm::R(X)); // vaesimc
        } else {
            // AESDECLAST undoes SubBytes/ShiftRows, so AESENC with zero
            // keys cancels those steps and leaves just MixColumns.
            bin(a, XOR, Y, Y, Y);
            a.vex(2, 1, false, false, 0xdf, X, X, Rm::R(Y));
            a.vex(2, 1, false, false, 0xdc, X, X, Rm::R(Y));
        }
        self.store_vec(rd, X);
        true
    }

    pub(super) fn pmull(&mut self, size: u8, high: bool, rd: u32, rn: u32, rm: u32) -> bool {
        if size != 0 && (size != 3 || !self.cfg.crypto.pclmul) {
            return false;
        }
        if size == 3 {
            self.ld_vec(X, rn);
            self.ld_vec(Y, rm);
        } else {
            self.widen(X, rn, 0, false, high);
            self.widen(Y, rm, 0, false, high);
        }
        let a = &mut self.a;
        if size == 3 {
            a.vex_ib(3, 1, false, false, 0x44, W, X, Rm::R(Y), if high { 0x11 } else { 0 });
        } else {
            // Eight independent 8x8 -> 16-bit polynomial products.
            // Widen first so shifts cannot spill into adjacent lanes.
            bin(a, XOR, W, W, W);
            for i in 0..8 {
                // Broadcast bit i of each multiplier to a 16-bit mask.
                a.vex_ib(1, 1, false, false, 0x71, 6, T, Rm::R(Y), 15 - i);
                a.vex_ib(1, 1, false, false, 0x71, 4, T, Rm::R(T), 15);
                bin(a, AND, T, T, X);
                bin(a, XOR, W, W, T);
                if i != 7 {
                    a.vex_ib(1, 1, false, false, 0x71, 6, X, Rm::R(X), 1);
                }
            }
        }
        self.store_vec(rd, W);
        true
    }

    pub(super) fn sha1(&mut self, op: u8, rd: u32, rn: u32, rm: u32) -> bool {
        if op > 5 {
            return false;
        }
        self.ld_vec(X, rd);
        self.ld_vec(Y, rn);
        if op <= 3 { self.ld_vec(W, rm); }
        let a = &mut self.a;
        match op {
            0..=2 => {
                // X = [a,b,c,d], Y.low = e, W = four message words + K.
                for _ in 0..4 {
                    shuffle(a, T, X, 0x55); // b
                    shuffle(a, U, X, 0xaa); // c
                    shuffle(a, V, X, 0xff); // d
                    match op {
                        0 => {
                            bin(a, XOR, U, U, V);
                            bin(a, AND, U, U, T);
                            bin(a, XOR, U, U, V);
                        }
                        1 => {
                            bin(a, XOR, U, U, T);
                            bin(a, XOR, U, U, V);
                        }
                        _ => {
                            bin(a, OR, S, T, U);
                            bin(a, AND, S, S, V);
                            bin(a, AND, U, U, T);
                            bin(a, OR, U, U, S);
                        }
                    }
                    ror(a, S, X, 27, R); // ROL(a,5)
                    bin(a, ADD, S, S, Y);
                    bin(a, ADD, S, S, U);
                    bin(a, ADD, S, S, W); // new a
                    ror(a, T, X, 2, R); // ROL(b,30) in lane 1
                    blend(a, X, X, T, 2);
                    shift_bytes(a, X, X, true, 4);
                    blend(a, X, X, S, 1); // [new a,a,ROL(b,30),c]
                    shuffle(a, Y, V, 0); // new e = old d
                    shift_bytes(a, W, W, false, 4);
                }
            }
            3 => {
                align(a, T, Y, X, 8); // [d2,d3,n0,n1]
                bin(a, XOR, X, X, T);
                bin(a, XOR, X, X, W);
            }
            4 => {
                ror(a, X, Y, 2, T);
                // SHA1H writes a scalar S register, clearing all high bits.
                shift_bytes(a, X, X, true, 12);
                shift_bytes(a, X, X, false, 12);
            }
            _ => {
                shift_bytes(a, T, Y, false, 4);
                bin(a, XOR, X, X, T);
                ror(a, Y, X, 31, T); // ROL(t,1)
                ror(a, U, X, 30, T); // ROL(t,2)
                shift_bytes(a, U, U, true, 12);
                bin(a, XOR, X, Y, U); // high lane also XORs ROL(t0,2)
            }
        }
        self.store_vec(rd, X);
        true
    }

    pub(super) fn sha256(&mut self, op: u8, rd: u32, rn: u32, rm: u32) -> bool {
        if !matches!(op, 4 | 5 | 6 | 0x10) {
            return false;
        }
        if self.cfg.crypto.sha {
            return self.sha256_host(op, rd, rn, rm);
        }
        // Read every operand before committing, including when they alias.
        self.ld_vec(X, if op == 5 { rn } else { rd });
        self.ld_vec(Y, if op == 5 { rd } else { rn });
        if op != 0x10 { self.ld_vec(W, rm); }
        let a = &mut self.a;
        let result = match op {
            4 | 5 => {
                // Four rounds: X = [a,b,c,d], Y = [e,f,g,h], W = Wt+Kt.
                // Only the low lane of each round's temporaries is used.
                for _ in 0..4 {
                    sigma(a, T, Y, [6, 11, 25], false, U, V);
                    shuffle(a, U, Y, 0x55); // f
                    shuffle(a, V, Y, 0xaa); // g
                    bin(a, XOR, U, U, V);
                    bin(a, AND, U, U, Y);
                    bin(a, XOR, U, U, V); // Ch(e,f,g)
                    bin(a, ADD, T, T, U);
                    shuffle(a, U, Y, 0xff); // h
                    bin(a, ADD, T, T, U);
                    bin(a, ADD, T, T, W); // T1 = h + Sigma1(e) + Ch + Wt+Kt
                    shuffle(a, U, X, 0xff); // d
                    bin(a, ADD, S, T, U); // new e

                    sigma(a, U, X, [2, 13, 22], false, V, R);
                    bin(a, ADD, T, T, U);
                    shuffle(a, U, X, 0x55); // b
                    shuffle(a, V, X, 0xaa); // c
                    bin(a, OR, R, X, U);
                    bin(a, AND, R, R, V);
                    bin(a, AND, U, X, U);
                    bin(a, OR, U, U, R); // Maj(a,b,c)
                    bin(a, ADD, T, T, U); // new a

                    shift_bytes(a, X, X, true, 4);
                    blend(a, X, X, T, 1);
                    shift_bytes(a, Y, Y, true, 4);
                    blend(a, Y, Y, S, 1);
                    shift_bytes(a, W, W, false, 4);
                }
                if op == 4 { X } else { Y }
            }
            0x10 => {
                // SHA256SU0: Vd + sigma0([d1,d2,d3,n0]).
                align(a, W, Y, X, 4);
                sigma(a, T, W, [7, 18, 3], true, U, V);
                bin(a, ADD, X, X, T);
                X
            }
            _ => {
                // SHA256SU1: the upper two lanes depend on the newly
                // computed lower lanes, not on the old destination.
                align(a, T, W, Y, 4); // [n1,n2,n3,m0]
                bin(a, ADD, X, X, T);
                shift_bytes(a, Y, W, false, 8); // [m2,m3,0,0]
                sigma(a, T, Y, [17, 19, 10], true, U, V);
                bin(a, ADD, Y, X, T); // r0,r1 in low lanes
                shift_bytes(a, W, Y, true, 8); // [0,0,r0,r1]
                sigma(a, T, W, [17, 19, 10], true, U, V);
                bin(a, ADD, X, X, T); // r2,r3 in high lanes
                blend(a, X, X, Y, 3);
                X
            }
        };
        self.store_vec(rd, result);
        true
    }

    fn sha256_host(&mut self, op: u8, rd: u32, rn: u32, rm: u32) -> bool {
        self.ld_vec(X, if op == 5 { rn } else { rd });
        self.ld_vec(Y, if op == 5 { rd } else { rn });
        if op != 0x10 { self.ld_vec(W, rm); }
        let a = &mut self.a;
        match op {
            4 | 5 => {
                // ARM: [a,b,c,d], [e,f,g,h] in low-to-high lane order.
                // SHA256RNDS2: [f,e,b,a], [h,g,d,c], with W+K in XMM0.
                // The block allocator reserves XMM0 for these instructions.
                shuffle(a, T, X, 0xb1);
                shuffle(a, U, Y, 0xb1);
                bin(a, 0x6c, X, U, T);
                bin(a, 0x6d, Y, U, T);
                a.vex(1, 2, false, false, 0x6f, 0, 0, Rm::R(W));
                a.sha256(0xcb, Y, X);
                shuffle(a, 0, W, 0x0e);
                a.sha256(0xcb, X, Y);
                shuffle(a, T, X, 0xb1);
                shuffle(a, U, Y, 0xb1);
                bin(a, if op == 4 { 0x6d } else { 0x6c }, X, T, U);
            }
            0x10 => a.sha256(0xcc, X, Y), // SHA256MSG1 == SHA256SU0
            _ => {
                align(a, T, W, Y, 4);
                bin(a, ADD, X, X, T);
                a.sha256(0xcd, X, W); // SHA256MSG2 completes SHA256SU1
            }
        }
        self.store_vec(rd, X);
        true
    }
}
