// SPDX-License-Identifier: GPL-2.0
// AES primitives for AESE/AESD/AESMC/AESIMC. Included by simd.rs.

static SBOX: [u8; 256] = {
    // Rijndael S-box, generated at build time would need GF math; hardcode.
    [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
        0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
        0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
        0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
        0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
        0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
        0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
        0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
        0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
        0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
        0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
        0x16,
    ]
};

fn inv_sbox() -> [u8; 256] {
    let mut inv = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        inv[SBOX[i] as usize] = i as u8;
        i += 1;
    }
    inv
}

#[inline]
fn xtime(x: u8) -> u8 {
    let h = (x >> 7) & 1;
    (x << 1) ^ (0x1b * h)
}

#[inline]
fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

fn bytes_of(v: [u64; 2]) -> [u8; 16] {
    let mut b = [0u8; 16];
    for i in 0..8 {
        b[i] = (v[0] >> (i * 8)) as u8;
        b[i + 8] = (v[1] >> (i * 8)) as u8;
    }
    b
}
fn vec_of(b: [u8; 16]) -> [u64; 2] {
    let mut lo = 0u64;
    let mut hi = 0u64;
    for i in 0..8 {
        lo |= (b[i] as u64) << (i * 8);
        hi |= (b[i + 8] as u64) << (i * 8);
    }
    [lo, hi]
}

// ShiftRows permutation indices (AES state is column-major).
const SHIFT_ROWS: [usize; 16] = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];
const INV_SHIFT_ROWS: [usize; 16] = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3];

/// AESE (decrypt=false): AddRoundKey(Vd^Vn) then ShiftRows then SubBytes.
/// AESD (decrypt=true): inverse ShiftRows then inverse SubBytes.
fn aes(cpu: &mut CpuState, rd: u32, rn: u32, decrypt: bool) {
    let state = bytes_of(cpu.vreg(rd));
    let key = bytes_of(cpu.vreg(rn));
    let mut t = [0u8; 16];
    for i in 0..16 {
        t[i] = state[i] ^ key[i];
    }
    let mut out = [0u8; 16];
    if !decrypt {
        for i in 0..16 {
            out[i] = SBOX[t[SHIFT_ROWS[i]] as usize];
        }
    } else {
        let inv = inv_sbox();
        for i in 0..16 {
            out[i] = inv[t[INV_SHIFT_ROWS[i]] as usize];
        }
    }
    cpu.set_vreg(rd, vec_of(out));
}

/// AESMC / AESIMC: (inverse) MixColumns.
fn aesmc(cpu: &mut CpuState, rd: u32, rn: u32, inverse: bool) {
    let s = bytes_of(cpu.vreg(rn));
    let mut out = [0u8; 16];
    for c in 0..4 {
        let col = [s[c * 4], s[c * 4 + 1], s[c * 4 + 2], s[c * 4 + 3]];
        let r = if !inverse {
            [
                xtime(col[0]) ^ (xtime(col[1]) ^ col[1]) ^ col[2] ^ col[3],
                col[0] ^ xtime(col[1]) ^ (xtime(col[2]) ^ col[2]) ^ col[3],
                col[0] ^ col[1] ^ xtime(col[2]) ^ (xtime(col[3]) ^ col[3]),
                (xtime(col[0]) ^ col[0]) ^ col[1] ^ col[2] ^ xtime(col[3]),
            ]
        } else {
            [
                gmul(col[0], 14) ^ gmul(col[1], 11) ^ gmul(col[2], 13) ^ gmul(col[3], 9),
                gmul(col[0], 9) ^ gmul(col[1], 14) ^ gmul(col[2], 11) ^ gmul(col[3], 13),
                gmul(col[0], 13) ^ gmul(col[1], 9) ^ gmul(col[2], 14) ^ gmul(col[3], 11),
                gmul(col[0], 11) ^ gmul(col[1], 13) ^ gmul(col[2], 9) ^ gmul(col[3], 14),
            ]
        };
        out[c * 4] = r[0];
        out[c * 4 + 1] = r[1];
        out[c * 4 + 2] = r[2];
        out[c * 4 + 3] = r[3];
    }
    cpu.set_vreg(rd, vec_of(out));
}

// ---- SHA1 / SHA256 (Arm ARM shared pseudocode) ----

fn words(v: [u64; 2]) -> [u32; 4] {
    [v[0] as u32, (v[0] >> 32) as u32, v[1] as u32, (v[1] >> 32) as u32]
}

fn unwords(w: [u32; 4]) -> [u64; 2] {
    [(w[0] as u64) | ((w[1] as u64) << 32), (w[2] as u64) | ((w[3] as u64) << 32)]
}

fn sha_choose(x: u32, y: u32, z: u32) -> u32 {
    ((y ^ z) & x) ^ z
}

fn sha_majority(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | ((x | y) & z)
}

fn sha1(cpu: &mut CpuState, op: u8, rd: u32, rn: u32, rm: u32) -> bool {
    let d = words(cpu.vreg(rd));
    let n = words(cpu.vreg(rn));
    let m = words(cpu.vreg(rm));
    let r = match op {
        0..=2 => {
            // SHA1C / SHA1P / SHA1M: X = Qd, Y = Sn, W = Vm
            let mut x = d;
            let mut y = n[0];
            for e in 0..4 {
                let t = match op {
                    0 => sha_choose(x[1], x[2], x[3]),
                    1 => x[1] ^ x[2] ^ x[3],
                    _ => sha_majority(x[1], x[2], x[3]),
                };
                y = y.wrapping_add(x[0].rotate_left(5)).wrapping_add(t).wrapping_add(m[e]);
                x[1] = x[1].rotate_left(30);
                // <Y, X> = ROL(Y:X, 32)
                let nx = [y, x[0], x[1], x[2]];
                y = x[3];
                x = nx;
            }
            x
        }
        3 => {
            // SHA1SU0: (n[63:0] : d[127:64]) ^ d ^ m
            let t = [d[2], d[3], n[0], n[1]];
            [t[0] ^ d[0] ^ m[0], t[1] ^ d[1] ^ m[1], t[2] ^ d[2] ^ m[2], t[3] ^ d[3] ^ m[3]]
        }
        4 => {
            // SHA1H: ROL(Sn, 30)
            [n[0].rotate_left(30), 0, 0, 0]
        }
        5 => {
            // SHA1SU1: T = d ^ (n >> 32)
            let t = [d[0] ^ n[1], d[1] ^ n[2], d[2] ^ n[3], d[3]];
            [
                t[0].rotate_left(1),
                t[1].rotate_left(1),
                t[2].rotate_left(1),
                t[3].rotate_left(1) ^ t[0].rotate_left(2),
            ]
        }
        _ => return false,
    };
    cpu.set_vreg(rd, unwords(r));
    true
}

fn sha256_hash(mut x: [u32; 4], mut y: [u32; 4], w: [u32; 4], part1: bool) -> [u32; 4] {
    for e in 0..4 {
        let chs = sha_choose(y[0], y[1], y[2]);
        let maj = sha_majority(x[0], x[1], x[2]);
        let s1 = y[0].rotate_right(6) ^ y[0].rotate_right(11) ^ y[0].rotate_right(25);
        let s0 = x[0].rotate_right(2) ^ x[0].rotate_right(13) ^ x[0].rotate_right(22);
        let t = y[3].wrapping_add(s1).wrapping_add(chs).wrapping_add(w[e]);
        x[3] = t.wrapping_add(x[3]);
        y[3] = t.wrapping_add(s0).wrapping_add(maj);
        // <Y, X> = ROL(Y:X, 32)
        let nx = [y[3], x[0], x[1], x[2]];
        let ny = [x[3], y[0], y[1], y[2]];
        x = nx;
        y = ny;
    }
    if part1 {
        x
    } else {
        y
    }
}

fn sha256(cpu: &mut CpuState, op: u8, rd: u32, rn: u32, rm: u32) -> bool {
    let d = words(cpu.vreg(rd));
    let n = words(cpu.vreg(rn));
    let m = words(cpu.vreg(rm));
    let r = match op {
        4 => sha256_hash(d, n, m, true),
        5 => sha256_hash(n, d, m, false),
        6 => {
            // SHA256SU1
            let t0 = [n[1], n[2], n[3], m[0]];
            let s = |v: u32| v.rotate_right(17) ^ v.rotate_right(19) ^ (v >> 10);
            let mut r = [0u32; 4];
            r[0] = s(m[2]).wrapping_add(d[0]).wrapping_add(t0[0]);
            r[1] = s(m[3]).wrapping_add(d[1]).wrapping_add(t0[1]);
            r[2] = s(r[0]).wrapping_add(d[2]).wrapping_add(t0[2]);
            r[3] = s(r[1]).wrapping_add(d[3]).wrapping_add(t0[3]);
            r
        }
        0x10 => {
            // SHA256SU0
            let t = [d[1], d[2], d[3], n[0]];
            let s = |v: u32| v.rotate_right(7) ^ v.rotate_right(18) ^ (v >> 3);
            [
                s(t[0]).wrapping_add(d[0]),
                s(t[1]).wrapping_add(d[1]),
                s(t[2]).wrapping_add(d[2]),
                s(t[3]).wrapping_add(d[3]),
            ]
        }
        _ => return false,
    };
    cpu.set_vreg(rd, unwords(r));
    true
}
