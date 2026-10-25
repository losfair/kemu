/* SPDX-License-Identifier: GPL-2.0 */
/* Instruction microbenchmarks, not complete cipher/hash implementations.
 * x0 = positive iteration count, x1 = 48-byte seed, x2 = 48-byte result.
 * Feedback keeps every result live. Run identical binaries on both kernels.
 */
.arch armv8-a+crypto
.text

.macro begin name
.global crypto_\name
.type crypto_\name, %function
.align 4
crypto_\name:
    ldp q0, q1, [x1]
    ldr q2, [x1, #32]
1:
.endm

.macro end name
    subs x0, x0, #1
    b.ne 1b
    stp q0, q1, [x2]
    str q2, [x2, #32]
    ret
.size crypto_\name, .-crypto_\name
.endm

begin aes_encrypt
.rept 4
    aese v0.16b, v1.16b
    aesmc v0.16b, v0.16b
.endr
end aes_encrypt

begin aes_decrypt
.rept 4
    aesd v0.16b, v1.16b
    aesimc v0.16b, v0.16b
.endr
end aes_decrypt

begin pmull64
.rept 4
    pmull v3.1q, v0.1d, v1.1d
    pmull2 v4.1q, v0.2d, v1.2d
    eor v0.16b, v3.16b, v4.16b
    eor v0.16b, v0.16b, v2.16b
.endr
end pmull64

begin pmull8
.rept 4
    pmull v3.8h, v0.8b, v1.8b
    pmull2 v4.8h, v0.16b, v1.16b
    eor v0.16b, v3.16b, v4.16b
    eor v0.16b, v0.16b, v2.16b
.endr
end pmull8

begin sha1
.rept 2
    sha1c q0, s1, v2.4s
    sha1p q0, s1, v2.4s
    sha1m q0, s1, v2.4s
    sha1h s1, s0
    sha1su0 v2.4s, v0.4s, v1.4s
    sha1su1 v2.4s, v1.4s
.endr
end sha1

begin sha256
.rept 2
    sha256h q0, q1, v2.4s
    sha256h2 q1, q0, v2.4s
    sha256su0 v2.4s, v0.4s
    sha256su1 v2.4s, v0.4s, v1.4s
.endr
end sha256

.section .note.GNU-stack,"",%progbits
