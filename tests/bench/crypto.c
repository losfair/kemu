/* SPDX-License-Identifier: GPL-2.0 */
/* Build: aarch64-linux-gnu-gcc -O2 -static -o build/crypto-bench \
 *            tests/bench/crypto.c tests/bench/crypto.S
 * Run: build/crypto-bench [iterations [trials]]
 * Compare checksums with qemu-aarch64 and timings with the same binary on
 * baseline/patched kemu. ns/insn includes loop and operand-handling overhead.
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

typedef void (*bench_fn)(uint64_t, const uint64_t *, uint64_t *);
#define DECLARE(name) extern void crypto_##name(uint64_t, const uint64_t *, uint64_t *)
DECLARE(aes_encrypt);
DECLARE(aes_decrypt);
DECLARE(pmull64);
DECLARE(pmull8);
DECLARE(sha1);

static double now(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
        perror("clock_gettime");
        exit(1);
    }
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

int main(int argc, char **argv)
{
    uint64_t iterations = argc > 1 ? strtoull(argv[1], NULL, 0) : 200000;
    unsigned trials = argc > 2 ? strtoul(argv[2], NULL, 0) : 3;
    if (!iterations || iterations > 1000000000 || !trials || trials > 100) {
        fprintf(stderr, "expected 1..1e9 iterations and 1..100 trials\n");
        return 1;
    }
    const uint64_t seed[6] = {
        0x0123456789abcdef, 0xfedcba9876543210,
        0x3141592653589793, 0x2384626433832795,
        0xa5c39e718b4d260f, 0x78695a4b3c2d1e0f,
    };
    const struct { const char *name; bench_fn run; unsigned insns; } cases[] = {
        {"aes-encrypt", crypto_aes_encrypt, 8},
        {"aes-decrypt", crypto_aes_decrypt, 8},
        {"pmull64", crypto_pmull64, 8},
        {"pmull8", crypto_pmull8, 8},
        {"sha1", crypto_sha1, 12},
    };
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint64_t result[6];
        cases[i].run(256, seed, result); /* Warm the translator/code cache. */
        for (unsigned trial = 0; trial < trials; trial++) {
            double start = now();
            cases[i].run(iterations, seed, result);
            double seconds = now() - start;
            uint64_t sum = 0;
            for (unsigned j = 0; j < 6; j++)
                sum = (sum << 7 | sum >> 57) ^ result[j];
            printf("CRYPTOBENCH %s trial=%u iterations=%" PRIu64
                   " seconds=%.6f ns/insn=%.3f checksum=%016" PRIx64 "\n",
                   cases[i].name, trial + 1, iterations, seconds,
                   seconds * 1e9 / (iterations * cases[i].insns), sum);
            fflush(stdout);
        }
    }
    return 0;
}
