/* SPDX-License-Identifier: GPL-2.0 */
/* gcc -O2 -static tests/bench/libm.c -lm -o libm-bench
 * Run identical AArch64 binaries on baseline/patched kernels. Warm each
 * function before timing; the last result is printed for comparison with
 * qemu-aarch64. Do not use -ffast-math for this accuracy-preserving path.
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static volatile double sink;
static double now(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) { perror("clock_gettime"); exit(1); }
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}
static double power(double x) { return pow(x, 2.5); }

#define BENCH(fn) do { \
    double x = 1.000001; \
    for (long i = 0; i < 1000; i++) { sink = fn(x); x += 1e-9; } \
    x = 1.000001; \
    double start = now(); \
    for (long i = 0; i < n; i++) { sink = fn(x); x += 1e-9; } \
    printf("LIBMBENCH %-6s ns/op=%.2f result=%.17g\n", #fn, (now()-start)*1e9/n, sink); \
} while (0)

int main(int argc, char **argv)
{
    long n = argc > 1 ? strtol(argv[1], NULL, 0) : 1000000;
    if (n < 1 || n > 100000000) return 2;
    BENCH(sqrt); BENCH(log); BENCH(rint); BENCH(round); BENCH(exp);
    BENCH(sin); BENCH(cos); BENCH(atan); BENCH(power);
    return 0;
}
