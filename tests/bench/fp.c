// SPDX-License-Identifier: GPL-2.0
/* Common FP kernels; build identically at -O3 for AArch64 and x86-64. */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define N 4096
#define M 48
static float x[N], y[N], z[N], a[M*M], b[M*M], c[M*M];
static double d[N];
static volatile double sink;

__attribute__((noinline)) static double saxpy(void)
{
	for (int i = 0; i < N; i++) z[i] = 0.75f * x[i] + y[i];
	return z[0] + z[N/2] + z[N-1];
}

__attribute__((noinline)) static double dot(void)
{
	double sum = 0;
	for (int i = 0; i < N; i++) sum += d[i] * d[N-1-i];
	return sum;
}

__attribute__((noinline)) static double matmul(void)
{
	memset(c, 0, sizeof(c));
	for (int i = 0; i < M; i++)
		for (int k = 0; k < M; k++)
			for (int j = 0; j < M; j++) c[i*M+j] += a[i*M+k] * b[k*M+j];
	return c[0] + c[M*M/2] + c[M*M-1];
}

__attribute__((noinline)) static double clamp(void)
{
	for (int i = 0; i < N; i++) z[i] = fminf(fmaxf(x[i], -0.25f), 0.25f);
	return z[0] + z[N/2] + z[N-1];
}

__attribute__((noinline)) static double range(void)
{
	unsigned count = 0;
	for (int i = 0; i < N; i++) count += d[i] > -0.25 && d[i] < 0.25;
	return count;
}

__attribute__((noinline)) static double mandelbrot(void)
{
	unsigned total = 0;
	for (int j = 0; j < 48; j++)
		for (int i = 0; i < 48; i++) {
			double cr = i / 24.0 - 1.5, ci = j / 24.0 - 1.0, re = 0, im = 0;
			unsigned n = 0;
			while (n < 64 && re*re + im*im < 4.0) {
				double next = re*re - im*im + cr;
				im = 2.0 * re * im + ci;
				re = next;
				n++;
			}
			total += n;
		}
	return total;
}

static double now(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec + t.tv_nsec * 1e-9;
}

int main(int argc, char **argv)
{
	static const struct { const char *name; double (*fn)(void); } tests[] = {
		{ "saxpy", saxpy }, { "dot", dot }, { "matmul", matmul },
		{ "clamp", clamp }, { "range", range }, { "mandelbrot", mandelbrot },
	};
	unsigned rounds = argc > 2 ? strtoul(argv[2], NULL, 0) : 50;
	if (!rounds) return 2;
	setvbuf(stdout, NULL, _IOLBF, 0);
	unsigned rng = 12345;
	for (int i = 0; i < N; i++) {
		rng = rng * 1664525u + 1013904223u;
		x[i] = ((int)(rng >> 16) - 32768) / 32768.0f;
		y[i] = (i % 31) / 32.0f;
		d[i] = x[i];
	}
	for (int i = 0; i < M*M; i++) { a[i] = x[i]; b[i] = y[i]; }
	for (unsigned k = 0; k < sizeof(tests)/sizeof(tests[0]); k++) {
		if (argc > 1 && strcmp(argv[1], "all") && strcmp(argv[1], tests[k].name)) continue;
		double sum = 0;
		sink = tests[k].fn();
		double start = now();
		for (unsigned r = 0; r < rounds; r++) {
			__asm__ volatile("" ::: "memory");
			sum += tests[k].fn();
		}
		double elapsed = now() - start;
		sink = sum;
		printf("FP %-10s rounds=%u ms=%.3f checksum=%.12g\n", tests[k].name, rounds, elapsed*1000, sum);
	}
	return 0;
}
