// SPDX-License-Identifier: GPL-2.0
/*
 * AArch64 integer division never traps: UDIV/SDIV by zero yield 0 and
 * SDIV INT_MIN/-1 yields INT_MIN. kemu lowers these to x86 div/idiv, which
 * *do* trap (#DE); the JIT pre-checks the divisor, and a host #DE raised by
 * a raced divisor is recovered in the interpreter (audit M-03). This test
 * exercises the architectural results and, with several threads sharing a
 * flipping divisor, stresses the division paths for spurious SIGFPE/crash.
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

static int failures;
#define CHECK(name, cond, ...) do { \
	if (cond) printf("PASS %s\n", name); \
	else { printf("FAIL %s: ", name); printf(__VA_ARGS__); printf("\n"); failures++; } \
} while (0)

static uint64_t udiv64(uint64_t a, uint64_t b)
{
	uint64_t r;
	__asm__ volatile("udiv %0, %1, %2" : "=r"(r) : "r"(a), "r"(b));
	return r;
}
static int64_t sdiv64(int64_t a, int64_t b)
{
	int64_t r;
	__asm__ volatile("sdiv %0, %1, %2" : "=r"(r) : "r"(a), "r"(b));
	return r;
}
static uint32_t udiv32(uint32_t a, uint32_t b)
{
	uint32_t r;
	__asm__ volatile("udiv %w0, %w1, %w2" : "=r"(r) : "r"(a), "r"(b));
	return r;
}
static int32_t sdiv32(int32_t a, int32_t b)
{
	int32_t r;
	__asm__ volatile("sdiv %w0, %w1, %w2" : "=r"(r) : "r"(a), "r"(b));
	return r;
}

static void test_semantics(void)
{
	CHECK("udiv-normal", udiv64(100, 7) == 14, "%lu", (unsigned long)udiv64(100, 7));
	CHECK("sdiv-normal", sdiv64(-100, 7) == -14, "%ld", (long)sdiv64(-100, 7));
	CHECK("udiv-by-zero", udiv64(1234, 0) == 0, "%lu", (unsigned long)udiv64(1234, 0));
	CHECK("sdiv-by-zero", sdiv64(-1234, 0) == 0, "%ld", (long)sdiv64(-1234, 0));
	CHECK("udiv32-by-zero", udiv32(99, 0) == 0, "%u", udiv32(99, 0));
	CHECK("sdiv64-intmin-m1", sdiv64(INT64_MIN, -1) == INT64_MIN, "%ld", (long)sdiv64(INT64_MIN, -1));
	CHECK("sdiv32-intmin-m1", sdiv32(INT32_MIN, -1) == INT32_MIN, "%d", sdiv32(INT32_MIN, -1));
}

#define THREADS 4
#define ITERS 200000
static volatile uint64_t shared_divisor = 1;

static void *flipper(void *arg)
{
	(void)arg;
	for (long i = 0; i < ITERS; i++)
		shared_divisor = (i & 1) ? 0 : 7;
	return NULL;
}

static void *divider(void *arg)
{
	long bad = 0;
	for (long i = 0; i < ITERS; i++) {
		/* Pin the divisor to guest x15, which kemu keeps in the (shared,
		 * cross-thread-writable) state page rather than a host register,
		 * so the division really reads gs:[off] -- the path a racing
		 * flipper can turn into a host #DE (audit M-03). */
		register uint64_t d __asm__("x15") = shared_divisor;	/* 0 or 7 */
		uint64_t q;
		__asm__ volatile("udiv %0, %1, %2" : "=r"(q) : "r"((uint64_t)1000), "r"(d));
		/* Architectural result is 142 (1000/7) or 0; never a trap. */
		if (d == 7 && q != 142)
			bad++;
		if (d == 0 && q != 0)
			bad++;
	}
	*(long *)arg = bad;
	return NULL;
}

static void test_stress(void)
{
	pthread_t th[THREADS];
	long bad[THREADS] = {0};

	pthread_t f;
	pthread_create(&f, NULL, flipper, NULL);
	for (int i = 0; i < THREADS; i++)
		pthread_create(&th[i], NULL, divider, &bad[i]);
	for (int i = 0; i < THREADS; i++)
		pthread_join(th[i], NULL);
	pthread_join(f, NULL);

	long total = 0;
	for (int i = 0; i < THREADS; i++)
		total += bad[i];
	/* Any result is architecturally valid for the value read; we only
	 * require that no SIGFPE killed us and the invariant above held. */
	CHECK("div-stress-no-trap", total == 0, "%ld unexpected results", total);
}

int main(void)
{
	test_semantics();
	test_stress();
	if (failures == 0)
		printf("DIVRACE ALL PASSED\n");
	else
		printf("DIVRACE %d FAILURES\n", failures);
	return failures ? 1 : 0;
}
