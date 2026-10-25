// SPDX-License-Identifier: GPL-2.0
/*
 * Top-byte-ignore (TBI): arm64 Linux ignores bits 63:56 of user data
 * addresses. Covers the access forms kemu translates, a hot loop (which
 * kemu retranslates with address masking), writeback keeping the tag, and
 * a fault through a tagged pointer (si_addr is reported untagged).
 */
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static int failures;
#define CHECK(name, cond, ...) do { \
	if (cond) printf("PASS %s\n", name); \
	else { printf("FAIL %s: ", name); printf(__VA_ARGS__); printf("\n"); failures++; } \
} while (0)

#define TAG(p, t) ((void *)((uintptr_t)(p) | ((uintptr_t)(t) << 56)))

static sigjmp_buf jb;
static void *fault_addr;
static void on_segv(int sig, siginfo_t *si, void *uc)
{
	(void)sig; (void)uc;
	fault_addr = si->si_addr;
	siglongjmp(jb, 1);
}

static double now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

int main(void)
{
	static long arr[64];
	static long pair[2];
	static _Atomic long counter;
	static unsigned char vec[32];
	long *p, r;

	/* plain load/store, immediate offset */
	p = TAG(&arr[3], 0x5a);
	*p = 1234;
	CHECK("ldst-imm", arr[3] == 1234 && *p == 1234, "arr[3]=%ld", arr[3]);

	/* register offset: base + index * 8 */
	long *base = TAG(arr, 0xa5);
	volatile long idx = 7;
	base[idx] = 77;
	CHECK("ldst-reg", arr[7] == 77 && base[idx] == 77, "arr[7]=%ld", arr[7]);

	/* pair */
	long a, b, *pp = TAG(pair, 0x11);
	__asm__ volatile("stp %2, %3, [%4]\n\tldp %0, %1, [%4]"
			 : "=&r"(a), "=&r"(b) : "r"(5L), "r"(6L), "r"(pp) : "memory");
	CHECK("ldst-pair", a == 5 && b == 6 && pair[1] == 6, "a=%ld b=%ld", a, b);

	/* post-index writeback keeps the tag */
	long *q = TAG(&arr[10], 0x77), *q0 = q;
	arr[10] = 10;
	__asm__ volatile("ldr %0, [%1], #8" : "=r"(r), "+r"(q) :: "memory");
	CHECK("writeback-tag", r == 10 && (uintptr_t)q == (uintptr_t)q0 + 8,
	      "r=%ld q=%p want %p", r, (void *)q, (void *)((uintptr_t)q0 + 8));

	/* SIMD */
	unsigned char *vp = TAG(vec, 0x42);
	__asm__ volatile("movi v0.16b, #0x5c\n\tst1 {v0.16b}, [%0]" :: "r"(vp) : "v0", "memory");
	CHECK("simd-st1", vec[0] == 0x5c && vec[15] == 0x5c, "vec[0]=%x", vec[0]);

	/* atomics (LSE or LL/SC, whichever the compiler picked) */
	_Atomic long *cp = TAG(&counter, 0x99);
	for (int i = 0; i < 1000; i++)
		atomic_fetch_add(cp, 2);
	long expect = 0;
	atomic_compare_exchange_strong(cp, &expect, 1); /* fails: 2000 */
	CHECK("atomics", atomic_load(&counter) == 2000 && expect == 2000, "counter=%ld", (long)counter);

	/* hot loop: kemu retranslates it with address masking */
	long *hot = TAG(arr, 0x3c);
	memset(arr, 0, sizeof(arr));
	double t0 = now();
	long sum = 0;
	for (long i = 0; i < 20000000; i++) {
		hot[i & 63] += i;
		sum += hot[(i + 1) & 63];
	}
	double dt = now() - t0;
	long ref = 0;
	memset(arr, 0, sizeof(arr));
	for (long i = 0; i < 20000000; i++) {
		arr[i & 63] += i;
		ref += arr[(i + 1) & 63];
	}
	CHECK("hot-loop", sum == ref, "sum=%ld ref=%ld", sum, ref);
	printf("hot loop: %.3f s (20M tagged load+store pairs)\n", dt);

	/* fault through a tagged pointer: si_addr has no tag */
	struct sigaction sa = { 0 };
	sa.sa_sigaction = on_segv;
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGSEGV, &sa, NULL);
	volatile long *bad = (volatile long *)(0x10UL | (0x6bUL << 56));
	if (!sigsetjmp(jb, 1)) {
		(void)*bad;
		CHECK("tagged-fault", 0, "no fault");
	} else {
		CHECK("tagged-fault", fault_addr == (void *)0x10, "si_addr=%p", fault_addr);
	}

	printf("%s: %d failures\n", failures ? "TBI FAILED" : "TBI ALL PASSED", failures);
	return failures != 0;
}
