// SPDX-License-Identifier: GPL-2.0
/* FP exceptions must survive signals arriving before a JIT stub spills MXCSR. */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <ucontext.h>

static volatile sig_atomic_t waiting, samples, failures, ticks;

static void alarm_handler(int sig, siginfo_t *info, void *context)
{
	(void)sig;
	(void)info;
	ticks++;
	if (!waiting) return;
	ucontext_t *uc = context;
	unsigned char *p = uc->uc_mcontext.__reserved;
	unsigned char *end = p + sizeof(uc->uc_mcontext.__reserved);
	int found = 0;
	while (p + 8 <= end) {
		unsigned magic, size, fpsr;
		memcpy(&magic, p, 4);
		memcpy(&size, p + 4, 4);
		if (size < 8 || size > (unsigned)(end - p)) break;
		if (magic == 0x46508001 && size >= 16) { /* FPSIMD_MAGIC */
			memcpy(&fpsr, p + 8, 4);
			/* All four exceptions were raised in translated code. */
			if ((fpsr & 0x1b) != 0x1b) failures++;
			found = 1;
			break;
		}
		p += size;
	}
	if (!found) failures++;
	samples++;
	waiting = 0;
}

int main(void)
{
	struct sigaction sa = { .sa_sigaction = alarm_handler, .sa_flags = SA_SIGINFO };
	struct itimerval timer = { .it_interval = { 0, 1000 }, .it_value = { 0, 1000 } };
	if (sigaction(SIGALRM, &sa, NULL) || setitimer(ITIMER_REAL, &timer, NULL)) return 2;
	for (unsigned i = 0; i < 100; i++) {
		/* DZC (1/0), IOC (0/0), UFC|IXC (smallest subnormal squared).
		 * The waiting flag is published after the exceptions, then the
		 * integer-only loop makes no host calls before signal delivery. */
		__asm__ volatile(
			"msr fpcr, xzr\n\tmsr fpsr, xzr\n\t"
			"fmov s0, #1.0\n\tfmov s1, wzr\n\t"
			"fdiv s2, s0, s1\n\tfdiv s2, s1, s1\n\t"
			"mov w9, #1\n\tfmov s0, w9\n\tfmul s2, s0, s0\n\t"
			"str w9, [%0]\n\t"
			"1: ldr w9, [%0]\n\tcbnz w9, 1b\n\t"
			:: "r"(&waiting) : "x9", "v0", "v1", "v2", "memory");
		if (ticks > 10000) return 2;
	}
	timer = (struct itimerval){0};
	setitimer(ITIMER_REAL, &timer, NULL);
	printf("fp-status: %d samples, %d failures\n", samples, failures);
	return failures || samples != 100;
}
