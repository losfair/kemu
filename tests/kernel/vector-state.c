// SPDX-License-Identifier: GPL-2.0
/* Live vector cache recovery through a fault, timer signals and sigreturn. */
#define _GNU_SOURCE
#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <ucontext.h>
#include <asm/sigcontext.h>

static volatile sig_atomic_t alarms, faults, bad_frame;
static void *fault_page;

static void handler(int sig, siginfo_t *si, void *ptr)
{
	if (sig == SIGSEGV) {
		ucontext_t *uc = ptr;
		struct fpsimd_context *fp = (void *)uc->uc_mcontext.__reserved;

		/* The first loop iteration has committed two adds to V0. */
		if (si->si_addr != fault_page || fp->head.magic != FPSIMD_MAGIC ||
		    (uint64_t)fp->vregs[0] != 3 || (uint64_t)(fp->vregs[0] >> 64) != 4)
			bad_frame = 1;
		faults++;
		if (mprotect(fault_page, 4096, PROT_READ))
			_Exit(2);
	} else {
		alarms++;
	}
	/* Leave different values in every guest vector before sigreturn. */
	__asm__ volatile(
		".irp r,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31\n"
		"movi v\\r\\().16b, #0x5a\n.endr\n"
		::: "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
		"v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
		"v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
		"v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31");
}

extern void vector_loop(uint64_t v[32][2], void *fault, unsigned count);
__asm__(
	".text\n.globl vector_loop\n.type vector_loop,%function\nvector_loop:\n"
	"stp q8,q9,[sp,#-128]!\nstp q10,q11,[sp,#32]\n"
	"stp q12,q13,[sp,#64]\nstp q14,q15,[sp,#96]\n"
	".irp r,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31\n"
	"ldr q\\r,[x0,#(16*\\r)]\n.endr\n"
	"1:\n"
	".irp r,0,1,2,3,4,5,6,7,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29\n"
	"add v\\r\\().2d,v\\r\\().2d,v31.2d\n.endr\n"
	"ldr q30,[x1]\nsubs w2,w2,#1\nb.ne 1b\n"
	".irp r,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31\n"
	"str q\\r,[x0,#(16*\\r)]\n.endr\n"
	"ldp q10,q11,[sp,#32]\nldp q12,q13,[sp,#64]\nldp q14,q15,[sp,#96]\n"
	"ldp q8,q9,[sp],#128\nret\n.size vector_loop,.-vector_loop\n");

int main(void)
{
	const unsigned n = 200000;
	uint64_t v[32][2];
	struct sigaction sa = { .sa_sigaction = handler, .sa_flags = SA_SIGINFO };
	struct itimerval timer = { .it_interval.tv_usec = 100, .it_value.tv_usec = 100 };

	fault_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	assert(fault_page != MAP_FAILED);
	((uint64_t *)fault_page)[0] = 0xfeed;
	((uint64_t *)fault_page)[1] = 0xbeef;
	assert(!mprotect(fault_page, 4096, PROT_NONE));
	sigfillset(&sa.sa_mask);
	assert(!sigaction(SIGSEGV, &sa, NULL));
	assert(!sigaction(SIGALRM, &sa, NULL));
	for (int r = 0; r < 32; r++) {
		v[r][0] = 2 * r + 1;
		v[r][1] = 2 * r + 2;
	}
	v[31][0] = v[31][1] = 1;
	assert(!setitimer(ITIMER_REAL, &timer, NULL));
	vector_loop(v, fault_page, n);
	timer.it_value.tv_usec = 0;
	assert(!setitimer(ITIMER_REAL, &timer, NULL));
	assert(faults == 1 && alarms > 0 && !bad_frame);
	for (int r = 0; r < 30; r++) {
		uint64_t delta = n * (r < 8 ? 2 : 1);
		assert(v[r][0] == 2 * r + 1 + delta && v[r][1] == 2 * r + 2 + delta);
	}
	assert(v[30][0] == 0xfeed && v[30][1] == 0xbeef);
	assert(v[31][0] == 1 && v[31][1] == 1);
	printf("PASS vector-state (%d signals, %d fault)\n", alarms, faults);
	return 0;
}
