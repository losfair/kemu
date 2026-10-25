// SPDX-License-Identifier: GPL-2.0
/* Preserve guest syscall arguments across signals and JIT epoch recovery. */
#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#define THREADS 4
#define ITERATIONS 100000

static atomic_uint done;
static _Thread_local volatile sig_atomic_t signals;
static struct result {
	uint64_t regs[6];
	unsigned pid, remaining, signals;
} results[THREADS];

static void handler(int sig)
{
	(void)sig;
	signals++;
}

extern unsigned syscall_loop(unsigned pid, unsigned count, uint64_t regs[6]);
__asm__(
	".text\n.globl syscall_loop\n.type syscall_loop,%function\nsyscall_loop:\n"
	"mov x6,x0\nmov x7,x1\nmov x9,x2\n"
	"mov x1,#0x1111\nmov x2,#0x2222\nmov x3,#0x3333\n"
	"mov x4,#0x4444\nmov x5,#0x5555\n"
	"1: mov x8,#172\nsvc #0\n" /* getpid */
	"stp x0,x1,[x9]\nstp x2,x3,[x9,#16]\nstp x4,x5,[x9,#32]\n"
	"cmp x0,x6\nb.ne 2f\n"
	"mov x10,#0x1111\ncmp x1,x10\nb.ne 2f\n"
	"mov x10,#0x2222\ncmp x2,x10\nb.ne 2f\n"
	"mov x10,#0x3333\ncmp x3,x10\nb.ne 2f\n"
	"mov x10,#0x4444\ncmp x4,x10\nb.ne 2f\n"
	"mov x10,#0x5555\ncmp x5,x10\nb.ne 2f\n"
	"subs x7,x7,#1\nb.ne 1b\nmov x0,#0\nret\n"
	"2: mov x0,x7\nret\n.size syscall_loop,.-syscall_loop\n"
);

static void *worker(void *arg)
{
	uintptr_t id = (uintptr_t)arg;
	struct result *r = &results[id];

	r->pid = getpid();
	r->remaining = syscall_loop(r->pid, ITERATIONS, r->regs);
	r->signals = signals;
	atomic_fetch_or(&done, 1u << id);
	return NULL;
}

int main(void)
{
	pthread_t threads[THREADS];
	struct sigaction sa = { .sa_handler = handler };
	const struct timespec pause = { .tv_nsec = 100000 };
	unsigned failures = 0, total_signals = 0;

	sigemptyset(&sa.sa_mask);
	assert(!sigaction(SIGUSR1, &sa, NULL));
	for (uintptr_t i = 0; i < THREADS; i++)
		assert(!pthread_create(&threads[i], NULL, worker, (void *)i));
	while (atomic_load(&done) != (1u << THREADS) - 1) {
		for (unsigned i = 0; i < THREADS; i++)
			if (!(atomic_load(&done) & (1u << i)))
				assert(!pthread_kill(threads[i], SIGUSR1));
		nanosleep(&pause, NULL);
	}
	for (unsigned i = 0; i < THREADS; i++) {
		struct result *r = &results[i];

		assert(!pthread_join(threads[i], NULL));
		total_signals += r->signals;
		if (!r->remaining)
			continue;
		failures++;
		printf("FAIL syscall-state thread %u, pid %u, %u calls remaining: "
		       "x0..x5=%lx,%lx,%lx,%lx,%lx,%lx\n", i, r->pid, r->remaining,
		       r->regs[0], r->regs[1], r->regs[2], r->regs[3], r->regs[4], r->regs[5]);
	}
	assert(total_signals);
	printf("%s syscall-state (%u signals)\n", failures ? "FAIL" : "PASS", total_signals);
	return failures != 0;
}
