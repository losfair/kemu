// SPDX-License-Identifier: GPL-2.0
/*
 * Regression tests for the kemu security-audit fixes that are observable
 * from guest userspace:
 *   M-01  sigaltstack enforces the arm64 minimum alternate-stack size
 *   M-05  prctl(PR_SET_TSC) and mmap(MAP_32BIT) are rejected
 *   L-05  CLONE_SETTLS accepts a tagged TPIDR_EL0; DC ZVA honours TBI
 *   L-01  the kemu region is hidden from PROCMAP_QUERY and /proc/<pid>/maps
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

static int failures;
#define CHECK(name, cond, ...) do { \
	if (cond) printf("PASS %s\n", name); \
	else { printf("FAIL %s: ", name); printf(__VA_ARGS__); printf("\n"); failures++; } \
} while (0)

/* arm64 rt_sigframe needs more than x86's MINSIGSTKSZ (2048). */
#define KEMU_MINSIGSTKSZ 5120

static void test_sigaltstack(void)
{
	static char buf[16384];
	stack_t ss;

	/* Too small: must be refused with ENOMEM, not accepted via x86's 2048. */
	ss.ss_sp = buf;
	ss.ss_flags = 0;
	ss.ss_size = 4096;	/* >= x86 MINSIGSTKSZ, < arm64 requirement */
	errno = 0;
	int r = sigaltstack(&ss, NULL);
	CHECK("sigaltstack-small-enomem", r == -1 && errno == ENOMEM, "r=%d errno=%d", r, errno);

	/* Large enough: accepted. */
	ss.ss_size = sizeof(buf);
	r = sigaltstack(&ss, NULL);
	CHECK("sigaltstack-ok", r == 0, "r=%d errno=%d", r, errno);

	/* SS_DISABLE ignores size. */
	ss.ss_flags = SS_DISABLE;
	ss.ss_size = 0;
	r = sigaltstack(&ss, NULL);
	CHECK("sigaltstack-disable", r == 0, "r=%d errno=%d", r, errno);
}

static void test_prctl_mmap(void)
{
	errno = 0;
	int r = prctl(PR_SET_TSC, 1, 0, 0, 0);
	CHECK("prctl-set-tsc-einval", r == -1 && errno == EINVAL, "r=%d errno=%d", r, errno);

#ifndef MAP_32BIT
#define MAP_32BIT 0x40
#endif
	errno = 0;
	void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
	CHECK("mmap-map32bit-einval", p == MAP_FAILED && errno == EINVAL,
	      "p=%p errno=%d", p, errno);
}

/* ---- CLONE_SETTLS with a tagged TLS value ---- */
#define CHILD_STACK 65536
static char child_stack[CHILD_STACK] __attribute__((aligned(16)));
static volatile uint64_t child_tpidr;
static volatile int child_ran;

static uint64_t read_tpidr(void)
{
	uint64_t v;
	__asm__ volatile("mrs %0, tpidr_el0" : "=r"(v));
	return v;
}

static int child_fn(void *arg)
{
	(void)arg;
	child_tpidr = read_tpidr();
	child_ran = 1;
	return 0;
}

static void test_clone_settls_tagged(void)
{
	/* A TPIDR_EL0 with a non-zero top byte: a non-canonical x86 FS base,
	 * which set_new_tls() would reject, but valid for arm64 (L-05). */
	uint64_t tagged = 0xAB00000012345670ULL;
	int rc = clone(child_fn, child_stack + CHILD_STACK,
		       CLONE_VM | CLONE_SETTLS | SIGCHLD, NULL, NULL,
		       (void *)tagged, NULL);
	CHECK("clone-settls-tagged-ok", rc > 0, "clone rc=%d errno=%d", rc, errno);
	if (rc > 0) {
		while (!child_ran)
			sched_yield();
		CHECK("clone-settls-tagged-value", child_tpidr == tagged,
		      "tpidr=%llx", (unsigned long long)child_tpidr);
	}
}

/* ---- DC ZVA through a tagged pointer ---- */
static void test_dczva_tagged(void)
{
	static unsigned char buf[256] __attribute__((aligned(64)));
	uint64_t dczid;

	__asm__ volatile("mrs %0, dczid_el0" : "=r"(dczid));
	unsigned bs = 4u << (dczid & 0xf);	/* block size in bytes */

	memset(buf, 0xaa, sizeof(buf));
	unsigned char *aligned = buf + 64;
	/* Tag the top byte: with TBI the store must still hit `aligned`. */
	uint64_t tagged = (uint64_t)(uintptr_t)aligned | (0x7eULL << 56);
	__asm__ volatile("dc zva, %0" :: "r"(tagged) : "memory");

	int zeroed = 1;
	for (unsigned i = 0; i < bs; i++)
		if (aligned[i] != 0)
			zeroed = 0;
	CHECK("dczva-tagged-zeroes", zeroed, "block of %u not zeroed", bs);
	/* The byte just before the block must be untouched (no wild store). */
	CHECK("dczva-tagged-bounds", buf[63] == 0xaa, "buf[63]=%02x", buf[63]);
}

/* ---- kemu region hidden from PROCMAP_QUERY ---- */
#ifndef PROCMAP_QUERY
struct procmap_query {
	uint64_t size;
	uint64_t query_flags;
	uint64_t query_addr;
	uint64_t vma_start;
	uint64_t vma_end;
	uint64_t vma_flags;
	uint64_t vma_page_size;
	uint64_t vma_offset;
	uint64_t inode;
	uint32_t dev_major;
	uint32_t dev_minor;
	uint32_t vma_name_size;
	uint32_t build_id_size;
	uint64_t vma_name_addr;
	uint64_t build_id_addr;
};
#define PROCMAP_QUERY _IOWR('f', 17, struct procmap_query)
#endif
#ifndef PROCMAP_QUERY_COVERING_OR_NEXT_VMA
#define PROCMAP_QUERY_COVERING_OR_NEXT_VMA 0x10
#endif

static void test_region_hidden(void)
{
	/* /proc/self/maps must not mention the kemu region. */
	int fd = open("/proc/self/maps", O_RDONLY);
	int in_maps = 0;
	if (fd >= 0) {
		char data[65536];
		ssize_t n = read(fd, data, sizeof(data) - 1);
		close(fd);
		if (n > 0) {
			data[n] = 0;
			in_maps = strstr(data, "[kemu-") != NULL;
		}
	}
	CHECK("maps-region-hidden", !in_maps, "found [kemu-*] in /proc/self/maps");

	/* Walk the whole address space with PROCMAP_QUERY; no returned VMA
	 * should be a kemu region (they would have no name and sit in the high
	 * user range). We just confirm the ioctl never surfaces a named
	 * "[kemu-" region by scanning its names. */
	fd = open("/proc/self/maps", O_RDONLY);
	if (fd < 0) {
		CHECK("procmap-query-hidden", 0, "open failed");
		return;
	}
	int leaked = 0, saw_stack = 0;
	volatile int stack_marker = 0;
	uint64_t sp = (uint64_t)(uintptr_t)&stack_marker;
	uint64_t addr = 0;
	for (int i = 0; i < 4096; i++) {
		char namebuf[128] = {0};
		struct procmap_query q;
		memset(&q, 0, sizeof(q));
		q.size = sizeof(q);
		q.query_addr = addr;
		q.query_flags = PROCMAP_QUERY_COVERING_OR_NEXT_VMA;
		q.vma_name_addr = (uint64_t)(uintptr_t)namebuf;
		q.vma_name_size = sizeof(namebuf);
		if (ioctl(fd, PROCMAP_QUERY, &q) != 0)
			break;
		if (strstr(namebuf, "[kemu-"))
			leaked = 1;
		/* The scan must reach the real guest VMAs above the hidden region,
		 * e.g. the stack holding this function's locals. */
		if (q.vma_start <= sp && sp < q.vma_end)
			saw_stack = 1;
		if (q.vma_end <= addr)
			break;
		addr = q.vma_end;
	}
	close(fd);
	CHECK("procmap-query-hidden", !leaked, "PROCMAP_QUERY revealed a kemu region");
	CHECK("procmap-query-reaches-stack", saw_stack,
	      "COVERING_OR_NEXT scan did not reach the stack VMA (truncated at the kemu region?)");
}

/* ---- the sealed [vdso] trampoline rejects munmap/mprotect ---- */
static unsigned long find_vdso(void)
{
	int fd = open("/proc/self/maps", O_RDONLY);
	char data[65536];
	unsigned long start = 0;
	if (fd < 0)
		return 0;
	ssize_t n = read(fd, data, sizeof(data) - 1);
	close(fd);
	if (n <= 0)
		return 0;
	data[n] = 0;
	char *p = strstr(data, "[vdso]");
	if (!p)
		return 0;
	/* Rewind to the start of the line and parse the start address. */
	while (p > data && p[-1] != '\n')
		p--;
	sscanf(p, "%lx", &start);
	return start;
}

static void test_region_sealed(void)
{
	unsigned long vdso = find_vdso();
	if (!vdso) {
		CHECK("region-sealed", 0, "could not locate [vdso] in /proc/self/maps");
		return;
	}
	/* The [vdso] trampoline is one of the four sealed kemu mappings. */
	errno = 0;
	int r1 = mprotect((void *)vdso, 4096, PROT_READ);
	CHECK("sealed-mprotect-eperm", r1 == -1 && errno == EPERM, "r=%d errno=%d", r1, errno);
	errno = 0;
	int r2 = munmap((void *)vdso, 4096);
	CHECK("sealed-munmap-eperm", r2 == -1 && errno == EPERM, "r=%d errno=%d", r2, errno);
}

/* ---- ptrace: skip a syscall at entry and inject a return value ---- */
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <linux/elf.h>
#ifndef NT_ARM_SYSTEM_CALL
#define NT_ARM_SYSTEM_CALL 0x404
#endif

/* arm64 user_pt_regs: regs[31], sp, pc, pstate. */
struct kemu_user_pt_regs { uint64_t regs[31], sp, pc, pstate; };

static void test_ptrace_skip_inject(void)
{
	pid_t child = fork();
	if (child == 0) {
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		raise(SIGSTOP);
		/* getpid(172) -- the tracer will skip it and inject 0xdead. */
		long ret;
		register long x8 __asm__("x8") = 172;
		register long x0 __asm__("x0");
		__asm__ volatile("svc #0" : "=r"(x0) : "r"(x8) : "memory");
		ret = x0;
		_exit(ret == (long)0xdead ? 0 : 1);
	}

	int status;
	waitpid(child, &status, 0);	/* initial SIGSTOP */
	ptrace(PTRACE_SETOPTIONS, child, 0, (void *)PTRACE_O_TRACESYSGOOD);
	int injected = 0, done = 0, ok = 0;
	while (!done) {
		if (ptrace(PTRACE_SYSCALL, child, 0, 0) != 0)
			break;
		if (waitpid(child, &status, 0) < 0)
			break;
		if (WIFEXITED(status)) {
			ok = (WEXITSTATUS(status) == 0);
			done = 1;
			break;
		}
		if (WIFSTOPPED(status) && (WSTOPSIG(status) == (SIGTRAP | 0x80))) {
			struct kemu_user_pt_regs regs;
			struct iovec iov = { &regs, sizeof(regs) };
			if (ptrace(PTRACE_GETREGSET, child, (void *)NT_PRSTATUS, &iov) != 0)
				continue;
			if (!injected && regs.regs[8] == 172) {
				/* syscall-enter for getpid: skip it and set x0. */
				int nr = -1;
				struct iovec niov = { &nr, sizeof(nr) };
				ptrace(PTRACE_SETREGSET, child, (void *)NT_ARM_SYSTEM_CALL, &niov);
				regs.regs[0] = 0xdead;
				iov.iov_len = sizeof(regs);
				ptrace(PTRACE_SETREGSET, child, (void *)NT_PRSTATUS, &iov);
				injected = 1;
			}
		}
	}
	CHECK("ptrace-skip-inject", ok, "child did not observe injected x0=0xdead");
}

/*
 * A guest svc that the interpreter retires (e.g. after a translation is
 * discarded because a concurrent munmap raced it) leaves pc = svc + 4 and
 * must still be performed through the interp_svc stub. An epoch change
 * (another thread's invalidation, kemu.stress) or a pending signal on the
 * way back to user mode used to redirect to dispatch instead, silently
 * skipping the syscall and leaving x0 untouched. Each worker runs
 * "movz x0, #0xbeef; mov x8, #__NR_getpid; svc #0; ret" from a freshly
 * mapped page (a fresh translation each time) while another thread churns
 * mappings and a third keeps signalling the workers.
 */
static const uint32_t svc_tpl[] = {
	0xd297dde0,	/* movz x0, #0xbeef */
	0xd2801588,	/* mov x8, #172 (__NR_getpid) */
	0xd4000001,	/* svc #0 */
	0xd65f03c0,	/* ret */
};

#define SVC_WORKERS 3
#define SVC_ITERS 1500
#define SVC_SENTINEL 0xbeef
static volatile int svc_stop;
static volatile int svc_sigs;
static pid_t svc_tids[SVC_WORKERS];
static long svc_skipped[SVC_WORKERS], svc_wrong[SVC_WORKERS];

static void svc_sig(int sig)
{
	(void)sig;
	__atomic_fetch_add(&svc_sigs, 1, __ATOMIC_RELAXED);
}

static void *svc_worker(void *arg)
{
	long i = (long)arg;
	size_t n = sizeof(svc_tpl);
	uint64_t pid = getpid();

	__atomic_store_n(&svc_tids[i], (pid_t)syscall(SYS_gettid), __ATOMIC_RELEASE);
	for (int it = 0; it < SVC_ITERS; it++) {
		char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		uint64_t r;

		if (p == MAP_FAILED || p == NULL) {
			/* NULL: the mmap svc itself was skipped (x0 = addr arg). */
			svc_skipped[i]++;
			continue;
		}
		memcpy(p, svc_tpl, n);
		__builtin___clear_cache(p, p + n);
		r = ((uint64_t (*)(void))p)();
		if (r == SVC_SENTINEL)
			svc_skipped[i]++;
		else if (r != pid)
			svc_wrong[i]++;
		munmap(p, 4096);
	}
	return NULL;
}

static void *svc_churn(void *arg)
{
	(void)arg;
	while (!svc_stop) {
		void *q = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (q != MAP_FAILED)
			munmap(q, 4096);
	}
	return NULL;
}

static void *svc_signaller(void *arg)
{
	pid_t pid = getpid();

	(void)arg;
	while (!svc_stop) {
		for (int i = 0; i < SVC_WORKERS; i++) {
			pid_t t = __atomic_load_n(&svc_tids[i], __ATOMIC_ACQUIRE);

			if (t)
				syscall(SYS_tgkill, pid, t, SIGUSR1);
		}
		sched_yield();
	}
	return NULL;
}

/* Runs in a child: a skipped mmap or rt_sigreturn svc kills it outright. */
static int svc_race(void)
{
	struct sigaction sa = { .sa_handler = svc_sig, .sa_flags = SA_RESTART };
	pthread_t w[SVC_WORKERS], c, s;
	long skipped = 0, wrong = 0;

	sigaction(SIGUSR1, &sa, NULL);
	pthread_create(&c, NULL, svc_churn, NULL);
	pthread_create(&s, NULL, svc_signaller, NULL);
	for (long i = 0; i < SVC_WORKERS; i++)
		pthread_create(&w[i], NULL, svc_worker, (void *)i);
	for (int i = 0; i < SVC_WORKERS; i++)
		pthread_join(w[i], NULL);
	svc_stop = 1;
	pthread_join(c, NULL);
	pthread_join(s, NULL);
	for (int i = 0; i < SVC_WORKERS; i++) {
		skipped += svc_skipped[i];
		wrong += svc_wrong[i];
	}
	printf("svc-race: %d calls, %d signals, %ld skipped, %ld wrong\n",
	       SVC_WORKERS * SVC_ITERS, svc_sigs, skipped, wrong);
	return skipped || wrong;
}

static void test_svc_not_skipped(void)
{
	int st = 0;
	pid_t pid = fork();

	if (pid == 0)
		_exit(svc_race());
	waitpid(pid, &st, 0);
	CHECK("svc-not-skipped-under-churn", WIFEXITED(st) && WEXITSTATUS(st) == 0,
	      "%s %d (svc skipped or wrong result)",
	      WIFSIGNALED(st) ? "child killed by signal" : "child exit",
	      WIFSIGNALED(st) ? WTERMSIG(st) : WEXITSTATUS(st));
}

int main(void)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	test_sigaltstack();
	test_prctl_mmap();
	test_clone_settls_tagged();
	test_dczva_tagged();
	test_region_hidden();
	test_region_sealed();
	test_ptrace_skip_inject();
	test_svc_not_skipped();
	if (failures == 0)
		printf("KEMU-SEC ALL PASSED\n");
	else
		printf("KEMU-SEC %d FAILURES\n", failures);
	return failures ? 1 : 0;
}
