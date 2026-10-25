// SPDX-License-Identifier: GPL-2.0
/*
 * kemu ABI selftest: run as an AArch64 binary under kemu.
 * Each check prints "PASS name" or "FAIL name: why".
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <ucontext.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <sys/utsname.h>
#include <sys/syscall.h>
#include <sys/auxv.h>
#include <stdatomic.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <elf.h>
#include <asm/ptrace.h>

static int failures;

#define CHECK(name, cond, ...) do { \
	if (cond) printf("PASS %s\n", name); \
	else { failures++; printf("FAIL %s: ", name); printf(__VA_ARGS__); printf("\n"); } \
} while (0)

/* ---- signals ---- */

static volatile int got_usr1;
static void on_usr1(int sig) { got_usr1 = sig; }

static sigjmp_buf segv_jb;
static volatile void *segv_addr;
static volatile int segv_code;
static void on_segv(int sig, siginfo_t *si, void *uc)
{
	segv_addr = si->si_addr;
	segv_code = si->si_code;
	siglongjmp(segv_jb, 1);
}

static volatile unsigned long ctx_pc, ctx_x19;
static void on_trap(int sig, siginfo_t *si, void *ucv)
{
	ucontext_t *uc = ucv;
	ctx_pc = uc->uc_mcontext.pc;
	ctx_x19 = uc->uc_mcontext.regs[19];
	uc->uc_mcontext.pc += 4;	/* skip the brk */
}

static void test_signals(void)
{
	struct sigaction sa = { 0 };

	sa.sa_handler = on_usr1;
	sigaction(SIGUSR1, &sa, NULL);
	raise(SIGUSR1);
	CHECK("signal-handler", got_usr1 == SIGUSR1, "got %d", got_usr1);

	sa.sa_sigaction = on_segv;
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGSEGV, &sa, NULL);
	if (!sigsetjmp(segv_jb, 1)) {
		*(volatile int *)0x10 = 1;
		CHECK("sigsegv", 0, "no fault");
	} else {
		CHECK("sigsegv", segv_addr == (void *)0x10 && segv_code == SEGV_MAPERR,
		      "addr %p code %d", segv_addr, segv_code);
	}

	/* Beyond the 48-bit VA range (non-canonical on x86): SEGV_MAPERR + address */
	if (!sigsetjmp(segv_jb, 1)) {
		(void)*(volatile long *)0x0041c000b0004680UL;
		CHECK("sigsegv-high", 0, "no fault");
	} else {
		CHECK("sigsegv-high", segv_addr == (void *)0x0041c000b0004680UL && segv_code == SEGV_MAPERR,
		      "addr %p code %d", segv_addr, segv_code);
	}

	/* Read-only page: SEGV_ACCERR */
	char *ro = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (!sigsetjmp(segv_jb, 1)) {
		ro[8] = 1;
		CHECK("sigsegv-accerr", 0, "no fault");
	} else {
		CHECK("sigsegv-accerr", segv_addr == ro + 8 && segv_code == SEGV_ACCERR,
		      "addr %p (want %p) code %d", segv_addr, ro + 8, segv_code);
	}

	/* ucontext: handler sees pc/regs and can modify pc */
	sa.sa_sigaction = on_trap;
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGTRAP, &sa, NULL);
	unsigned long pc_brk;
	register unsigned long x19 asm("x19") = 0x1234567890abcdefUL;
	asm volatile("adr %0, 1f\n1: brk #0x7" : "=r"(pc_brk), "+r"(x19));
	CHECK("ucontext", ctx_pc == pc_brk && ctx_x19 == 0x1234567890abcdefUL,
	      "pc %lx want %lx x19 %lx", ctx_pc, pc_brk, ctx_x19);

	/* sigaltstack */
	stack_t ss = { .ss_sp = malloc(65536), .ss_size = 65536 };
	CHECK("sigaltstack", sigaltstack(&ss, NULL) == 0, "errno %d", errno);
}

/* ---- threads ---- */

static atomic_int counter;
static __thread int tls_var = 7;

static void *thr(void *arg)
{
	for (int i = 0; i < 100000; i++)
		atomic_fetch_add(&counter, 1);
	tls_var += (int)(long)arg;
	return (void *)(long)tls_var;
}

static void test_threads(void)
{
	pthread_t t[4];
	long sum = 0;

	for (long i = 0; i < 4; i++)
		pthread_create(&t[i], NULL, thr, (void *)i);
	for (int i = 0; i < 4; i++) {
		void *r;
		pthread_join(t[i], &r);
		sum += (long)r;
	}
	CHECK("threads-atomic", counter == 400000, "counter %d", counter);
	CHECK("threads-tls", sum == 7 * 4 + 0 + 1 + 2 + 3 && tls_var == 7, "sum %ld tls %d", sum, tls_var);

	pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
	pthread_mutex_lock(&m);
	pthread_mutex_unlock(&m);
	CHECK("mutex", 1, "");
}

/* ---- processes ---- */

static void test_process(const char *self)
{
	pid_t p = fork();
	if (p == 0)
		_exit(17);
	int st;
	waitpid(p, &st, 0);
	CHECK("fork-wait", WIFEXITED(st) && WEXITSTATUS(st) == 17, "status %x", st);

	int fds[2];
	pipe(fds);
	p = fork();
	if (p == 0) {
		dup2(fds[1], 1);
		execl(self, self, "child", NULL);
		_exit(99);
	}
	close(fds[1]);
	char buf[64] = { 0 };
	read(fds[0], buf, sizeof(buf) - 1);
	waitpid(p, &st, 0);
	CHECK("exec", strcmp(buf, "child ok\n") == 0 && WEXITSTATUS(st) == 0,
	      "got '%s' status %x", buf, st);

	p = vfork();
	if (p == 0)
		_exit(3);
	waitpid(p, &st, 0);
	CHECK("vfork", WEXITSTATUS(st) == 3, "status %x", st);

	/* exec a native x86_64 binary */
	p = fork();
	if (p == 0) {
		execl("/bin/true", "true", NULL);
		_exit(98);
	}
	waitpid(p, &st, 0);
	CHECK("exec-native", WIFEXITED(st) && WEXITSTATUS(st) == 0, "status %x", st);
}

/* ---- files ---- */

static void test_files(void)
{
	struct stat st;
	int fd = open("/tmp/kemu-test", O_CREAT | O_RDWR | O_TRUNC, 0644);
	CHECK("open", fd >= 0, "errno %d", errno);
	write(fd, "abcdef", 6);
	CHECK("fstat", fstat(fd, &st) == 0 && st.st_size == 6 && S_ISREG(st.st_mode),
	      "size %ld mode %o", (long)st.st_size, st.st_mode);
	CHECK("stat", stat("/tmp/kemu-test", &st) == 0 && st.st_size == 6, "errno %d", errno);
	int fl = fcntl(fd, F_GETFL);
	CHECK("fcntl-getfl", (fl & O_ACCMODE) == O_RDWR && !(fl & O_DIRECTORY), "flags %o", fl);
	close(fd);

	CHECK("o_directory", open("/tmp/kemu-test", O_RDONLY | O_DIRECTORY) < 0 && errno == ENOTDIR,
	      "errno %d", errno);
	DIR *d = opendir("/");
	int n = 0;
	struct dirent *e;
	while (d && (e = readdir(d)))
		n++;
	CHECK("opendir", d && n > 3, "entries %d", n);
	CHECK("o_nofollow", symlink("/tmp/kemu-test", "/tmp/kemu-link") == 0 &&
	      open("/tmp/kemu-link", O_RDONLY | O_NOFOLLOW) < 0 && errno == ELOOP, "errno %d", errno);
	unlink("/tmp/kemu-link");
	unlink("/tmp/kemu-test");

	struct utsname u;
	uname(&u);
	CHECK("uname", strcmp(u.machine, "aarch64") == 0, "machine %s", u.machine);
}

static void test_epoll(void)
{
	int fds[2], ep = epoll_create1(0);
	struct epoll_event ev = { .events = EPOLLIN, .data.u64 = 0x1122334455667788ULL }, out[4];

	pipe(fds);
	epoll_ctl(ep, EPOLL_CTL_ADD, fds[0], &ev);
	write(fds[1], "x", 1);
	int n = epoll_wait(ep, out, 4, 1000);
	CHECK("epoll", n == 1 && out[0].events == EPOLLIN && out[0].data.u64 == 0x1122334455667788ULL,
	      "n %d events %x data %llx", n, n > 0 ? out[0].events : 0,
	      n > 0 ? (unsigned long long)out[0].data.u64 : 0ULL);
	/* io_uring is not offered to guests (it reads native structs). */
	long r = syscall(425 /* io_uring_setup */, 8, calloc(1, 128));
	CHECK("io_uring disabled", r == -1 && errno == ENOSYS, "r %ld errno %d", r, errno);
}

static void test_ptrace(void)
{
	pid_t p = fork();
	if (p == 0) {
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		raise(SIGSTOP);
		for (volatile int i = 0; i < 10; i++)
			;
		getpid();
		_exit(5);
	}
	int st;
	waitpid(p, &st, 0);
	struct user_pt_regs r;
	struct iovec iov = { &r, sizeof(r) };
	long ok = ptrace(PTRACE_GETREGSET, p, NT_PRSTATUS, &iov);
	CHECK("ptrace-getregset", ok == 0 && iov.iov_len == sizeof(r) && r.pc > 0x400000 && (r.sp & 15) == 0,
	      "ret %ld len %zu pc %llx sp %llx", ok, iov.iov_len, r.pc, r.sp);
	unsigned long long pc0 = r.pc;
	int steps = 0, seq = 1;
	for (int i = 0; i < 5; i++) {
		unsigned long long prev = r.pc;
		ptrace(PTRACE_SINGLESTEP, p, 0, 0);
		waitpid(p, &st, 0);
		if (!WIFSTOPPED(st) || WSTOPSIG(st) != SIGTRAP)
			break;
		ptrace(PTRACE_GETREGSET, p, NT_PRSTATUS, &iov);
		if (r.pc == prev)
			seq = 0;
		steps++;
	}
	CHECK("ptrace-singlestep", steps == 5 && seq && r.pc != pc0, "steps %d pc %llx", steps, r.pc);
	/* Syscall stops: find getpid (172 on arm64) */
	int found = 0;
	for (int i = 0; i < 200 && !found; i++) {
		ptrace(PTRACE_SYSCALL, p, 0, 0);
		waitpid(p, &st, 0);
		if (!WIFSTOPPED(st))
			break;
		int nr = -2;
		struct iovec iv = { &nr, sizeof(nr) };
		ptrace(PTRACE_GETREGSET, p, 0x404 /* NT_ARM_SYSTEM_CALL */, &iv);
		if (nr == 172)
			found = 1;
	}
	CHECK("ptrace-syscall", found, "no getpid stop");
	ptrace(PTRACE_CONT, p, 0, 0);
	ptrace(PTRACE_CONT, p, 0, 0);
	waitpid(p, &st, 0);
	CHECK("ptrace-exit", WIFEXITED(st) && WEXITSTATUS(st) == 5, "status %x", st);
}

static void test_misc(void)
{
	struct timespec a, b;
	clock_gettime(CLOCK_MONOTONIC, &a);
	usleep(10000);
	clock_gettime(CLOCK_MONOTONIC, &b);
	long dt = (b.tv_sec - a.tv_sec) * 1000000000L + (b.tv_nsec - a.tv_nsec);
	CHECK("clock-usleep", dt >= 10000000 && dt < 1000000000, "dt %ld", dt);

	unsigned long hw = getauxval(AT_HWCAP);
	CHECK("hwcap", (hw & 3) == 3, "hwcap %lx", hw);
	CHECK("pagesize", sysconf(_SC_PAGESIZE) == 4096, "%ld", sysconf(_SC_PAGESIZE));

	void *m = mmap(NULL, 1 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	memset(m, 0x5a, 1 << 20);
	CHECK("mmap", ((unsigned char *)m)[12345] == 0x5a, "");
	CHECK("munmap", munmap(m, 1 << 20) == 0, "");

	unsigned long tp;
	asm volatile("mrs %0, tpidr_el0" : "=r"(tp));
	CHECK("tpidr", tp != 0, "tp %lx", tp);

	unsigned long cnt1, cnt2, frq;
	asm volatile("mrs %0, cntvct_el0" : "=r"(cnt1));
	asm volatile("mrs %0, cntfrq_el0" : "=r"(frq));
	asm volatile("mrs %0, cntvct_el0" : "=r"(cnt2));
	CHECK("cntvct", cnt2 >= cnt1 && frq > 1000000, "cnt %lu %lu frq %lu", cnt1, cnt2, frq);
}

int main(int argc, char **argv)
{
	if (argc > 1 && !strcmp(argv[1], "child")) {
		printf("child ok\n");
		return 0;
	}
	setvbuf(stdout, NULL, _IONBF, 0);
	test_signals();
	test_threads();
	test_process(argv[0]);
	test_files();
	test_epoll();
	test_ptrace();
	test_misc();
	printf("%s: %d failures\n", failures ? "FAILED" : "ALL PASSED", failures);
	return failures != 0;
}
