// Multi-threaded stress: synchronization primitives under real parallelism.
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NT 4
static int fails;
#define CHECK(c, ...) do { if (!(c)) { printf("FAIL: " __VA_ARGS__); puts(""); fails++; } } while (0)

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static long counter;
static _Atomic long acnt;
static long llsc;

static void *t_mutex(void *a)
{
	for (int i = 0; i < 200000; i++) {
		pthread_mutex_lock(&mu);
		counter++;
		pthread_mutex_unlock(&mu);
	}
	return a;
}

static void *t_atomic(void *a)
{
	for (int i = 0; i < 200000; i++) {
		atomic_fetch_add_explicit(&acnt, 1, memory_order_relaxed);
		long v = atomic_load(&acnt);
		while (!atomic_compare_exchange_weak(&acnt, &v, v + 2))
			;
	}
	return a;
}

static void *t_llsc(void *a)
{
	for (int i = 0; i < 200000; i++) {
		long tmp; int st;
#ifdef __aarch64__
		__asm__ volatile("1: ldaxr %0, [%2]\n add %0, %0, #3\n stlxr %w1, %0, [%2]\n cbnz %w1, 1b"
				 : "=&r"(tmp), "=&r"(st) : "r"(&llsc) : "memory");
#else
		(void)tmp; (void)st; __atomic_fetch_add(&llsc, 3, __ATOMIC_SEQ_CST);
#endif
	}
	return a;
}

/* Store-buffer litmus with seq_cst: r0 == r1 == 0 is forbidden. */
static _Atomic int sx, sy, go_sb;
static int r0[100000], r1[100000];
static _Atomic int phase;
static void *sb_a(void *a)
{
	for (int i = 0; i < 100000; i++) {
		while (atomic_load(&phase) < 2 * i + 1) ;
		atomic_store(&sx, 1);
		r0[i] = atomic_load(&sy);
		atomic_fetch_add(&go_sb, 1);
		while (atomic_load(&phase) < 2 * i + 2) ;
	}
	return a;
}
static void *sb_b(void *a)
{
	for (int i = 0; i < 100000; i++) {
		while (atomic_load(&phase) < 2 * i + 1) ;
		atomic_store(&sy, 1);
		r1[i] = atomic_load(&sx);
		atomic_fetch_add(&go_sb, 1);
		while (atomic_load(&phase) < 2 * i + 2) ;
	}
	return a;
}

/* Condvar producer/consumer with checksummed buffers. */
#define QN 8
static struct { unsigned char d[4096]; unsigned sum; } q[QN];
static int qh, qt;
static pthread_cond_t cv_ne = PTHREAD_COND_INITIALIZER, cv_nf = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t qm = PTHREAD_MUTEX_INITIALIZER;
static long bad_bufs;
static void *prod(void *a)
{
	unsigned seed = (unsigned)(long)a;
	for (int i = 0; i < 20000; i++) {
		pthread_mutex_lock(&qm);
		while (qh - qt == QN) pthread_cond_wait(&cv_nf, &qm);
		int slot = qh % QN;
		unsigned s = 0;
		for (int k = 0; k < 4096; k++) { seed = seed * 1103515245 + 12345; q[slot].d[k] = seed >> 16; s += q[slot].d[k] * (k + 1); }
		q[slot].sum = s;
		qh++;
		pthread_cond_signal(&cv_ne);
		pthread_mutex_unlock(&qm);
	}
	return a;
}
static void *cons(void *a)
{
	for (int i = 0; i < 20000; i++) {
		pthread_mutex_lock(&qm);
		while (qh == qt) pthread_cond_wait(&cv_ne, &qm);
		int slot = qt % QN;
		unsigned s = 0;
		for (int k = 0; k < 4096; k++) s += q[slot].d[k] * (k + 1);
		if (s != q[slot].sum) bad_bufs++;
		qt++;
		pthread_cond_signal(&cv_nf);
		pthread_mutex_unlock(&qm);
	}
	return a;
}

static void run(void *(*f)(void *))
{
	pthread_t t[NT];
	for (long i = 0; i < NT; i++) pthread_create(&t[i], 0, f, (void *)i);
	for (int i = 0; i < NT; i++) pthread_join(t[i], 0);
}

int main(int argc, char **argv)
{
	const char *only = argc > 1 ? argv[1] : "";
	if (!*only || strstr(only, "mutex")) { run(t_mutex); CHECK(counter == NT * 200000L, "mutex counter %ld", counter); puts("mutex done"); }
	if (!*only || strstr(only, "atomic")) { run(t_atomic); CHECK(acnt == NT * 600000L, "atomic counter %ld", (long)acnt); puts("atomic done"); }
	if (!*only || strstr(only, "llsc")) { run(t_llsc); CHECK(llsc == NT * 600000L, "llsc counter %ld", llsc); puts("llsc done"); }
	if (!*only || strstr(only, "sb")) {
		pthread_t a, b;
		pthread_create(&a, 0, sb_a, 0); pthread_create(&b, 0, sb_b, 0);
		int both0 = 0;
		for (int i = 0; i < 100000; i++) {
			atomic_store(&sx, 0); atomic_store(&sy, 0); atomic_store(&go_sb, 0);
			atomic_store(&phase, 2 * i + 1);
			while (atomic_load(&go_sb) != 2) ;
			atomic_store(&phase, 2 * i + 2);
		}
		pthread_join(a, 0); pthread_join(b, 0);
		for (int i = 0; i < 100000; i++) both0 += !r0[i] && !r1[i];
		CHECK(both0 == 0, "seq_cst store-buffer violations: %d", both0);
		puts("sb done");
	}
	if (!*only || strstr(only, "cond")) {
		pthread_t p[2], c[2];
		for (long i = 0; i < 2; i++) { pthread_create(&p[i], 0, prod, (void *)(i + 1)); pthread_create(&c[i], 0, cons, 0); }
		for (int i = 0; i < 2; i++) { pthread_join(p[i], 0); pthread_join(c[i], 0); }
		CHECK(bad_bufs == 0, "corrupt buffers %ld", bad_bufs);
		puts("cond done");
	}
	printf("mtstress: %s\n", fails ? "FAILED" : "ok");
	return !!fails;
}
