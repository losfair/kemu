// Simple integer benchmarks: sieve, sort, hash, matrix (int), linked list.
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

static long now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1000000L + t.tv_nsec / 1000; }

static uint64_t sieve(int n) {
	char *s = calloc(n, 1); uint64_t c = 0;
	for (int i = 2; i < n; i++) if (!s[i]) { c += i; for (long j = (long)i * i; j < n; j += i) s[j] = 1; }
	free(s); return c;
}
static int cmp(const void *a, const void *b) { uint32_t x = *(uint32_t*)a, y = *(uint32_t*)b; return x < y ? -1 : x > y; }
static uint64_t sortb(int n) {
	uint32_t *a = malloc(n * 4); uint32_t x = 12345;
	for (int i = 0; i < n; i++) { x ^= x << 13; x ^= x >> 17; x ^= x << 5; a[i] = x; }
	qsort(a, n, 4, cmp); uint64_t s = 0; for (int i = 0; i < n; i += 1000) s += a[i]; free(a); return s;
}
static uint64_t hashb(int n) {
	uint64_t h = 1469598103934665603ULL;
	for (int i = 0; i < n; i++) { h ^= (uint64_t)i * 0x9e3779b97f4a7c15ULL; h *= 1099511628211ULL; h = (h << 13) | (h >> 51); }
	return h;
}
static uint64_t matb(int n) {
	int *a = malloc(n*n*4), *b = malloc(n*n*4), *c = calloc(n*n, 4);
	for (int i = 0; i < n*n; i++) { a[i] = i % 7; b[i] = i % 5; }
	for (int i = 0; i < n; i++) for (int k = 0; k < n; k++) { int t = a[i*n+k]; for (int j = 0; j < n; j++) c[i*n+j] += t * b[k*n+j]; }
	uint64_t s = 0; for (int i = 0; i < n*n; i++) s += c[i]; free(a); free(b); free(c); return s;
}
struct node { struct node *next; long v; };
static uint64_t listb(int n, int iters) {
	struct node *nodes = malloc(n * sizeof *nodes); int *perm = malloc(n * 4);
	for (int i = 0; i < n; i++) perm[i] = i;
	uint32_t x = 7; for (int i = n - 1; i > 0; i--) { x ^= x << 13; x ^= x >> 17; x ^= x << 5; int j = x % (i + 1); int t = perm[i]; perm[i] = perm[j]; perm[j] = t; }
	for (int i = 0; i < n; i++) { nodes[perm[i]].next = &nodes[perm[(i + 1) % n]]; nodes[i].v = i; }
	uint64_t s = 0; struct node *p = &nodes[0];
	for (int k = 0; k < iters; k++) { s += p->v; p = p->next; }
	free(nodes); free(perm); return s;
}

int main(int argc, char **argv) {
	long total = 0, t; uint64_t r;
#define RUN(name, expr) t = now(); r = expr; t = now() - t; total += t; printf("%-8s %8ld ms  (%llx)\n", name, t / 1000, (unsigned long long)r);
	RUN("sieve", sieve(20000000));
	RUN("sort", sortb(2000000));
	RUN("hash", hashb(200000000));
	RUN("matmul", matb(400));
	RUN("list", listb(1 << 16, 50000000));
	printf("total    %8ld ms\n", total / 1000);
	return 0;
}
