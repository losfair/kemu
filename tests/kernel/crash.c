#include <stdio.h>
__attribute__((noinline)) int inner(volatile int *p, int v) { *p = v; return v + 1; }
__attribute__((noinline)) int outer(int v) { return inner((int *)0x1234, v * 2) + 3; }
int main(void) { printf("about to crash\n"); return outer(21); }
