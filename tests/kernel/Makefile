# AArch64 test programs run under kemu (scripts/vm-smoke.sh runs them).
# lzmat needs an arm64 liblzma: make lzmat LZMA_LIB=<dir with liblzma.so.5>
CC := aarch64-linux-gnu-gcc
CFLAGS := -O2 -Wall -Wno-unused-result

STATIC := abi auxv cat crash hello-static tbi vector-state
DYN := hello-dyn mtstress

all: $(STATIC) $(DYN) ../bench/intbench.arm64

abi: abi.c
	$(CC) $(CFLAGS) -static -pthread -o $@ $<
auxv cat crash tbi vector-state: %: %.c
	$(CC) $(CFLAGS) -static -o $@ $<
hello-static: hello.c
	$(CC) $(CFLAGS) -static -o $@ $<
hello-dyn: hello.c
	$(CC) $(CFLAGS) -o $@ $<
mtstress: mtstress.c
	$(CC) $(CFLAGS) -pthread -o $@ $<
lzmat: lzmat.c
	$(CC) $(CFLAGS) -pthread -o $@ $< -L$(LZMA_LIB) -l:liblzma.so.5
../bench/intbench.arm64: ../bench/intbench.c
	$(CC) -O2 -static -o $@ $<

clean:
	rm -f $(STATIC) $(DYN) lzmat

.PHONY: all clean
