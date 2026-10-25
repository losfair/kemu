// SPDX-License-Identifier: GPL-2.0
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <zlib.h>

#define SIZE (1u << 20)
static unsigned char input[SIZE], output[SIZE];

static double now(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec + t.tv_nsec * 1e-9;
}

int main(int argc, char **argv)
{
	unsigned rounds = argc > 2 ? strtoul(argv[2], NULL, 0) : 10;
	unsigned bytes = argc > 3 ? strtoul(argv[3], NULL, 0) : SIZE;
	if (!rounds || !bytes || bytes > SIZE) return 2;
	setvbuf(stdout, NULL, _IOLBF, 0);
	unsigned rng = 12345;
	const char text[] = "The quick brown fox jumps over the lazy dog. 0123456789\n";
	for (unsigned i = 0; i < bytes; i++) {
		rng = rng * 1664525u + 1013904223u;
		input[i] = i % 4096 < 3072 ? text[i % (sizeof(text)-1)] : rng >> 24;
	}
	uLongf capacity = compressBound(bytes), size = capacity;
	unsigned char *compressed = malloc(capacity);
	assert(compressed && compress2(compressed, &size, input, bytes, 6) == Z_OK);
	const char *names[] = { "compress", "decompress", "adler32", "crc32" };
	for (unsigned k = 0; k < 4; k++) {
		if (argc > 1 && strcmp(argv[1], "all") && strcmp(argv[1], names[k])) continue;
		unsigned long checksum = 0;
		double start = now();
		for (unsigned r = 0; r < rounds; r++) {
			if (k == 0) {
				size = capacity;
				assert(compress2(compressed, &size, input, bytes, 6) == Z_OK);
				checksum += size;
			} else if (k == 1) {
				uLongf len = bytes;
				assert(uncompress(output, &len, compressed, size) == Z_OK && len == bytes);
				checksum += output[r % bytes];
			} else if (k == 2) checksum += adler32(1, input, bytes);
			else checksum += crc32(0, input, bytes);
		}
		double elapsed = now() - start;
		if (k < 2) {
			uLongf len = bytes;
			assert(uncompress(output, &len, compressed, size) == Z_OK && len == bytes);
			assert(!memcmp(input, output, bytes));
		}
		printf("ZLIB %-10s rounds=%u bytes=%u ms=%.3f MiB/s=%.2f checksum=%lu version=%s\n",
		       names[k], rounds, bytes, elapsed*1000, (double)rounds * bytes / SIZE / elapsed, checksum, zlibVersion());
	}
	free(compressed);
	return 0;
}
