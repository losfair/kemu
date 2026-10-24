// Threaded liblzma round trip (stresses multi-threaded guests under kemu).
// usage: lzmat [threads] [iterations] [MiB]
#include <lzma.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

int main(int argc, char **argv)
{
	unsigned th = argc > 1 ? atoi(argv[1]) : 4;
	int iters = argc > 2 ? atoi(argv[2]) : 4;
	size_t n = (argc > 3 ? atoi(argv[3]) : 8) << 20;
	unsigned char *in = malloc(n), *out = malloc(n), *mid = malloc(n + n / 2 + 65536);
	unsigned long long x = 88172645463325252ull;
	for (size_t i = 0; i < n; i++) {
		x ^= x << 13; x ^= x >> 7; x ^= x << 17;
		in[i] = (x % 7 == 0) ? (unsigned char)x : (unsigned char)(i / 1024);
	}
	int bad = 0, forks = getenv("FORK") ? atoi(getenv("FORK")) : 0;
	for (int f = 0; f < forks; f++) {
		pid_t pid = fork();
		if (pid == 0) { forks = 0; break; }
		int st;
		waitpid(pid, &st, 0);
		printf("fork %d: child status %#x\n", f, st);
		bad += st != 0;
	}
	if (forks) return bad != 0;
	for (int it = 0; it < iters; it++) {
		lzma_mt mt = { .threads = th, .block_size = 1 << 20, .preset = 1, .check = LZMA_CHECK_CRC64 };
		lzma_stream s = LZMA_STREAM_INIT;
		int simple = getenv("SIMPLE") != NULL;
		if ((simple ? lzma_easy_encoder(&s, 1, LZMA_CHECK_CRC64) : lzma_stream_encoder_mt(&s, &mt)) != LZMA_OK) { puts("enc init"); return 1; }
		s.next_in = in; s.avail_in = n; s.next_out = mid; s.avail_out = n + n / 2 + 65536;
		lzma_ret r = lzma_code(&s, LZMA_FINISH);
		while (r == LZMA_OK) r = lzma_code(&s, LZMA_FINISH);
		size_t clen = s.total_out;
		lzma_end(&s);
		if (r != LZMA_STREAM_END) { printf("it %d: encode err %d\n", it, r); bad++; continue; }
		lzma_stream d = LZMA_STREAM_INIT;
		lzma_mt dm = { .threads = th, .memlimit_threading = 1ull << 30, .memlimit_stop = UINT64_MAX };
		if ((simple ? lzma_stream_decoder(&d, UINT64_MAX, 0) : lzma_stream_decoder_mt(&d, &dm)) != LZMA_OK) { puts("dec init"); return 1; }
		memset(out, 0, n);
		/* Feed in small chunks, like dpkg-deb's decompressor. */
		size_t chunk = getenv("CHUNK") ? atoi(getenv("CHUNK")) : 4096, fed = 0;
		d.next_out = out; d.avail_out = n;
		do {
			if (d.avail_in == 0 && fed < clen) {
				size_t k = clen - fed < chunk ? clen - fed : chunk;
				d.next_in = mid + fed; d.avail_in = k; fed += k;
			}
			r = lzma_code(&d, fed == clen ? LZMA_FINISH : LZMA_RUN);
		} while (r == LZMA_OK);
		lzma_end(&d);
		int ok = r == LZMA_STREAM_END && memcmp(in, out, n) == 0;
		printf("it %d: clen %zu dec %d %s\n", it, clen, r, ok ? "ok" : "MISMATCH");
		bad += !ok;
	}
	return bad != 0;
}
