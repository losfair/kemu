# kemu

kemu is an in-kernel emulator that lets an x86_64 Linux machine run AArch64
(arm64) Linux programs transparently. `execve()` of an arm64 ELF just works:
the kernel translates the guest code to x86_64 on the fly. The program sees an
arm64 kernel: arm64 syscall numbers, signal frames, ptrace regsets, `/proc`
views and core dumps.

- Out-of-tree patch set for **Linux v6.18**.
- The translator, decoder and interpreter are in **Rust** (`no_std`, no kernel
  dependencies, so they can also be tested in userspace). The kernel glue is C.
- Integer code runs close to native speed (see [Status](#status)).

The design is in [DESIGN.md](DESIGN.md). §18 there is the detailed
implementation status.

## Status

Working:

- A full Debian trixie arm64 userland: debootstrap's second stage, dpkg, bash,
  python3, gcc/binutils, make, perl, git, coreutils, strace and multithreaded xz.
- Guest JITs: OpenJDK 21 (HotSpot), Node.js 20 (V8 with wasm), LuaJIT, PyPy and
  Ruby YJIT. kemu invalidates translations per guest page when a guest JIT
  rewrites its code (`IC IVAU`).
- Threads, futexes, LL/SC and seq_cst atomics, signals, ptrace and
  single-step, core dumps, seccomp/audit as `AUDIT_ARCH_AARCH64`.
- T1 JIT with superblocks, block chaining, register remapping and lazy flags.
- Block-local caching of up to eight guest vectors in XMM registers, retained
  across self-loops, with saved-XMM recovery for signals and faults.
- SHA-256 rounds and message schedules use SHA-NI when available, with
  AVX2 lowering on other hosts. Vector byte reversal stays in translated
  code in both cases.
- SHA-1 and byte-wise PMULL/PMULL2 translated to AVX2. AES instructions
  use AES-NI and 64-bit PMULL/PMULL2 use PCLMULQDQ when the host provides
  them; otherwise those instructions use the interpreter. Optional host
  features are detected without changing the x86-64-v3 minimum.
- FPCR/FPSR reads and writes, NEON bit selects, and libc/compiler bit
  scans, population counts and reductions stay in translated code.
- Scalar SIMD lane moves and scalar/byte shifts used in GHASH stay in
  translated code as well, avoiding helpers in OpenSSL's AES-GCM loop.
- A shared translation cache for file-backed code. Library code translated by
  one process is reused by the next one after re-validating it against the
  bytes in memory. Adjacent validation reads are batched within executable
  pages. Per-process code chunks grow on demand up to 128 MiB, so a GCC
  compilation can retain its working set without a mid-compile flush.
- The decoder and interpreter are checked against Arm's machine-readable A64
  specification and differentially against qemu (`tools/isa-audit`,
  `tools/difftest`).

Performance, measured against native x86_64 builds of the same C source
(`tests/bench/intbench.c`):

| Benchmark | % of native |
|---|---|
| integer overall | ~100% |
| sieve / hash / list | 97–100% |
| qsort | ~84% |
| matmul (NEON) | ~65% |

Tagged pointers work as on arm64 Linux: the top byte of data addresses is
ignored (TBI). Untagged code runs at full speed; code that uses tags is
retranslated with address masking after a few faults.

io_uring isn't offered to arm64 programs (the syscalls return `ENOSYS` and
libraries fall back to plain syscalls), because ring operations use native
struct layouts behind kemu's back.

Not done yet: a real vDSO, rseq, perf callchains through translated code, the
optimizing tier (T2), cross-block vector allocation, the LSM hook and the
code-cache verifier.

## Layout

```
overlay/            new files copied into the kernel tree
  kernel/kemu/      C glue: binfmt, syscalls, signals, ptrace, JIT driver, shared cache
  arch/x86/kemu/    x86 entry hooks
  rust/kemu_core/   decoder, interpreter, T1 translator, recovery metadata
patches/            changes to existing kernel files, one patch per hook area
scripts/            apply/build/boot helpers
tests/kernel/       AArch64 test programs (ABI suite, threading stress, ...)
tests/jit-workloads/ JIT-heavy guest programs (HotSpot, V8, LuaJIT, PyPy, YJIT)
tests/bench/        intbench
tools/kemu-user/    run arm64 binaries in userspace on kemu_core (fast iteration, perf)
tools/jit-test/     random differential test: JIT vs interpreter, incl. async interrupts
tools/difftest/     interpreter vs qemu-aarch64, per instruction class
tools/isa-audit/    decoder check against Arm's A64 XML spec
```

## Building

Requirements: clang/lld/llvm, Rust 1.88.0 with `rust-src`, `bindgen-cli`
0.71, and the usual kernel build dependencies. The host CPU must be
x86-64-v3 (AVX2, BMI1/2) because the JIT emits those instructions. kemu doesn't
check this at boot yet.

```sh
# Pristine v6.18 tree
curl -sSfL https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.18.tar.xz | tar -xJ
scripts/apply.sh linux-6.18

cd linux-6.18
rustup override set 1.88.0
make LLVM=1 defconfig kvm_guest.config
scripts/kconfig/merge_config.sh -m .config ../ci/kemu.config   # CONFIG_RUST + CONFIG_KEMU
make LLVM=1 olddefconfig
make LLVM=1 -j$(nproc) bzImage
```

When working on kemu itself, `scripts/build.sh` re-syncs `overlay/` into an
already patched tree (`$LINUX`, default `~/src/linux-6.18`) and rebuilds.
`scripts/export-patches.sh` regenerates `patches/` from that tree.

### Architecture interface

The common emulator uses the architecture interface in `asm/kemu.h` for
register access, syscall entry, TLS, fault information and ELF personality.
The native implementation lives in `overlay/arch/x86/`; other x86_64 kernel
ports supply their own architecture code and select `HAVE_KEMU`.

To enable the vector register cache, a port defines `KEMU_ARCH_VECTOR_CACHE`
as 1 and provides `u32 kemu_arch_read_fpu(u64 xmm[8][2])` in `asm/kemu.h`. It must
capture the interrupted task's user XMM0..7 and return MXCSR, synchronizing live FPU state
first, and work in task context with IRQs either enabled or disabled. Without
this opt-in, vectors remain in the state page. The native implementation
handles lazy FPU state and XSAVE's init-state optimization. Userspace callers
opt in with `Cfg::vector_cache` and supply `HostRegs::xmm` during recovery.
Recovery must also merge live MXCSR exception flags into FPSR; in page-state
stub ranges, use the saved MXCSR image instead (live state may precede a reload
or signal return).

Host atomic access, the virtual counter and random-number generation use
the `kemu_arch_*` services declared in `include/linux/kemu.h`. The common
layer validates atomic sizes and alignment before calling the backend.
Architecture entry code must run syscall-exit tracing after `kemu_svc()`
returns, so tracers see the result in the emulated register state. Kernel
ports also supply the lifecycle, signal, fault and ptrace call sites from
that header and the native syscall wrappers used by `syscall_table.h`.

## Running

On a kemu kernel, arm64 binaries run directly:

```sh
./hello-static                     # static binaries need nothing else
chroot /srv/debian-arm64 /bin/bash # dynamic ones need an arm64 userland
```

To try it in a VM, `scripts/run-vm.sh` boots the kernel under QEMU/KVM with a
busybox initramfs. The repo is mounted at `/mnt` and the host's
`/usr/aarch64-linux-gnu` serves as the arm64 sysroot:

```sh
make -C tests/kernel                         # needs aarch64-linux-gnu-gcc
scripts/run-vm.sh                            # interactive shell
scripts/run-vm.sh './tests/kernel/abi'       # run one command and power off
scripts/vm-smoke.sh                          # the CI test run
```

For a full Debian arm64 rootfs, run `scripts/mkrootfs.sh stage1` (debootstrap on
the host) and then `scripts/mkrootfs.sh stage2` (the second stage, run under
kemu). Then:

```sh
KEMU_DISK=build/arm64.img scripts/run-vm.sh \
  '. scripts/chroot-run.sh; chroot /r /usr/bin/python3 -c "print(1)"'
```

Use absolute paths after `chroot /r`: busybox's `chroot` applet prefers its own
x86 applets over the rootfs's binaries.

### Kernel parameters

| Parameter | Effect |
|---|---|
| `kemu.jit=0` | interpreter only |
| `kemu.jitoff=<mask>` | turn off JIT features one at a time, for bisecting (1 helper for all non-branches, 2 helper for SIMD/FP, 4 one-insn blocks, 8 no chaining, 32 no register remapping, 64 no vector cache) |
| `kemu.xcache=0` | disable the shared translation cache |
| `kemu.xcache_mb=<n>` | shared cache size limit (default 128) |
| `kemu.debug=1` | per-process translation statistics on exit |
| `kemu.stress=<n>` | debug: every n translations, interrupt all other threads of the process so their state is recovered mid-block |

## Testing

```sh
cargo test --manifest-path overlay/rust/kemu_core/Cargo.toml --features std
cargo run --release --manifest-path tools/jit-test/Cargo.toml -- 100000
INTR=50 RELOC=1 tools/jit-test/target/release/jit-test 50000   # async interrupts + relocation
INTR=50 RELOC=1 tools/jit-test/target/release/jit-test 20000 1 6 # SHA256, with no interpreter fallback
NO_SHA=1 INTR=50 RELOC=1 tools/jit-test/target/release/jit-test 20000 1 6 # AVX2 fallback
INTR=50 RELOC=1 tools/jit-test/target/release/jit-test 20000 1 7 # AES, PMULL, SHA1
NO_AES=1 NO_PCLMUL=1 tools/jit-test/target/release/jit-test 20000 1 7 # optional-feature fallback
INTR=20 RELOC=1 tools/jit-test/target/release/jit-test 10000 1 9 # FP min/max and indexed multiply/FMA
INTR=20 RELOC=1 tools/jit-test/target/release/jit-test 10000 1 10 # TBL/TBX and byte/halfword ZIP/UZP
INTR=20 RELOC=1 tools/jit-test/target/release/jit-test 10000 1 11 # full FP catalog, exact status and native-path checks
INTR=10 RELOC=1 tools/jit-test/target/release/jit-test 30000 1 12 # FP control/status and libc/compiler SIMD
scripts/vm-smoke.sh                                            # in-kernel ABI suite etc.
```

`tests/bench/crypto.c` and `crypto.S` provide crypto instruction
microbenchmarks (including both PMULL widths and all SHA-1/SHA-256 operations).
Build and run the same binary on baseline and patched kernels, checking
its checksums against QEMU:

```sh
mkdir -p build
aarch64-linux-gnu-gcc -O2 -static -o build/crypto-bench tests/bench/crypto.c tests/bench/crypto.S
qemu-aarch64 build/crypto-bench 200000 1
KERNEL=/path/to/bzImage scripts/run-vm.sh 'build/crypto-bench 200000 3'
# Check fallback when optional host instructions are hidden from the VM:
KERNEL=/path/to/bzImage KEMU_CPU=host,-aes,-pclmulqdq scripts/run-vm.sh 'build/crypto-bench 1000 1'
```

The benchmark warms translations before timing, reports time per crypto
instruction including loop/operand overhead, and prints deterministic
checksums. It is not a complete cipher or hash throughput test.

`tests/bench/fp.c` exercises SAXPY, a double dot product, 48×48 matrix
multiplication, clamping, range counting, Mandelbrot, SIMD square roots,
quantization, and rounding. `tests/bench/zlib.c`
measures compression (level 6), decompression, Adler-32, and CRC-32 over
deterministic mixed text/random data, and verifies the compression round trip.
Both accept a case name (or `all`) and iteration count; zlib also accepts the
buffer size in bytes (up to its 1 MiB default).

```sh
aarch64-linux-gnu-gcc -O3 -fno-math-errno -static tests/bench/fp.c -lm -o build/fp.arm64
# ZLIB_ARM64 is an extracted arm64 zlib development package or sysroot.
aarch64-linux-gnu-gcc -O3 -static tests/bench/zlib.c -I$ZLIB_ARM64/usr/include \
  $ZLIB_ARM64/usr/lib/aarch64-linux-gnu/libz.a -o build/zlib.arm64
qemu-aarch64 build/fp.arm64 all 20
qemu-aarch64 build/zlib.arm64 all 2 131072
tools/kemu-user/target/release/kemu-user --jit build/fp.arm64 all 20
tools/kemu-user/target/release/kemu-user --jit build/zlib.arm64 all 2 131072
```

Use the same binaries on baseline and patched kernels and compare checksums
against QEMU. For a native comparison, compile the same sources with host GCC
and the same optimization level, linking the same zlib version, and run them
in the same VM. Compiler vectorization can differ across architectures.
Run helper profiling separately with `KEMU_JIT_STATS=1`; its per-helper
formatting and counters distort timings.

`tests/bench/libm.c` measures scalar libm calls, including the FPCR reads
and NEON bit selects used by glibc's `sin`, `cos`, and `atan`. Build with
`-O2 -static` and `-lm`; pass an optional iteration count (default one million).
For complete hash throughput use
`openssl speed -elapsed -seconds 2 -bytes 8192 sha256`.
Always use elapsed time: in-kernel emulation contributes to
system CPU time, which OpenSSL's default user-time measurement excludes.

`tests/bench/bun.mjs` reproduces the Bun JSON and gzip workloads. Each sample
runs 20 JSON parse/stringify round trips over 10,000 objects, or eight level-6
compressions of a deterministic 1 MiB buffer followed by decompression and
SHA-256 verification. It prints elapsed milliseconds and checksums after
untimed warmups; process startup is excluded. With the matching Bun binaries
and their libc loaders installed in the guest, run both architectures inside
the same QEMU/KVM VM, then repeat on the other kernel:

```sh
KERNEL=/path/to/bzImage scripts/run-vm.sh '
  /path/in/guest/bun-x64 tests/bench/bun.mjs json 7 3 native
  /path/in/guest/bun-arm64 tests/bench/bun.mjs json 7 3 kemu
  /path/in/guest/bun-x64 tests/bench/bun.mjs gzip 7 3 native
  /path/in/guest/bun-arm64 tests/bench/bun.mjs gzip 7 3 kemu
'
```

Use the same Bun release (tested with 1.4.4), repeat with reversed run order,
and compare medians and checksums. Keep helper profiling disabled for timings.

T1 lowers every currently decoded S/D FP instruction family: scalar and SIMD
arithmetic, comparisons (including conditional comparisons), rounding,
pairwise/across-lane reductions, integer/fixed-point conversions, precision
conversions, reciprocal estimates, and reciprocal refinement steps. Half
precision **storage conversions** are lowered; FP16 arithmetic is unsupported.
Packed signed int32 conversions stay packed on AVX2; 64-bit/unsigned conversion
forms use native scalar lanes and commit the vector once. Reciprocal estimates
use ARM's exact tables embedded in the translated block. Unusual inputs use
softfloat where host behavior differs: NaN propagation, FPCR.FZ/AHP,
saturation/modulo cases, and underflow/overflow boundaries. FCVTXN also uses the
helper outside its normal-result fast range. Thus instruction coverage does
not imply every input executes without a helper.

Mode 11 iterates the readable opcode catalog in `tools/jit-test/src/fp-catalog.txt`.
It checks all four rounding modes, scalar/vector arrangements, aliasing, exact
FPCR/FPSR/NZCV, exceptional inputs and inactive lanes. Ordinary-input cases
must execute without helper calls (apart from the terminating BRK). Run with
`NO_VCACHE=1` as well to check state-page and cached-vector paths.

Mode 12 also covers the integer NEON paths used by Bun's JSON parser and
zlib: CMTST, UMINV, SSHLL/USHLL, byte/halfword UQSUB, and 32/64-bit USHL.
It checks operand aliasing, inactive lanes, signed low-byte shift counts,
sticky FPSR.QC, and exact FPCR/FPSR/NZCV, allowing only the terminating BRK
to use an instruction helper.

`tests/jit-workloads/run.sh` runs JIT-heavy programs for Java, Node, LuaJIT,
PyPy and Ruby inside an arm64 userland, each with the guest's JIT on and off,
and compares the checksums with each other and with native x86_64 runs:

```sh
scripts/mkrootfs.sh full            # arm64 rootfs + runtimes, via qemu-user (~20 min)
scripts/vm-jit-stress.sh 2 2        # 2 rounds, then 2 concurrent copies
KEMU_APPEND=kemu.stress=50 scripts/vm-jit-stress.sh 1 2   # forced state recovery
```

CI (`.github/workflows/ci.yml`) runs the userspace tests. It also builds a
pristine v6.18 kernel with the patch set and boots it under KVM to run the
in-kernel tests, then runs `vm-jit-stress.sh` on that kernel. The arm64 rootfs
for that job is cached, keyed on `scripts/mkrootfs.sh`.

## License

GPL-2.0. See [LICENSE](LICENSE).
