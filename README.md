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
- A shared translation cache for file-backed code. Library code translated by
  one process is reused by the next one after re-validating it against the
  bytes in memory.
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

io_uring isn't offered to arm64 programs (the syscalls return `ENOSYS` and
libraries fall back to plain syscalls), because ring operations use native
struct layouts behind kemu's back.

Not done yet: a real vDSO, rseq, perf callchains through translated code, the
optimizing tier (T2), host-register allocation for NEON, the LSM hook and the
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
| `kemu.jitoff=<mask>` | turn off JIT features one at a time, for bisecting (1 helper for all non-branches, 2 helper for SIMD/FP, 4 one-insn blocks, 8 no chaining, 32 no register remapping) |
| `kemu.xcache=0` | disable the shared translation cache |
| `kemu.xcache_mb=<n>` | shared cache size limit (default 128) |
| `kemu.debug=1` | per-process translation statistics on exit |
| `kemu.stress=<n>` | debug: every n translations, interrupt all other threads of the process so their state is recovered mid-block |

## Testing

```sh
cargo test --manifest-path overlay/rust/kemu_core/Cargo.toml --features std
cargo run --release --manifest-path tools/jit-test/Cargo.toml -- 100000
INTR=50 RELOC=1 tools/jit-test/target/release/jit-test 50000   # async interrupts + relocation
scripts/vm-smoke.sh                                            # in-kernel ABI suite etc.
```

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
