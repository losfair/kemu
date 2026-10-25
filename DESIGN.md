# kemu — In-Kernel AArch64 User-Mode Emulation for x86_64 Linux

Status: **Design proposal** · Base: **Linux v6.18** · Host: **x86_64** · Guest: **AArch64 (EL0, LP64, little-endian)**

---

## 1. Summary

kemu lets an x86_64 Linux kernel run unmodified AArch64 Linux userspace binaries.
Running such a binary works like running a native one: `execve()` it, `ptrace()` it,
core-dump it, put it in a container, filter it with seccomp. kemu does this with a
dynamic binary translator that lives **inside the kernel**. It translates AArch64
code into x86_64 code, and that code runs **in ring 3** in the process's own address
space. The guest-facing kernel ABI (syscalls, signals, auxv, `/proc`, ptrace regsets)
is provided by the kernel itself, not by a userspace emulator pretending to be a
kernel.

Key decisions:

| Area | Decision |
|---|---|
| Where the translator runs | In the kernel, in the faulting/trapping task's own context |
| Where translated code runs | User mode (CPL3), in a kernel-owned, guest-read-only "code cache" mapping |
| Address space | Guest VA = host VA (identity). No software MMU, no address translation on loads and stores |
| Loading | A new in-kernel binfmt (`binfmt_kemu`) built from `fs/binfmt_elf.c` the same way `compat_binfmt_elf.c` is |
| Syscalls | A third syscall ABI next to native and IA32 compat, with arm64 numbers and arm64 layouts, dispatched to the existing kernel implementations |
| Signals and faults | Exact. The kernel rebuilds guest state from host state plus translator metadata and builds real arm64 signal frames |
| Language | Translator, optimizer, code generator and guest-state model in **Rust** (`kemu-core`, `no_std`, no kernel deps). A thin, auditable **C** layer for entry, mm and signal hooks |
| Performance | Two-tier JIT (fast baseline plus optimizing region compiler), static register pinning, lazy flags, call/return prediction, shared per-inode translation cache. One back end: x86-64-v3 (AVX2), no APX/AVX-512 paths |
| Distribution | Out-of-tree patch set against Linux v6.18. Not intended for upstream |
| Target | ≥ 80% of native x86_64 throughput (geomean, methodology in §13), ≥ 95% on syscall/IO-bound workloads |

---

## 2. Goals and non-goals

### 2.1 Goals

1. **Transparency.** An AArch64 ELF runs through plain `execve()` with no
   binfmt_misc registration, no interpreter binary inside the container, and no
   visible helper process. Inside the process:
   - `uname -m` reports `aarch64`. `/proc/cpuinfo` and `getauxval(AT_HWCAP)` describe an arm64 CPU.
   - `/proc/self/maps` shows only guest mappings. `/proc/self/exe` is the guest binary.
   - Signals arrive with arm64 `ucontext_t`/`sigcontext`, and faults report exact guest PCs and addresses.
   - An aarch64 `gdb`/`strace` (itself emulated) or a native x86_64 `gdb-multiarch`/`strace` can trace the process and sees arm64 registers and arm64 syscall numbers.
   - Core dumps are valid `EM_AARCH64` ELF cores.
   - seccomp, audit and syscall tracepoints see `AUDIT_ARCH_AARCH64` with arm64 numbers.
2. **Correctness.** Architecturally faithful AArch64 EL0 semantics for everything we
   advertise in HWCAPs. Anything not advertised either works or raises `SIGILL`
   exactly as an arm64 kernel on hardware without that feature would.
3. **Memory safety.** Every part of kemu that parses or transforms
   attacker-controlled input (guest instructions, guest memory, guest-written
   structures) is safe Rust. C is limited to glue with no parsing logic.
4. **Performance.** ≥ 80% of native x86_64 performance for CPU-bound code compiled
   from the same source (§13), and near-native for syscall-heavy code.
5. **Robustness.** A misbehaving or hostile guest can at worst crash itself. It can
   never panic, deadlock, or corrupt the kernel. Translator memory and CPU use is
   bounded and charged to the guest's cgroup.

### 2.2 Non-goals (v1)

- AArch32/Thumb (EL0 32-bit), big-endian AArch64, ILP32.
- SVE/SVE2/SME, MTE, pointer authentication, and BTI enforcement. PAC/BTI
  instructions live in HINT space and execute as NOPs, which is architecturally
  correct when the feature isn't advertised.
- System-mode emulation, arm64 kernel modules, arm64 KVM.
- Calling host x86_64 libraries from guest code ("thunking", as in FEX/box64).
  Possible later (§16), but it breaks transparency and is out of scope.
- Hosts without x86-64-v3 (AVX2, BMI1/2, FMA, LZCNT, MOVBE) plus AES-NI and PCLMULQDQ.
- APX and AVX-512/AVX10 back ends. kemu generates only VEX-encoded x86-64-v3 code,
  so there is one register model, one encoder, and one performance profile to
  validate. Hosts with APX or AVX-512 run the same code.
- Upstream submission. kemu is maintained as an out-of-tree patch set (§5.6).

---

## 3. Why in the kernel?

Userspace emulators (qemu-user, FEX-Emu, box64) work, but they have structural
limits that kemu is designed to remove:

| Problem in userspace emulators | kemu |
|---|---|
| Need binfmt_misc plus an interpreter visible in every mount namespace (`F` flag workarounds, container breakage) | Kernel-intrinsic binfmt. Nothing has to exist in the container except the guest's own files |
| `/proc/self/exe`, `/proc/self/maps`, `ptrace`, core dumps show the emulator, not the program | The kernel shows guest views by construction |
| Syscalls are reimplemented in userspace, then re-issued as host syscalls. Layout translation is duplicated and drifts | One dispatch layer in the kernel reuses the real implementations, including the asm-generic layouts the kernel already has |
| Signals are emulated with host signal handlers, so async delivery needs heuristics or polling, and faults inside the emulator are confusing | The kernel delivers signals itself and rebuilds exact guest state from metadata |
| seccomp/audit see x86 syscalls from the emulator, not the guest's arm64 syscalls | Filters see the guest ABI, the same way IA32 compat tasks see `AUDIT_ARCH_I386` |
| Code cache and emulator state are writable by the guest (same address space, same permissions) | Code cache, lookup tables and metadata are read-only to the guest. Only the kernel writes them |
| Extra transitions (guest → emulator → kernel) | Translated code traps straight into the kernel's kemu syscall path |

**Cost:** a JIT in the kernel is a large new attack surface. §12 explains how we
contain it: a Rust core with no unsafe code in the translation path, a code-cache
verifier, bounded resources, fuzzing and differential testing. The kernel's
precedent is eBPF, which also turns untrusted input into machine code. kemu's output
runs in **user mode**, which is a much weaker position than eBPF's ring 0, so a
translator bug cannot directly become kernel code execution.

### 3.1 Alternatives considered

- **Pure userspace translator plus a small kernel helper** (binfmt plus a privileged
  code-cache syscall). This fixes code-cache integrity but still emulates signals,
  ptrace and `/proc` in userspace. We rejected it because most of the transparency
  work ends up in the kernel anyway.
- **Interpreter only.** Simple, but 10–50× slower. It stays useful as a debug and
  reference mode (`kemu.mode=interp`, §14), not as the main engine.
- **Ahead-of-time whole-binary translation.** It can't handle JITs, `dlopen`, or
  indirect branches without a runtime anyway. We include it only as an optional,
  persistent cache that feeds the JIT (§10.4).

---

## 4. Architecture overview

```
                      ┌───────────────────── user mode (CPL3), one process ─────────────────────┐
                      │                                                                          │
   guest memory       │  .text/.data/heap/stack/mmaps of the AArch64 program (host NX on .text)   │
   (identity mapped)  │                                                                          │
                      │  ┌──────────── kemu region (VM_KEMU, hidden from guest) ──────────────┐  │
                      │  │ code cache (R-X)  │ lookup table (R--) │ stubs (R-X) │ per-thread  │  │
                      │  │ translated blocks │ guest PC → host PC │ dispatcher  │ CPU state   │  │
                      │  │                   │                    │ helpers     │ (RW, %gs)   │  │
                      │  └───────────────────┴────────────────────┴─────────────┴─────────────┘  │
                      └───────────────┬───────────────────────────────▲─────────────────────────┘
                     syscall (svc /   │ page fault, #UD, IRQ,          │ sysret / iret to
                     translate miss)  │ timer, IPI                     │ (possibly new) host PC
                      ┌───────────────▼───────────────────────────────┴─────────────────────────┐
                      │                    kernel (x86_64, Linux 6.18 + kemu)                     │
                      │                                                                           │
                      │  C glue (kernel/kemu/, arch/x86/kemu/)                                    │
                      │   entry hooks · binfmt_kemu · signal frames · ptrace regsets · /proc ·     │
                      │   mm hooks · rseq fixup · perf callchains · seccomp/audit arch            │
                      │                         │  narrow FFI (kemu_ffi.h / bindgen)              │
                      │  Rust (rust/kemu_core + kernel/kemu/rust)                                 │
                      │   decoder · IR · T1 baseline JIT · T2 region optimizer · x86 encoder ·     │
                      │   code-cache manager · state reconstruction · syscall marshalling ·        │
                      │   verifier · invalidation/epochs                                           │
                      └───────────────────────────────────────────────────────────────────────────┘
```

Lifecycle of a guest instruction:

1. `execve()` → `binfmt_kemu` maps the ELF and interpreter, builds an arm64 auxv
   and stack, creates the kemu region, and sets `regs->ip` to the dispatcher and
   the guest PC to the entry point.
2. The dispatcher looks up the guest PC in the lookup table. On a miss it executes
   `syscall` with `rax = KEMU_SYS_TRANSLATE`.
3. The kernel's kemu entry path calls the Rust translator. It reads guest code from
   user memory, translates it, writes the result into the code cache, links it, and
   returns to user mode at the new host PC.
4. Translated code runs at native speed. Direct branches are chained, indirect
   branches go through inline caches and the lookup table, and returns use a host
   return stack.
5. An AArch64 `svc #0` becomes `syscall` with `rax = KEMU_SYS_SVC`. The kernel runs
   the guest syscall and returns into translated code.
6. A page fault or other trap at a code-cache address is mapped back to a guest PC
   and an exact guest register state, then delivered as an arm64 signal.

---

## 5. Kernel integration (C layer)

All core-kernel changes are small hooks guarded by `CONFIG_KEMU` and a static key
(`kemu_enabled_key`), so they cost nothing when kemu is unused. kemu is built in
(`bool`, not tristate) because it hooks entry and mm code, which rules out a loadable
module. It ships as a kernel patch set (§5.6). It can be turned off at
runtime with `/proc/sys/kernel/kemu/enabled` (new execs only).

### 5.1 Source layout

```
kernel/kemu/                C: generic glue
  binfmt_kemu.c             #include "../../fs/binfmt_elf.c" with arm64 overrides (compat_binfmt_elf.c pattern)
  syscall.c                 kemu syscall entry, seccomp/ptrace/audit integration, dispatch table
  syscall_tbl.c             generated from scripts/syscall.tbl (arm64 ABI selectors)
  abi/                      per-syscall layout translators (stat, epoll, clone, sigaction, ...)
  signal.c                  arm64 rt_sigframe build / rt_sigreturn
  ptrace.c                  arm64 user_regset_view for kemu tasks
  proc.c                    /proc/cpuinfo, maps filtering, auxv, stat fields
  mm.c                      kemu region VMAs, VMA lifecycle hooks, code-cache page writes
  vdso/                     aarch64 vDSO image (prebuilt blob + reproducible build script)
  rust/                     kernel-facing Rust crate (bindings, allocation, locking)
arch/x86/kemu/
  entry.c                   x86 entry glue, exit-to-user fixups, FSGSBASE setup
  stubs.S                   template for user-mode dispatcher and helper stubs
rust/kemu_core/             no_std Rust crate, no kernel dependencies (also built by cargo for tests)
tools/testing/selftests/kemu/
tools/kemu/                 decoder generator, differential tester, fuzz harnesses, kemu-stat
Documentation/admin-guide/kemu.rst
```

### 5.2 Task state

`struct task_struct` gets a `struct kemu_thread *kemu` pointer (NULL for native
tasks). `struct mm_struct` gets a `struct kemu_mm *kemu`. A task is a kemu task
when `TIF_KEMU` is set (thread flag, checked cheaply on entry and exit) and
`SYSCALL_WORK_KEMU` routes it to the kemu syscall path, the same way
`SYSCALL_WORK_SYSCALL_USER_DISPATCH` routes Syscall User Dispatch.

`kemu_thread` (kernel-only, Rust-owned via an opaque handle) holds:
- a pointer to the thread's **user-mapped CPU state page** (§6.3) plus the kernel
  alias of the same page,
- the host return-stack region bounds,
- the acknowledged invalidation epoch, single-step/trace mode, and `orig_x0` for
  syscall restart.

`kemu_mm` holds the code cache, the lookup table, block metadata, the
translated-page index, the epoch counter, statistics, and limits.

### 5.3 Binary loading: `binfmt_kemu`

Built like `fs/compat_binfmt_elf.c`, by re-including `fs/binfmt_elf.c` with macro
overrides:

| Macro | kemu value |
|---|---|
| `elf_check_arch` | `e_machine == EM_AARCH64 && EI_CLASS == ELFCLASS64 && EI_DATA == ELFDATA2LSB` |
| `ELF_PLATFORM` | `"aarch64"` |
| `ELF_HWCAP`, `ELF_HWCAP2`, `ELF_HWCAP3` | kemu's advertised feature set (§8.6) |
| `ARCH_DLINFO` | `AT_SYSINFO_EHDR` = kemu aarch64 vDSO; `AT_MINSIGSTKSZ` = arm64 value |
| `ELF_EXEC_PAGESIZE` | 4096 (AT_PAGESZ). arm64 binaries linked with 64K max-page-size load fine because segment alignment above page size is legal |
| `START_THREAD` | `kemu_start_thread()`: create the kemu region, set guest PC/SP, point `regs->ip` at the dispatcher |
| `SET_PERSONALITY` | set `TIF_KEMU`, `SYSCALL_WORK_KEMU`, utsname machine override |
| `ELF_CORE_COPY_REGS` / regset view | arm64 `user_pt_regs` / `user_fpsimd_state` built from reconstructed guest state |
| `arch_elf_adjust_prot` | strip host executability from guest mappings (§6.1) |

`PT_INTERP` (e.g. `/lib/ld-linux-aarch64.so.1`) resolves in the caller's mount
namespace like any other path. Multiarch distributions and arm64 container images
work unchanged. An optional fallback prefix
(`/proc/sys/kernel/kemu/interp_prefix`, per user namespace) is tried only if the
interpreter isn't found, similar to `qemu -L`.

`binfmt_kemu` registers after `binfmt_elf`, which already rejects `EM_AARCH64`, so
native exec performance is untouched.

Exec in either direction just works: a kemu task that execs an x86_64 binary
becomes native (the kemu state is dropped with the old mm), and vice versa.

### 5.4 Entry and exit

**Syscall entry.** In `do_syscall_64()` (generic entry), tasks with
`SYSCALL_WORK_KEMU` go to `kemu_syscall(regs)`. `rax` is interpreted as a **kemu
operation**, never as an x86_64 syscall number:

| `rax` | Operation |
|---|---|
| `KEMU_SYS_SVC` | guest `svc #0`: guest syscall, args read from the CPU state page |
| `KEMU_SYS_TRANSLATE` | lookup miss: translate the guest PC in `rdi` (or the CPU state) and return to its host PC |
| `KEMU_SYS_HELPER` | rare slow paths: exclusive monitor fallback, unsupported-op `SIGILL`, `IC IVAU`, ISB with pending invalidation, `MRS` of emulated ID registers |
| anything else | `SIGSYS`/`SIGKILL` (cannot happen from correct translated code) |

Because every `syscall` from a kemu task is interpreted this way regardless of RIP,
even a guest that somehow ran arbitrary x86 code (§12.3) can only make the syscalls
an arm64 guest could make, and only through seccomp in the guest ABI. For kemu
tasks, `int $0x80`, `sysenter`, and the legacy vsyscall page raise `SIGSYS`, which
closes the IA32 side door.

**Exit to user.** In `exit_to_user_mode_prepare()`, kemu tasks run
`kemu_exit_fixup()` when `TIF_KEMU_FIXUP` is set. That bit is set whenever the guest
PC changed in the kernel (signal delivery, `rt_sigreturn`, ptrace `SETREGSET`,
rseq abort) or the thread's invalidation epoch is stale. The fixup:
- maps the guest PC to a host PC (or the dispatcher),
- rewrites stale host addresses in `regs->ip` and on the host return stack (§9.4),
- reloads statically pinned guest registers into the host registers in `pt_regs`.

**Page faults, #UD, #GP, #DE, #AC in user mode with a code-cache RIP.** The
normal handlers run first (demand paging, COW, userfaultfd, NUMA hinting all work
untouched). Only when the kernel would raise a signal does it call
`kemu_force_sig_fault()`, which reconstructs guest state (§9.3) and queues an arm64
signal with the guest PC, guest `si_addr`, and an arm64 `ESR` value in the
`esr_context` record.

### 5.5 Context switch

Guest state lives in host GPRs, XMM/YMM registers, MXCSR, and the user GS base, all
of which the x86 context switch already saves (XSAVE plus FSGSBASE). **kemu adds
nothing to the context-switch path.**

### 5.6 Out-of-tree patch set

kemu is maintained as an out-of-tree patch set against **Linux v6.18**, tracking the
6.18 stable branch. We don't plan to submit it upstream, so the design is optimized
for cheap rebases rather than for upstream review:

- **New files over edits.** Almost all code lives in new directories
  (`kernel/kemu/`, `arch/x86/kemu/`, `rust/kemu_core/`, selftests, tools). Changes
  to existing files are limited to the hook call sites listed below. Each is a
  one-to-three-line call into kemu behind `CONFIG_KEMU` plus a static key.
- **Hook inventory** (the only touched core files): generic entry
  (`kernel/entry/common.c`, `include/linux/entry-common.h`, the `SYSCALL_WORK_KEMU`
  bit), x86 entry and signal (`arch/x86/entry/syscall_64.c`,
  `arch/x86/kernel/signal.c`, `arch/x86/include/asm/syscall.h`, the trap and fault
  handlers in `arch/x86/kernel/traps.c` and `arch/x86/mm/fault.c`), mm
  (`mm/vma.c`, `mm/mprotect.c`, `mm/mremap.c`, `mm/memory.c` for
  `access_process_vm`, `vm_get_page_prot`), `fs/exec.c` and `fs/binfmt_elf.c`
  (re-include points), `fs/proc/` (maps, cpuinfo, stat, auxv), `kernel/rseq.c`,
  `kernel/ptrace.c` regset view selection, `kernel/events/` callchain,
  `include/linux/sched.h` and `mm_types.h` (two pointers), Kconfig and Makefiles.
- **Patch series layout.** One patch per hook area, then the self-contained kemu
  directories, so a rebase conflict is confined to a small, obvious patch.
- **Rust bindings are carried in the series.** The mm/VMA, `task_work`, signal and
  regset abstractions kemu needs beyond the 6.18 `kernel` crate live in
  `kernel/kemu/rust/`, not in `rust/kernel/`, so they never conflict with upstream
  Rust-for-Linux changes.
- **CI** builds and runs the selftests on every 6.18.y stable release, and runs the
  conformance and performance suites (§15, §13) on each rebase.

---

## 6. Address space and memory model

### 6.1 Identity mapping

Guest virtual addresses are host virtual addresses. A guest `LDR x0, [x1]` becomes
`mov rax, [rcx]` with no bounds check and no software TLB. This is the biggest
single performance advantage over full-system emulators.

- **VA width.** x86_64 user space is 47 bits with 4-level paging. arm64 Linux user
  space is usually 48 bits, but mmap hands out addresses below 2^47 unless asked
  otherwise, and portable software can't assume more. With 5-level paging the
  existing `mmap` hint rules apply as they do natively.
- **Page size.** The guest sees 4 KiB pages (`AT_PAGESZ`, `sysconf`). Binaries that
  require 16K/64K *runtime* pages (rare, mostly Apple-silicon-specific builds) are
  unsupported.
- **Host NX on guest code.** Guest code never runs natively. For kemu mms,
  `vm_get_page_prot()` drops host executability for every guest VMA while keeping
  `VM_EXEC` as the semantic flag (used by the translator, `/proc/maps`, and
  mprotect). The only host-executable pages in a kemu process are the kemu region's
  code and stub pages.
- **Execute-only mappings** (`PROT_EXEC` without `PROT_READ`) behave as R+X. x86
  can't express EL0 XOM, and arm64 Linux doesn't currently provide XOM to EL0
  either.
- **Top-byte-ignore (TBI).** arm64 hardware ignores address bits 63:56 for EL0 data
  accesses. Most glibc programs never set them, so the default translation does no
  masking. kemu switches a process to **tagged mode** when any of these happen:
  `prctl(PR_SET_TAGGED_ADDR_CTRL)`, an ELF note or Android ABI marker, or a
  non-canonical-address #GP from translated code. In tagged mode, translated memory
  accesses mask the tag: one `and`/`andn` per address with a scratch register,
  folded into the address computation by T2, or free in hardware via Intel LAM_U57
  / AMD UAI where the tag bits fit. The #GP path reconstructs state, flushes the
  process's translations, and retries the instruction in tagged mode. This keeps
  untagged programs at zero cost and tagged programs correct.

### 6.2 The kemu region

At exec, kemu reserves one contiguous range near the top of the user address space
(below the stack gap, randomized within a window). The range contains:

| Part | Host perms | Kernel writes via | Purpose |
|---|---|---|---|
| Code cache | R-X | `FOLL_FORCE` page writes (the uprobes/ptrace-poke path) | Translated blocks |
| Stubs | R-X | written at creation | Dispatcher, lookup-miss trampoline, return-miss handler, FP fixup helpers |
| Lookup table | R-- | same as code cache | Open-addressed guest PC → host PC hash |
| Per-thread CPU state | RW- | kernel alias (vmap) | Guest register spill area, NZCV, FPCR/FPSR, TPIDR_EL0, host return stack |

The region's VMAs carry `VM_KEMU | VM_DONTEXPAND | VM_MIXEDMAP`-style protections.
In the guest-visible API:
- They don't appear in `/proc/<pid>/maps`, `smaps`, `numa_maps`, or `pagemap`
  for readers without `CAP_SYS_PTRACE` over the target plus
  `/proc/sys/kernel/kemu/show_region=1`. Debug views live in
  `/proc/<pid>/kemu/{maps,stats}`.
- `mmap(MAP_FIXED)`, `mremap`, `munmap`, `mprotect`, `madvise(MADV_DONTNEED)`,
  `mseal` and `process_vm_writev` that touch them fail with `ENOMEM`/`EINVAL`,
  as if the range were unmappable. Non-fixed mmap never chooses addresses there,
  because the region sits in the reserved gap.
- Guest stores into code-cache or lookup pages fault (read-only PTEs) and become an
  ordinary guest `SIGSEGV`.

All region memory is accounted to the process's memcg (`__GFP_ACCOUNT`) and limited
by `kemu.max_cache_mb` (default 256 MiB per mm, shrinkable).

**Fork.** Region pages are ordinary anonymous private pages, so `fork()` copies them
with normal COW. After fork, the child's guest addresses and memory are identical to
the parent's, so every translation stays valid. The kernel writes cache pages through
the `FOLL_FORCE` path, which breaks COW correctly. Kernel-side metadata is split into
immutable chunks shared through refcounting (`Arc`), so cloning it at fork is O(number
of chunks), not O(cache size). `vfork`/`CLONE_VM` share everything, as you'd expect.

### 6.3 Per-thread CPU state page and `%gs`

Each guest thread has one CPU state page, user RW and kernel-aliased. The user
**GS base** points at it (set by the kernel; Linux enables FSGSBASE since 5.9 and
saves the user GS base on context switch). Translated code addresses unpinned guest
registers as `gs:[off]`, which frees every host GPR except `rsp` for guest use (§8.1).
FS is unused by kemu and left alone. Guest TLS is `TPIDR_EL0`, which is just a field
in the page.

The guest can find and scribble on this page with ordinary stores. That's acceptable:
it only contains state the guest owns anyway (its own registers) plus host return-stack
hints, which are always verified before use (§9.2). The kernel treats everything in
the page as untrusted input and reads each field once with `READ_ONCE`.

### 6.4 Memory ordering

AArch64 is weakly ordered (other-multi-copy-atomic). x86 is TSO, which is strictly
stronger. **Plain AArch64 loads and stores map to plain x86 moves with no fences.**
This is the "easy direction", unlike x86-on-ARM emulators, which need hardware TSO
modes or fences everywhere.

The only AArch64 orderings x86 doesn't give for free are store→load:

| AArch64 | x86 translation |
|---|---|
| `LDR`/`STR`/`LDP`/`STP` | `mov` |
| `LDAR`, `LDAPR`, `LDAXR` | `mov` (x86 loads already have acquire semantics) |
| `STLR` | `xchg` (implicit `lock`; makes STLR→LDAR RCsc as AArch64 requires) |
| `DMB ISHLD`, `DMB ISHST`, `DMB OSH*LD/ST` | nothing (compiler-barrier only in the IR) |
| `DMB ISH`, `DMB SY`, `DSB *` | `lock or qword [rsp], 0`, which is cheaper than `mfence` and enough for WB memory |
| `ISB` | nothing (context sync handled by invalidation protocol, §10.3) |
| LSE `CAS*`, `CASP*` | `lock cmpxchg`, `lock cmpxchg16b` |
| LSE `SWP*` | `xchg` |
| LSE `LDADD*`, `LDCLR*`, `LDEOR*`, `LDSET*` | `lock xadd` / `lock cmpxchg` loop for clr/eor/set when the old value is used, `lock and/xor/or` when it's discarded (`ST*` aliases) |
| `LDSMAX*`/`LDUMAX*` etc. | `lock cmpxchg` loop |

**Exclusives (`LDXR`/`STXR`, `LDAXP`/`STLXP`).** The per-thread monitor state
(address, size, observed value) lives in the CPU state page. `STXR` becomes
`lock cmpxchg` against the value seen by `LDXR` (`cmpxchg16b` for pairs). This
allows ABA, which the architecture forbids, but it's the standard technique and is
safe for every lock/RCU/refcount idiom generated by mainstream compilers. Clearing the
monitor (`CLREX`, exceptions, context switch) is modeled by invalidating the local
monitor. A **strict monitor mode** (per process, `prctl` or sysctl) makes exclusive
regions single-step through a page-write-protect protocol for workloads that need
exact semantics. We advertise LSE (`HWCAP_ATOMICS`), so glibc, libstdc++, and Rust
pick LSE paths through outline-atomics or ifuncs, which keeps LL/SC rare.

---

## 7. Rust core (`kemu-core`)

### 7.1 Structure

```
rust/kemu_core/src/
  lib.rs            #![no_std], #![forbid(unsafe_code)] except in `encoder::emit` (audited, tiny)
  decode/           AArch64 A64 decoder, generated from Arm's machine-readable ISA spec
  ir/               typed SSA IR (value numbering, block params, effects)
  frontend/         A64 → IR lifting (one function per instruction class)
  t1/               baseline translator: IR-light, linear, block-local
  t2/               region optimizer: CFG/loop discovery, SSA opts, global regalloc
  backend/x86/      x86_64 encoder (legacy + VEX, x86-64-v3 only), instruction selection
  regmap/           static guest-register pinning profiles
  meta/             host-PC → guest-state recovery tables (compressed)
  verify/           code-cache verifier (§12.2)
  state/            guest architectural state model, NZCV/FPCR/FPSR semantics
  interp/           reference interpreter (debug mode and differential oracle)
  sysabi/           syscall argument/structure marshalling (pure functions over byte slices)
```

`kemu-core` doesn't depend on the kernel crate. All interaction goes through a
trait the kernel side implements:

```rust
pub trait Env {
    /// Read guest instruction bytes. May fail (fault) — never panics.
    fn read_code(&mut self, guest_pc: u64, buf: &mut [u32]) -> Result<usize, Fault>;
    /// Is [pc, pc+len) inside a guest VM_EXEC mapping, and which generation?
    fn exec_region(&self, guest_pc: u64) -> Option<ExecRegion>;
    fn host_features(&self) -> &HostFeatures;
    fn should_yield(&self) -> bool;            // cond_resched hook / time budget
}
```

The same source builds as an ordinary Rust crate with `cargo` for unit tests, fuzzing
(cargo-fuzz/libFuzzer), differential testing, and a userspace benchmark harness that
runs translated code in a ptrace'd sandbox. Kernel-specific code (allocation,
locking, page writes, FFI) lives in `kernel/kemu/rust/`, which uses the 6.18
`kernel` crate (`KBox`, `KVec`, `Arc`, `Mutex`, `SpinLock`, `Opaque`, task/mm
abstractions) and carries its own bindings where they're missing (§5.6).

### 7.2 Safety rules

- `#![forbid(unsafe_code)]` everywhere in `kemu-core` except the encoder's final
  copy into an output buffer. `kernel/kemu/rust` has `unsafe` only at FFI
  boundaries, each with a `// SAFETY:` comment, as kernel Rust requires.
- **No panics.** `clippy::{panic, unwrap_used, expect_used, indexing_slicing,
  arithmetic_side_effects}` are `deny`. Arithmetic is checked or explicitly
  wrapping. A kernel-side panic would be a `BUG()`, so it's treated as a security
  bug.
- **No allocation during translation.** Each translation runs in a per-thread
  **bounded arena** reserved up front (T1: 64 KiB, T2: 1 MiB). Limits on guest
  instructions per block (T1: 128, T2 region: 4096) make every intermediate bounded.
  Running out of arena ends the block early, which is always legal. This sidesteps
  fallible-allocation plumbing inside the optimizer and makes worst-case memory use
  provable.
- **Bounded time.** T2 passes are worklist algorithms with explicit fuel. The
  translator polls `Env::should_yield()` between passes. T2 can be preempted and
  resumed (§10.2).
- **Errors are guest events.** An undecodable or unsupported instruction translates
  to a trap stub that raises `SIGILL` with the right guest PC. A translator-internal
  invariant failure falls back to T1, then to the interpreter for that block. It's
  counted and logged once (ratelimited), and never crashes the kernel.

### 7.3 Decoder

The decoder is generated from Arm's machine-readable A64 specification into a
decision tree of `match` on bitfields (no table indexed by unmasked guest data, so
no Spectre-v1 gadget). The generator lives in `tools/kemu/gen-decoder`. Generated
Rust is committed, so the kernel build needs no generator toolchain. It's validated
exhaustively over the 2^32 encoding space against LLVM's disassembler in CI.

---

## 8. Translation

### 8.1 Register mapping

AArch64 has 31 GPRs plus SP and 32 × 128-bit vector registers. x86_64 has 16 GPRs
(only 15 usable, since `rsp` is the host return stack) and, with AVX2, 16 vector
registers. kemu deliberately doesn't use APX or AVX-512 (§2.2), so this is the only
register file it targets. Spilling is the biggest structural cost of this emulation direction, so
kemu pins guest registers statically at block boundaries (the "canonical map") and
lets T2 reallocate freely inside regions.

**Baseline host (x86-64-v3), GPRs.** 13 pinned guest registers plus 2 scratch:

| Host | Guest | Rationale |
|---|---|---|
| `rbx` | SP | every function |
| `rbp` | X29 (FP) | frame accesses |
| `rsi` | X30 (LR) | every call/return |
| `rdi`,`rcx`,`r8`,`r9`,`r10`,`r11` | X0–X5 | AAPCS args/results, hottest by profile |
| `r12`,`r13`,`r14` | X19–X21 | most-used callee-saved |
| `r15` | X9 | most-used temporary in GCC/LLVM output |
| `rax`,`rdx` | scratch | `lahf`, `div`/`mul`, address temporaries |
| `rsp` | host return stack | call/ret prediction (§9.2) |
| others | `gs:[…]` | spilled; T2 promotes them inside hot regions |

BMI2 (`shlx`/`sarx`/`shrx`/`rorx`/`mulx`/`andn`) means variable shifts and wide
multiplies need no fixed registers. The mapping is a translator *profile*. kemu can
pick a different profile per process from a cheap static histogram of register use
in the main executable's `.text`.

**Living with 15 registers.** Without APX, register pressure has to be handled
in the translator:
- **Memory operands instead of reloads.** A spilled guest register is used
  directly as an x86 memory operand (`add rdi, gs:[x22]`, `cmp gs:[x23], rcx`).
  On current cores that's a micro-fused load+op that hits L1, so a read of a spilled
  register costs about one extra cycle of latency, not an extra instruction.
- **Per-region maps.** T2 chooses its own register assignment for each hot region
  and only converts to the canonical map on region exits. Most hot loops in
  compiled AArch64 code touch fewer than 13 GPRs.
- **Profile-guided canonical maps.** The canonical map is chosen per binary from
  observed register use (persisted in the per-inode cache, §10.4), instead of the
  fixed default above.
- **Spill hoisting.** Fills and spills of guest registers that aren't live-through
  a loop are moved to the loop's preheader and exits.

**Vector registers.** V0–V13 are pinned to `xmm0–xmm13`, with `xmm14`/`xmm15` as
scratch. V14–V31 live in `gs:[…]`. That's a good fit for AAPCS code, where V16–V31
are short-lived temporaries T2 can allocate inside regions. Upper YMM halves are kept
clean (VEX encoding everywhere, no legacy SSE), so there are no transition penalties
and no `vzeroupper`.

### 8.2 Flags (NZCV)

| AArch64 | x86 |
|---|---|
| N | SF |
| Z | ZF |
| C | CF after add; **¬CF** after sub/cmp (AArch64 C = NOT borrow) |
| V | OF |

- The translator tracks carry polarity statically. Conditional branches and
  `CSEL`/`CSET`/`CCMP` choose x86 conditions accordingly (`b.hs` after `cmp`
  → `jae`, after `adds` → `jc`).
- Flag liveness is computed per block (T1) and per region (T2). Most flag-setting
  instructions are immediately consumed or dead, so nothing is materialized.
- When flags are live across a block exit, they're saved compactly with
  `lahf` + `seto` into `gs:[nzcv_x86]` with a polarity bit, and restored with the
  `add al, 0x7f; sahf` idiom. Converting to architectural NZCV (`MRS NZCV`,
  signal frames, ptrace) happens only on demand in the kernel or a stub.
- `CCMP`/`CCMN` become `jcc`-free sequences using `cmov` on precomputed flag
  images, or a branch in T2 when profitable. `ADC`/`SBC` reuse CF directly,
  inverting with `cmc` when polarity needs it.
- T2 schedules flag-clobbering x86 instructions (most ALU ops) away from live
  AArch64 flags, using flag-neutral forms (`lea`, `mov`, BMI2 `shlx`/`rorx`/`andn`,
  `mulx`) where it can, so flags rarely need saving inside a region.

### 8.3 Memory accesses

AArch64 addressing modes map onto x86 SIB:

| AArch64 | x86 |
|---|---|
| `[Xn, #imm]` | `[rn + disp32]` |
| `[Xn, Xm, LSL #s]` (s ≤ 3) | `[rn + rm*2^s]` |
| `[Xn, Wm, UXTW #s]` | `mov e_tmp, wm` (zero-ext) → `[rn + tmp*2^s]` (T2 reuses known-zero-extended values) |
| `[Xn, Wm, SXTW #s]` | `movsxd` → SIB |
| pre/post-index writeback | access + `lea`/`add` on base (after the access, so a fault leaves the base unchanged, §9.3) |
| `LDP`/`STP` X | two `mov` |
| `LDP`/`STP` Q | two `vmovdqu` |
| `LDR`/`STR` Wt | 32-bit `mov` (implicit zero-extend matches AArch64) |
| `LDRSW`/`LDRSB`/`LDRSH` | `movsxd`/`movsx` |
| `DC ZVA` | align the address down to 64 B, then two 32-byte `vmovdqu` zero stores (one 64-byte block, as advertised in `DCZID_EL0`) |
| `PRFM` | `prefetcht0/t1/t2/nta`, or `prefetchw` for PST |

Unaligned accesses are legal on both sides. Unaligned exclusives fault on AArch64,
so kemu checks alignment on the LDXR path and raises `SIGBUS` (`BUS_ADRALN`).

### 8.4 Control flow

- **Direct branches** (`B`, `B.cond`, `CBZ`, `TBZ`) → `jmp`/`jcc rel32` to the target
  block once it's translated, otherwise to a per-exit stub that requests translation
  and then **patches** the branch (block chaining). Patch sites are 4-byte aligned
  displacement fields written with a single store, so concurrent executors see either
  the old or the new valid target.
- **Calls** (`BL`) → `mov rsi, <ret_pc>` then `call <target>`. The host return
  address points at the landing pad that continues the block at `ret_pc`.
- **Returns** (`RET`) → `mov rax, rsi` (or the `RET Xn` register) then `ret`. Every
  landing pad starts with `cmp rax, <its ret_pc>; jne ret_miss`. So host return
  prediction (the CPU's RSB) does all the work in the common case, and correctness
  never depends on it (§9.2).
- **Indirect branches** (`BR`, `BLR`) → per-site inline cache (1–2 entries,
  compare plus direct `jmp`), then an inline probe of the global lookup table
  (`hash = (pc >> 2) & mask`, 16-byte entries `{guest_pc, host_pc}`), then the
  dispatcher. `BLR` additionally does the call protocol so the callee's `RET` is
  predicted.
- **`SVC #0`** → spill live pinned registers needed for args (X0–X5, X8) to their
  canonical CPU-state slots, then `mov eax, KEMU_SYS_SVC; syscall`, then reload
  X0. The syscall instruction's `rcx`/`r11` clobbers are modeled as clobbers in the
  register allocator.
- **`BRK`** → trap stub that raises `SIGTRAP` (`TRAP_BRKPT`), which is what
  debuggers rely on. **`UDF`** → `SIGILL`. **`HLT`/`HVC`/`SMC`** → `SIGILL`.

### 8.5 SIMD and floating point

NEON maps mostly 1:1 onto SSE4.2/AVX2. Notable cases:

| AArch64 | x86 |
|---|---|
| `TBL`/`TBX` (1–4 regs) | `vpshufb` per table register with range fix-ups (`vpcmpgtb` + `vpblendvb`) |
| `ZIP`/`UZP`/`TRN`/`EXT` | `vpunpck*`, `vpshufd`, `vpshufb`, `vpalignr` |
| `XTN`/`SQXTN`/`UQXTN` | `vpshufb` / `vpackss*`/`vpackus*` (with sign fixups) |
| `UADDLV`, `ADDV` | `vpsadbw` / horizontal shuffles |
| `CNT` | `vpshufb` nibble lookup table |
| `SDOT`/`UDOT` | `vpmaddubsw`/`vpmaddwd` sequences with sign correction |
| `FMLA` | `vfmadd231ps/pd` (fused, matches AArch64) |
| `AESE`+`AESMC` pair | `vpxor x,k` + `vaesenc x, zero` (fused by peephole; standalone `AESMC` via `aesdeclast`/`aesenc` identities) |
| `PMULL`/`PMULL2` | `vpclmulqdq` |
| `CRC32C*` | `crc32` (x86 implements CRC32C) |
| `CRC32*` (IEEE poly) | `vpclmulqdq` folding (Barrett reduction); 4–6 µops |
| `SHA1*`/`SHA256*` | SHA-NI where operation boundaries line up, else AVX2 sequences |
| `RNDR`/`RNDRRS` | `rdrand`/`rdseed` with NZCV set per spec on failure |

**FP semantics.** x86 and AArch64 differ in a few places. kemu is **bit-exact by
default** and adds fix-ups only where results can differ:

- **Rounding mode and FZ.** FPCR.RMode/FZ map onto MXCSR.RC/FTZ+DAZ. MXCSR is only
  rewritten on `MSR FPCR`, and it's preserved across context switches by XSAVE.
  FZ16/AH are not advertised.
- **Default NaN and NaN propagation.** x86's default QNaN has the sign bit set and
  AArch64's (FPCR.DN=0) doesn't, and their operand-selection rules differ. Arithmetic
  results that may be NaN get a cheap fix-up (`vcmpunord` + blend) **only when T2
  can't prove non-NaN-ness**. A per-process `kemu.fp=fast` opt-out drops it.
- **`FMIN`/`FMAX`/`FMINNM`/`FMAXNM`.** x86 `minps`/`maxps` are not commutative with
  NaN/±0. kemu emits correct compare-and-blend sequences.
- **`FCVTZS`/`FCVTZU` and friends** saturate on AArch64. x86 returns the
  "integer indefinite" value, so kemu emits compare-and-fix-up sequences. T2
  drops them when range analysis proves the input is in range.
- **`FRECPE`/`FRSQRTE`** must match Arm's estimate tables bit-for-bit, so they're
  table-driven (not x86 `rcpps`).
- **FPSR** cumulative flags come from MXCSR exception bits, read lazily. IDC has no
  exact x86 equivalent and is approximated from DE.

### 8.6 System registers and the advertised CPU

kemu presents a virtual CPU with MIDR implementer `0x00` (reserved by Arm for
software use) and a feature set roughly equal to **Armv8.2-A plus selected later
extensions**:

- HWCAP: `FP ASIMD AES PMULL SHA1 SHA2 CRC32 ATOMICS FPHP ASIMDHP CPUID ASIMDRDM
  JSCVT FCMA LRCPC DCPOP ASIMDDP USCAT ILRCPC FLAGM SB`.
- HWCAP2: `DCPODP FLAGM2 FRINT`, plus `RNG` when the host has RDRAND and RDSEED.
- **Not advertised:** SVE/SME, MTE, PACA/PACG, BTI, POE, GCS, SSBS, plus anything
  not fully implemented.

Readable EL0 system registers:

| Register | Translation |
|---|---|
| `TPIDR_EL0`, `TPIDRRO_EL0` | `gs:[…]` load/store |
| `NZCV`, `FPCR`, `FPSR` | materialize (§8.2/§8.5) |
| `CNTVCT_EL0` (`CNTVCTSS`) | `rdtsc` (`rdtscp`/`lfence; rdtsc` for the ordered form) |
| `CNTFRQ_EL0` | constant = host TSC frequency (requires invariant TSC; otherwise kemu falls back to a clock-derived scaled counter) |
| `CTR_EL0` | **DIC=0**, IDC=1, 64-byte lines. DIC=0 forces guests to issue `IC IVAU`, which kemu relies on (§10.3) |
| `DCZID_EL0` | 64-byte blocks |
| `MIDR_EL1`, `ID_AA64*_EL1`, `MPIDR_EL1` (via `MRS` emulation, HWCAP_CPUID) | constants matching the advertised features, consistent with `/proc/cpuinfo` and HWCAPs |

---

## 9. Precise state, signals, and the return stack

### 9.1 Precise-state invariant

kemu guarantees that **at any host instruction boundary inside translated code, the
kernel can reconstruct the exact AArch64 architectural state at a guest instruction
boundary.** This is how faults, async signals, ptrace stops, `/proc/<pid>/syscall`,
perf, and code invalidation all work without polling.

Mechanism:

1. **Restartable instruction sequences.** The host sequence for each guest
   instruction is idempotent until its *commit point*. Guest register writes happen
   in scratch or in the destination after all faultable memory accesses. Stores are
   idempotent on normal memory, so for `STP`, `ST1 {…}` and similar, an interruption
   between stores rolls back to the instruction start and re-execution reproduces
   identical memory. Writeback happens last. Atomics are one locked instruction.
2. **Recovery metadata.** For each block, `meta` records a compressed map
   `host_offset → (guest_pc, location of each guest register, flag image state,
   pending-store info)`. Most entries are deltas from the canonical map, encoded as
   a byte-coded state machine (like DWARF CFI), roughly 1–2 bytes per guest
   instruction. Metadata lives in kernel memory, not in the user mapping.
3. **Rollback rule.** For a host RIP in the middle of guest instruction *i*, the
   state is "before *i*", with registers read from the locations metadata gives for
   that point.

**Deviation (by design):** NZCV is exact at an interruption point only if the flags
are *live* there (some later instruction in the block, or a block exit, reads them).
Dead flags are never materialized. That is what makes lazy flags cheap, but a signal
delivered at such a point (for example a fault) shows a stale NZCV in `uc_mcontext`.
Execution after `rt_sigreturn` is unaffected, because the flags are overwritten
before anything reads them.

### 9.2 Host return stack

`rsp` points into a per-thread host return stack (64 KiB plus guard pages) in the
CPU state area. It only holds host return addresses pushed by translated `call`s.
Its entries are **hints**: every landing pad verifies the actual guest return target.
- **Mismatch** (longjmp, exception unwinding, coroutines, tail-call tricks, or a
  guest corrupting the stack) → `ret_miss` stub → indirect lookup.
- **Overflow/underflow** (unbalanced call/ret) → a guard-page fault, which kemu
  handles by resetting `rsp` to the stack's midpoint and resuming at the dispatcher
  with the reconstructed guest PC. This costs one fault per 4096 unbalanced
  frames.
- **CET shadow stacks** are disabled for kemu tasks (guests can't request them;
  unbalanced guest returns would raise `#CP`). Optional hardening (§12.3) can
  enable them with a `#CP`→resync handler.

### 9.3 Signal delivery

`arch_do_signal_or_restart()` checks `TIF_KEMU` and calls `kemu_handle_signal()`:

1. Reconstruct guest state from `pt_regs`, xstate, the CPU state page, and
   metadata (§9.1).
2. Build an arm64 `rt_sigframe` on the guest stack (or the guest's sigaltstack):
   `siginfo` (same LP64 layout on both ABIs), and a `ucontext` with arm64
   `sigcontext` (`regs[31]`, `sp`, `pc`, `pstate` with NZCV), a `__reserved` record
   chain containing `fpsimd_context` (V0–V31, FPSR, FPCR), `esr_context` for
   faults, and the terminating null record. Frame size and alignment match arm64.
3. Set guest X0 = signo, X1 = &info, X2 = &uc, SP = frame, PC = handler,
   X30 = `sa_restorer` if `SA_RESTORER`, else the aarch64 vDSO's
   `__kernel_rt_sigreturn`.
4. Set `TIF_KEMU_FIXUP`, so the exit path enters the handler's translation.

`rt_sigreturn` (arm64 nr 139) validates and restores the frame, including any edits
the handler made to `uc_mcontext` (JIT safepoints and Go's async preemption modify
the PC). Syscall restart follows arm64 rules: `-ERESTARTSYS`/`-ERESTARTNOINTR`
rewind the guest PC by 4 and restore `X0 = orig_x0`, and
`-ERESTART_RESTARTBLOCK` sets X8 = `__NR_restart_syscall` (128).

Signal numbers, `siginfo`, `sigset_t`, and `sigaction` layouts are identical
between asm-generic/arm64 and x86_64 LP64, so the core signal code (queueing,
masks, `sigaction` storage) needs no translation. Guest handler addresses are just
guest VAs stored in `sighand`. Only `MINSIGSTKSZ`/`SIGSTKSZ` (5120/16384 on arm64)
and frame layout differ.

### 9.4 Interrupted code that is being freed

See the invalidation protocol (§10.3). On every exit to user mode with a stale
epoch, the thread rewrites `regs->ip` and any stale return-stack entries to
dispatcher stubs, using metadata to keep guest state exact.

---

## 10. Code cache management and tiering

### 10.1 Tier 1: baseline translator

- Unit: a guest basic block (≤ 128 instructions, ends at branches or page crossings).
- Linear lifting, block-local flag liveness, canonical register map at entry and exit,
  direct encoding.
- Target compile speed **≤ 150 ns per guest instruction**, so startup of large
  programs (clang, python, JVM) is dominated by real work, not translation.
- Each block gets an execution counter (`inc dword gs:[ctr_slot]` on loop heads and
  function entries only) that triggers T2.

### 10.2 Tier 2: region optimizer

Triggered when a block's counter passes a threshold (default 4096 per entry, or 256
back-edge iterations). The region is grown from the hot seed over T1 profile edges:
loops, inlined small leaf calls, and if-conversion candidates.

Passes, in order: lifting to SSA → constant/copy propagation → `ADRP`+`ADD`/`LDR`
folding into absolute or RIP-relative constants → flag elimination plus
compare-branch fusion → redundant zero/sign-extension elimination → load/store
forwarding of spilled guest registers → loop-invariant code motion (including hoisting
`gs:` spills/fills out of loops) → AArch64 idiom recognition (`UBFX`/`SBFX`/`BFI` →
`bextr`/`shrx`/`rorx`; `CSEL`/`CSINC`/`CSNEG` → `cmov`/`setcc`/`adc` tricks;
`MADD` → `imul`+`add`/`lea`) → instruction selection with x86 addressing-mode
folding → **linear-scan register allocation across the whole region**, with the
canonical map only on region exits → block layout (fall-through on hot paths) → encode,
emit metadata, and run the verifier.

Compilation runs **in the guest thread's own context**, in time slices (default
200 µs, resumable state in the per-thread arena) via `task_work` on the exit-to-user
path. That makes CPU time accounting and cgroup limits correct with no kernel
threads. The block keeps running its T1 code until T2 finishes, then the T1 entry is
patched to jump to the region.

### 10.3 Invalidation and reclamation

**When translations become invalid:**
- `IC IVAU` on a guest VA. This is the architectural signal. Because `CTR_EL0.DIC=0`,
  every compliant JIT (V8, HotSpot, LuaJIT, .NET, libgcc `__clear_cache`) issues it.
  It traps through `KEMU_SYS_HELPER` and invalidates blocks overlapping the cache line.
- VMA changes: `munmap`, `mremap`, `mprotect` removing `PROT_EXEC`,
  `MAP_FIXED` replacement, and `madvise(MADV_DONTNEED)` on exec mappings. These are
  reported by `kemu_vma_change()` hooks in `mm/vma.c`/`mm/mprotect.c`/`mm/mremap.c`.
  We use explicit hooks instead of mmu_notifiers so that reclaim, migration and
  compaction never cause spurious invalidations.
- `access_process_vm()` writes (ptrace `POKETEXT`, `/proc/pid/mem`,
  `process_vm_writev`) into exec mappings of a kemu mm, which covers debugger
  breakpoints.
- **Paranoid SMC mode** (opt-in per process): for guests that skip `IC IVAU`,
  pages with live translations are write-protected, and a write fault invalidates
  them and unprotects the page.

The per-mm **translated-page index** (a maple tree from guest page to block list)
makes invalidation O(blocks on the affected page).

**Protocol (epoch-based, RCU-like, but tracking user mode instead of kernel mode):**

1. **Unlink.** Under the per-mm translation lock, remove the blocks from the lookup
   table (keys set to the invalid value `1` first, then targets), re-point chained
   jumps into them back at translation stubs, and retire them to the current epoch's
   free list.
2. **Bump** `kemu_mm.epoch`. For the invalidating thread, the remainder of the
   current block is never executed: `IC IVAU` is followed in the guest by `ISB`,
   which ends the block, and the helper returns to the dispatcher.
3. **Quiesce.** A thread is quiescent once it's in the kernel. IPI the CPUs in
   `mm_cpumask` that are currently running this mm's threads in user mode (the
   membarrier mechanism) to force a kernel entry. Each thread acknowledges the epoch
   in `kemu_exit_fixup()`, rewriting a stale `regs->ip` and return-stack entries.
   Threads that are blocked or preempted acknowledge on their next exit to user
   mode, before they can run any code.
4. **Free** the retired blocks' cache space once every thread has acknowledged
   (or is in the kernel and will fix up before returning).

Lookup-table slots are reused only after their epoch is reclaimed, which rules out
torn `{key, target}` reads. Cross-thread semantics match the architecture: after
thread A's `IC IVAU`+`DSB`, other threads see new code no later than their next
context-synchronizing event. Under kemu, that's their next kernel entry or
dispatcher pass, which the IPI forces immediately.

**Capacity.** When the cache reaches its limit, kemu evicts in generations: it
retires the oldest cold T1 generation first, and flushes everything only as a last
resort. The cache registers a shrinker so the kernel can reclaim memory under
pressure.

### 10.4 Shared and persistent translations (phase 4)

Most executable code is file-backed (libc, libstdc++, libpython, the main binary).
kemu keeps an optional **per-inode translation cache**. It's keyed by `(sb, ino,
i_version or mtime/ctime, file offset, kemu ABI version, host feature mask,
translation profile)` and lives in kernel memory, reclaimable by a shrinker.
Translations of file-backed code are emitted with **relocation records** for every
guest-PC-derived immediate (ADRP results, BL return addresses, branch targets
outside the block). A new process mapping the same library at a different (ASLR)
address gets the code by `memcpy` plus relocation instead of retranslating, which
brings `bash`/`python` startup close to native.

An on-disk persistent cache would need a trust story (translations are executable
code produced from untrusted input, so a tampered cache must never be loaded). This
is left open (§17).

---

## 11. Syscall ABI layer

### 11.1 Dispatch

The guest syscall table is generated at build time from `scripts/syscall.tbl` with
the same ABI selectors `arch/arm64/kernel/Makefile.syscalls` uses (arm64 has used
the unified table since v6.11). Each entry has one of these kinds:

| Kind | Handling | Examples |
|---|---|---|
| **passthrough** | Build an x86_64 `pt_regs` (`di, si, dx, r10, r8, r9` = guest X0–X5) and call the existing `__x64_sys_*` for the equivalent syscall | `read`, `write`, `openat`, `close`, `mmap`, `futex`, `ppoll`, `pselect6`, `bpf`, `getdents64`, `statx`, `faccessat2`, ~85% of the table |
| **marshalled** | Rust `sysabi` converts layouts, then calls an inner kernel helper (`vfs_fstatat`, `do_epoll_ctl`, …) | `newfstatat`/`fstat` (asm-generic `struct stat` ≠ x86_64 `struct stat`), `epoll_ctl`/`epoll_pwait`/`epoll_pwait2` (x86_64 `epoll_event` is packed: 12 vs 16 bytes) |
| **reordered** | Argument order differs | `clone` (asm-generic: `flags, stack, ptid, tls, ctid`; x86_64: `…, ctid, tls`) |
| **kemu-semantic** | Needs guest-state awareness | `rt_sigreturn`, `rt_sigaction` (flag sanity), `sigaltstack`, `clone`/`clone3` (`CLONE_SETTLS` sets the child's guest `TPIDR_EL0`, not the FS base; the child's guest SP/PC come from guest state), `execve*`, `prctl` (arm64 options), `ptrace`, `personality`, `uname`, `mprotect`/`mmap` (`PROT_BTI` accepted and ignored, `PROT_MTE` → `EINVAL`), `rseq`, `riscv_*`-style arch-specific stubs |
| **unsupported** | `-ENOSYS`, as on an arm64 kernel without the feature | none expected in v1 except features we don't advertise |

The kemu syscall path mirrors generic entry so every existing consumer sees the
guest ABI:

```
kemu_syscall(regs)
  read nr = X8, args = X0..X5 (READ_ONCE from CPU state page); save orig_x0
  syscall_enter_from_user_mode_work():
      ptrace syscall-enter stop        (tracer sees arm64 regset, §11.3)
      seccomp                          (seccomp_data.arch = AUDIT_ARCH_AARCH64, nr = arm64 nr)
      tracepoint sys_enter, audit      (syscall_get_arch() == AUDIT_ARCH_AARCH64)
  dispatch via guest table
  write X0 = return value
  syscall_exit_to_user_mode():         exit stop, audit, signals, kemu_exit_fixup
```

The `asm/syscall.h` helpers (`syscall_get_nr`, `syscall_get_arguments`,
`syscall_set_return_value`, `syscall_get_arch`, …) become kemu-aware, the same way
they already handle IA32 compat tasks through `TS_COMPAT`. This makes seccomp,
audit, `PTRACE_GET_SYSCALL_INFO`, `/proc/<pid>/syscall`, and BPF syscall
tracepoints correct with no changes to those subsystems.

**seccomp policy.** Filters installed by the guest are written for arm64 and work
as-is. Filters inherited from an x86_64 parent (container runtimes) see
`AUDIT_ARCH_AARCH64`. Runtimes must list `SCMP_ARCH_AARCH64` in their profile.
Docker/podman profiles already do this on multi-arch configurations, and an
unknown arch falls through to the profile's default action, which fails closed. This
mirrors how IA32 tasks are filtered today.

### 11.2 ABI-sensitive surfaces (audited list)

Both ABIs are LP64 little-endian with the asm-generic ioctl encoding, so nearly all
structures are byte-identical. The known differences are handled explicitly and
covered by selftests:

- `struct stat` (fstat family), `struct epoll_event` (epoll syscalls).
- io_uring is not offered to guests: `io_uring_setup`, `io_uring_enter` and
  `io_uring_register` return `ENOSYS`, and programs fall back to ordinary syscalls
  (libuv, liburing users, glibc). Ring operations read and write native structs
  directly, for example `struct epoll_event` for `IORING_OP_EPOLL_CTL`, which
  bypasses this translation layer.
- `clone`/`clone3` TLS semantics; `struct user_regs_struct` and regsets (ptrace, core dumps).
- Signal frames, `MINSIGSTKSZ`, `AT_MINSIGSTKSZ`.
- `prctl`: `PR_SVE_*`, `PR_SME_*`, `PR_PAC_*`, `PR_MTE_*`, `PR_SET_TAGGED_ADDR_CTRL`
  (enables tagged mode, §6.1). x86-specific `arch_prctl` doesn't exist in the
  arm64 table.
- `ioctl`: passthrough by default, with a denylist for host-architecture-specific
  interfaces that would mislead a guest (`/dev/kvm` → `ENOTTY`, x86 MSR/CPUID
  devices, perf PMU raw events). `perf_event_open` maps generic events and
  rejects raw x86 PMU encodings.
- `/proc`: `cpuinfo` (arm64 format for kemu readers), `<pid>/auxv`, `<pid>/maps`
  (region hidden), `<pid>/stat` `kstkeip`/`kstkesp` (guest PC/SP),
  `<pid>/syscall`, `<pid>/personality`.
- vDSO: §11.4.
- `rseq`: the kernel's `rseq_ip_fixup()` compares the *guest* PC (reconstructed)
  with `rseq_cs` and redirects to the guest `abort_ip` through `TIF_KEMU_FIXUP`.
  glibc 2.35+ registers rseq unconditionally, so this is required.
- `getcpu`, `membarrier` (`MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE` maps to an
  epoch bump plus IPI, which gives guests correct cross-modifying-code semantics).
- `pkey_*`: `-ENOSPC`/`-EINVAL` (POE not advertised).

### 11.3 ptrace, debugging, and core dumps

- `task_user_regset_view(task)` returns an **arm64 regset view** for kemu tracees:
  `NT_PRSTATUS` (`user_pt_regs`), `NT_PRFPREG` (`user_fpsimd_state`),
  `NT_ARM_TLS`, `NT_ARM_SYSTEM_CALL`, and `NT_ARM_HW_BREAK`/`HW_WATCH` (stubbed to
  0 slots in v1). The view is chosen by the **tracee**, so native x86_64
  `gdb-multiarch`/`strace` and emulated aarch64 `gdb`/`strace` both work.
  Legacy x86 `PTRACE_GETREGS`/`PEEKUSER` on a kemu tracee returns `-EIO`.
- `SETREGSET` writes guest state and sets `TIF_KEMU_FIXUP`.
- `PTRACE_SINGLESTEP` puts the thread in single-step mode: it executes 1-instruction
  translations (not cached in the shared lookup table) and stops with `SIGTRAP`
  (`TRAP_TRACE`) after each one.
- Software breakpoints: `POKETEXT` of a `BRK` invalidates translations (§10.3).
- `PTRACE_SYSCALL`, `PTRACE_O_TRACESYSGOOD`, `SECCOMP_RET_TRACE`, and syscall
  number changes by the tracer (`NT_ARM_SYSTEM_CALL`) behave like arm64.
- Core dumps: `binfmt_kemu`'s core writer emits `EM_AARCH64` cores with arm64 notes,
  readable by `gdb-multiarch` and aarch64 `gdb`.

### 11.4 vDSO

kemu ships an **aarch64 vDSO image** built from the kernel's generic vDSO sources
for arm64 (prebuilt blob in-tree plus a reproducible build script, so x86 kernel
builds don't need an arm64 cross compiler). It exports `__kernel_clock_gettime`,
`__kernel_gettimeofday`, `__kernel_clock_getres`, `__kernel_getrandom`, and
`__kernel_rt_sigreturn`, and it maps the host's generic vDSO data pages
(`vdso_time_data`, `vdso_rng_data`).

Two paths make it fast:
- Its arm64 clock read is `MRS CNTVCT_EL0`, which kemu translates to `rdtsc`, so
  the host TSC clocksource's `mult`/`shift` in the shared data page apply unchanged.
  The translated vDSO is just guest code.
- **Intrinsic binding.** The translator recognizes calls into known vDSO entry points
  and emits a direct call to the host x86_64 vDSO implementation, with AAPCS ↔
  SysV argument marshalling and caller-saved register handling. That's about 20 ns
  for `clock_gettime`, the same as native.

When the TSC isn't the active clocksource, the vDSO falls back to the real syscall,
exactly as native arm64 does when the counter is unusable.

### 11.5 Observability

- **perf.** `perf_instruction_pointer()` and `perf_callchain_user()` report guest
  PCs for kemu tasks (reconstructed via metadata, frame-pointer walk over X29 on the
  guest stack). `perf report` then symbolizes against the aarch64 ELFs and
  `PERF_RECORD_MMAP2` records it already has. Raw host-side profiling of
  translated code is available through `/proc/<pid>/kemu/perf-map` (perf map format).
- `/proc/<pid>/kemu/stats`: blocks and regions translated, cache use, T2 time,
  invalidations, lookup misses, return-stack misses, flag materializations, spills.
- Tracepoints `kemu:translate`, `kemu:invalidate`, `kemu:fallback`, `kemu:sigill`.

---

## 12. Security

### 12.1 Threat model

The guest is untrusted user code with the same credentials as a native process of
that user. kemu must not let it:
1. corrupt kernel memory, crash or hang the kernel (translator bugs),
2. bypass seccomp, LSMs, audit, or namespaces,
3. use more memory or CPU than its cgroup allows,
4. learn kernel addresses or other processes' data.

Running arbitrary *x86 user-mode code* inside its own process is **not** a privilege
escalation. A user can already run native x86 binaries. kemu's guarantees are about
the kernel boundary, not about sandboxing guest code from itself.

### 12.2 Defenses

- **Memory-safe translator.** `kemu-core` is `#![forbid(unsafe_code)]`, panic-free,
  allocation-free during translation, and fuel-bounded (§7.2). The C layer has no
  parsing logic: all guest-controlled bytes (instructions, sigframes, syscall
  structures, CPU state page) are parsed in Rust.
- **Code-cache verifier.** Every emitted block (always in debug and CI builds,
  sampled in production, configurable) is decoded by an independent x86 decoder in
  `verify/` and checked:
  - only allowlisted opcodes (no `wrgsbase`/`wrfsbase`, `int`, `sysenter`,
    `xsave` variants that could change state unexpectedly, `cli` etc. — the last
    fault anyway),
  - `syscall` only at stub-defined sites,
  - every direct branch target is inside the cache at an instruction boundary,
  - no embedded kernel pointers.

  This is a defense-in-depth check that the translator does what it intends. It is
  not a NaCl-style sandbox, because escape from the sandbox wouldn't cross a
  privilege boundary anyway.
- **Integrity of kemu metadata.** Recovery metadata, block tables, and the
  translated-page index live in kernel memory. User-visible structures (code,
  lookup table) are read-only to the guest. The writable CPU state page is treated as
  hostile input.
- **Syscall funnel.** All syscalls from kemu tasks go through the guest ABI path
  (§5.4). IA32 entry points are disabled for kemu tasks.
- **Resource limits.** Cache and arena memory is memcg-charged. Translation time is
  ordinary task CPU time. There are per-mm limits on blocks, regions, and metadata.
  Invalidation storms (a guest `IC IVAU`-ing in a loop) are rate-limited by falling
  back to interpreting the affected pages.
- **No kernel pointers in user mappings.** Stubs and code reference only user
  addresses. Region placement is randomized per exec.
- **Speculation.** Translated code runs in user mode, so Spectre exposure equals
  native. The translator's decoder uses no data-indexed tables (§7.3). Syscall
  dispatch uses `array_index_nospec`.
- **Testing as a security control.** Continuous fuzzing of decode → translate →
  verify, of the syscall marshallers, and of sigreturn frame parsing. syzkaller
  gets an `aarch64-on-kemu` target.

### 12.3 Optional hardening

- CET shadow stack for the host return stack with a `#CP`→resync handler (stops
  guest stores from steering translated `ret`s).
- `kemu.verify=always` for high-assurance deployments (about 30% extra translation
  cost, negligible steady-state cost).
- LSM hook `security_kemu_exec()` so policies can allow or deny foreign-arch
  execution per domain. kemu can also be restricted to user namespaces or cgroups
  through a sysctl.

---

## 13. Performance

### 13.1 Target and methodology

**Target: ≥ 80% of native.** "Native" means the same source compiled for x86_64
with the same compiler, version, and flags (`-O2`, no `-march` beyond x86-64-v2 for
x86, `-march=armv8.2-a` for arm64), run natively on the same host.

- Primary metric: geomean of SPEC CPU 2017 intrate + fprate (rate-1). Secondary: a
  suite of real workloads (CPython pyperformance, Node/V8 Octane-like, OpenJDK
  Renaissance, Go `go1` benchmarks, `zstd`/`xz`, SQLite speedtest, LLVM
  self-compile, nginx/Redis throughput with wrk/memtier).
- Report per benchmark, not just the geomean, plus startup latency
  (`/bin/true`, `python -c pass`) and translation overhead as a share of total CPU time.
- Host matrix: one recent Intel and one recent AMD part. kemu emits the same
  x86-64-v3 code on both.

### 13.2 Where time goes, and the budget

| Overhead source | Native cost | kemu mitigation | Budget (CPU-bound) |
|---|---|---|---|
| Address translation | — | Identity mapping: zero | 0% |
| Memory ordering | — | x86 TSO ⊇ AArch64; only `STLR` and full `DMB` cost anything | <1% |
| Register pressure (31 → 15 GPRs) | — | Static pinning of hot regs; spilled regs used as memory operands; per-region maps, global regalloc and spill hoisting in T2 | 6–10% |
| Flags | — | Liveness elimination, polarity tracking, compare-branch fusion | 1–2% |
| Indirect branches | 1 `jmp` | Inline cache → inline hash probe | 1–3% (higher for interpreters, mitigated by per-site caches) |
| Calls/returns | `call`/`ret` | Mapped onto real `call`/`ret` (RSB-predicted) plus a 2-instruction check | 1–2% |
| Instruction expansion (addressing modes, `UXTW`, `CSEL` chains, NEON shuffles, FP fix-ups) | — | T2 idiom matching, range analysis to drop FP fix-ups | 3–7% |
| Translation time | — | Fast T1, sliced T2, per-inode shared cache | <1% (long-running), visible at startup |
| Syscalls | 1 transition | 1 transition (same as native) plus the guest-ABI dispatch (~20 ns) | ~0% |
| **Total** | | | **~14–22% overhead → 78–86%** |

The arm64 compilation itself also helps: GCC/LLVM output for AArch64 assumes 31
registers and three-operand ALU ops, so it has fewer memory operands and fewer
redundant moves. That partly offsets expansion when we re-allocate on x86.

**Honest risk assessment.** 80% is aggressive. State-of-the-art x86→ARM translators
(Rosetta 2, with AOT plus hardware TSO help) land around 70–80%, and open-source
userspace translators are usually lower. kemu's advantages are the easy memory-model
direction, identity mapping, zero-copy syscalls, and exact signals without polling.
The deciding factor is register pressure: with APX and AVX-512 out of scope, the
15-register x86 file is a permanent constraint. Expected outcome: **about 80%
geomean, with FP/SIMD-heavy code at 80–90% and integer-heavy, branchy code at
72–82%.** Workloads dominated by guest JITs (V8, HotSpot) are
the weak point, because frequent code invalidation and translating JIT output twice
hurts. We track these separately.

### 13.3 Performance roadmap

1. T1 + chaining + call/ret mapping → 40–55%.
2. T2 region compiler with global regalloc and flag elimination → 70–80%.
3. Per-inode cache, vDSO intrinsics → startup and short-lived-process parity.
4. Profile-guided canonical maps (per-binary register profiles persisted in the
   per-inode cache), indirect-branch target profiling, and superblock formation
   across calls → ≥ 80% geomean.

---

## 14. Configuration and operation

| Knob | Default | Purpose |
|---|---|---|
| `CONFIG_KEMU` | n | Build kemu (depends on `X86_64`, `RUST`, `GENERIC_ENTRY`, `X86_FSGSBASE`-capable CPUs at runtime) |
| `/proc/sys/kernel/kemu/enabled` | 1 (when built) | Allow new AArch64 execs |
| `.../restrict` | 0 | 1 = only in non-initial user namespaces; 2 = disabled for unprivileged users |
| `.../max_cache_mb` | 256 | Per-mm code-cache limit |
| `.../t2_threshold` | 4096 | Tier-up threshold |
| `.../verify` | `sample` | `off` / `sample` / `always` |
| `.../interp_prefix` | empty | Fallback interpreter search prefix (per userns) |
| `.../show_region` | 0 | Show kemu region in `/proc/<pid>/maps` to privileged readers |
| `prctl(PR_KEMU_*)` (kemu-specific, invisible to arm64 software that doesn't know it) | — | Per-process: `fp=fast`, strict monitor, paranoid SMC, tagged mode, interp mode (debug) |

The kernel command line `kemu.mode=interp` forces the reference interpreter
everywhere. It's for bring-up and bisection.

The host CPU check at boot requires x86-64-v3, AES-NI, PCLMULQDQ, and FSGSBASE. Without them kemu
refuses to enable and logs why.

---

## 15. Testing and validation

1. **Unit tests** (`cargo test` on `kemu-core`): decoder (exhaustive vs LLVM),
   per-instruction semantics vs the reference interpreter, encoder round-trips
   via an independent x86 decoder.
2. **Differential instruction testing.** Random and template-generated instruction
   sequences with random register, memory and FPCR state, run (a) on real AArch64
   hardware (CI runners on Graviton/Ampere), (b) through kemu T1, (c) through kemu T2,
   and (d) in the interpreter. Final architectural state and memory diffs must be
   identical, including NaN payloads and FPSR. This runs continuously.
3. **Fuzzing.** cargo-fuzz on translate+verify (no panics, bounded arena and fuel,
   verifier-clean output), on `sysabi` marshallers, and on sigframe parsing.
   syzkaller with an aarch64-binary-on-kemu target for the kernel interface.
4. **Kernel selftests** (`tools/testing/selftests/kemu/`, aarch64 static test
   binaries built with a cross toolchain and checked in as test assets or built in
   CI): exec/auxv, every marshalled syscall, signals (sync, async, nested,
   sigaltstack, restart semantics, `uc_mcontext` modification), ptrace regsets and
   single-step, rseq abort, SMC with `IC IVAU`, fork/vfork/clone/threads,
   invalidation under concurrency, seccomp with `AUDIT_ARCH_AARCH64`, core dumps.
5. **Conformance suites**: LTP (aarch64 build), glibc and musl test suites, the
   Go, Rust, and Python test suites, and the OpenJDK jtreg tier1 subset, all run as
   guests.
6. **Real-world**: a Debian arm64 chroot running `apt`, compilers, and `dpkg`
   builds; `docker run --platform linux/arm64` for popular images; Chromium/Node/JVM
   workloads for JIT behavior; Go programs (SIGURG async preemption).
7. **Performance CI**: the §13.1 suite on every merge, with regressions over 2% flagged.

---

## 16. Implementation plan

| Phase | Deliverable | Exit criteria |
|---|---|---|
| **0. Skeleton** | `binfmt_kemu`, kemu region, CPU state page, syscall funnel, reference interpreter running in-kernel (interpretation in `KEMU_SYS_TRANSLATE` loop) | Static aarch64 "hello world" and busybox run; arm64 auxv; `uname -m` |
| **1. ABI completeness** | Full syscall table + marshalling, signals/sigreturn, ptrace regsets, `/proc` views, vDSO, rseq, seccomp/audit arch | Dynamic glibc programs, Debian chroot, LTP syscalls pass at parity with arm64 hardware |
| **2. T1 JIT** | Decoder, T1 translator, chaining, call/ret mapping, metadata + precise state, invalidation protocol, verifier | Differential tests clean; 40%+ of native; JITs (Node, Java) run |
| **3. T2 optimizer** | Region formation, SSA opts, global regalloc, flag elimination, NEON/FP fix-up minimization | 70–80% of native on SPEC (AVX2 host) |
| **4. Caching and startup** | Per-inode shared translation cache with relocations, vDSO intrinsics | Startup within 1.5× native for `python -c pass` |
| **5. Profile-guided tuning** | Per-binary canonical register maps, indirect-branch profiling, cross-call superblocks | ≥ 80% geomean on SPEC |
| **6. Hardening and maintenance** | CET-SS option, LSM hook, documentation, syzkaller coverage, rebase tooling and CI on 6.18.y stable releases | — |

**Possible later work:** SVE/SVE2 at VL=128 on AVX2 (predicates emulated with
vector masks), opt-in native library thunks, on-disk persistent cache, AArch32
guests.

---

## 17. Open questions and risks

1. **Out-of-tree maintenance cost.** Every rebase risks conflicts in entry, signal,
   and mm code, which change often upstream. The hook inventory (§5.6) keeps that
   surface small. Moving off the 6.18 line later will need a deliberate port.
2. **Rust-for-Linux surface.** kemu needs mm/VMA, task_work, signal, and regset
   abstractions beyond what 6.18 provides. They're carried privately in
   `kernel/kemu/rust`, and kemu owns their soundness.
3. **Register pressure.** With APX out of scope, integer-heavy code may stay below
   80% (§13.2). The mitigations are all in the translator (§8.1).
4. **Exclusive-monitor ABA** is a known deviation. Strict mode exists, but we need
   data on whether any real software is affected.
5. **On-disk translation cache trust model** (signed by a kernel-held key? only
   root-populated directories? IMA-style measurement?) is undecided.
6. **Guest JIT performance** (double translation, invalidation frequency): we may
   need JIT-specific heuristics such as detecting W^X flip patterns and delaying
   T2 for recently written pages.
7. **Container ecosystem.** seccomp profiles must include `SCMP_ARCH_AARCH64`. This
   needs documentation and coordination with runtimes. Fail-closed behavior is safe
   but may surprise users at first.
8. **FP bit-exactness vs speed.** The default (exact) costs a few percent on
   FP-heavy code. Whether `fp=fast` should ever be the default is open.

---

## 18. Implementation status (2026-10-24)

This section tracks the implementation against the plan in §16. It's a snapshot;
the code and its commit history are authoritative.

**Working.** Phases 0–2 and the shared cache from phase 4:

- In-kernel reference interpreter and T1 JIT. The decoder and interpreter were
  audited against Arm's machine-readable A64 XML (`tools/isa-audit`): there are 0
  encoding mismatches over about 340k words and 0 semantic mismatches against qemu
  on data processing, SIMD and FP.
- ABI layer: signals, ptrace regsets and single-step, core dumps, `/proc`
  views, and seccomp/audit as `AUDIT_ARCH_AARCH64`.
- Real software: a Debian trixie arm64 rootfs is installed by running debootstrap's
  second stage under kemu (`scripts/mkrootfs.sh`). dpkg, bash, python3 (json,
  sqlite3, hashlib, zlib), gcc/as/ld, make, perl, git, coreutils, strace and
  multithreaded xz all run correctly.
- Shared translation cache (§10.4). See "Deviations" for the keying.
- Guest JITs: OpenJDK 21 (HotSpot C1/C2), Node.js 20 (V8, including wasm and
  irregexp), LuaJIT, PyPy and Ruby YJIT run `tests/jit-workloads` with output
  identical to their interpreter modes and to native x86_64 runs.

**Performance** (kemu-user `--jit` on the same host, noisy machine):

- intbench is at parity with native overall: sieve ~97%, hash and list ~100%,
  qsort ~84%.
- matmul (NEON) is ~65%.
- Warm `python3 -c pass` is ~60 ms in the VM (~100 ms without the shared cache).

**Deviations from the design as written:**

- **No T2 yet.** The T1 translator carries the optimizations that the design gave
  to T2:
  - superblocks across conditional branches;
  - per-block register remapping (loop promotion);
  - cross-block flag liveness: direct exit targets are scanned and the flags image
    is skipped when the target writes NZCV first;
  - out-of-line flag saves on taken B.cond exits.
- **Guest V registers live in the state page.** Each NEON/FP operation loads and
  stores through `%gs`. Block-level xmm allocation needs xmm-aware state recovery
  in the kernel (reading guest values out of saved FPU state). It's the main
  remaining performance item (matmul).
- **Shared-cache keying.** The cache is keyed by (sb, ino, i_generation, file
  offset) and validated by content. Every guest instruction word a translation
  read, including flag look-ahead into exit targets, is re-read at the new
  address and compared. So the key doesn't need `i_version`/mtime, and text that
  was rewritten in place or patched in memory just misses. Relocatable mode emits
  guest-PC-derived values as `movabs` imm64 with relocation records. Completeness
  is tested by translating every block at two guest bases (`KEMU_RELOC_CHECK`).
  Defaults: `kemu.xcache_mb=128` (LRU, plus a shrinker); `kemu.xcache=0` disables
  the cache.
- **Invalidation (§10.3).** Every block records the guest pages it read (its own
  page, since blocks never cross one, plus flag look-ahead into exit targets). A
  per-mm page index finds the blocks to remove on `IC IVAU` or when an executable
  mapping goes away. Removing a block takes it out of the lookup table and block
  index and restores the chained jumps into it; its code stays until the next
  capacity flush, so threads still inside it are safe, and an epoch bump sends
  every thread back through the dispatcher at its next kernel exit. Only running
  out of code space flushes everything. A flush retires chunks, which are freed
  once no thread can be executing in them: threads that are off-CPU with their
  state in the state page, or current, don't hold chunks (otherwise a thread
  sleeping in `futex()` pins all of them). The epoch is published after the table
  reset, so a thread that sees it can't pick up a stale table entry.
- **io_uring is disabled for guests** (§11.2).
- **Top-byte-ignore (TBI).** arm64 Linux ignores bits 63:56 of user data
  addresses. The interpreter applies this to every data access. Translated code
  doesn't mask addresses, so untagged programs pay nothing. A tagged pointer is
  non-canonical on x86, so a tagged access raises #GP. A #GP hook in
  `exc_general_protection` recovers the guest state and runs the instruction in
  the interpreter, then continues, or delivers `SEGV_MAPERR`/`SEGV_ACCERR` with
  the untagged address, as arm64 reports it. After 8 such faults a block is
  retranslated with address masking (`Cfg::tbi`: the base is copied and untagged
  with `shl 8; sar 8`; atomics and exclusives use the interpreter helper), and
  such translations bypass the shared cache. The tagged-address syscall ABI
  (`PR_SET_TAGGED_ADDR_CTRL`) isn't supported, so syscalls given tagged pointers
  fail with `EFAULT` (the arm64 default).
- **Oversized superblocks.** When exit slots or recovery points run out, the
  translation is retried with half the instruction limit instead of failing.

**Debug knobs:**

- `kemu.jit=0` runs the interpreter only.
- `kemu.jitoff=<mask>` turns JIT features off for bisecting:
  - 1: helper for every non-branch instruction;
  - 2: helper for SIMD/FP;
  - 4: one-instruction blocks;
  - 8: no chaining;
  - 32: no register remapping.
- `kemu.debug=1` prints per-mm statistics: translations, shared-cache hits,
  translation time, flushes and targeted invalidations.
- `kemu.stress=<n>` bumps the epoch and kicks every other thread once per n
  translations. This forces state recovery at arbitrary points in translated code.
  (State recovery once mistook a block's exit trampolines, which run after the
  remap epilogue, for remapped code. A thread interrupted there got one guest
  register's value in another, which crashed HotSpot's C2 compiler about once in
  60 runs. Trampolines now start with an explicit canonical `REMAP 0` point.)
- kemu-user:
  - `KEMU_JIT_STATS` prints a helper-instruction histogram;
  - `KEMU_XLAT_BENCH=<span>` measures translator throughput;
  - `KEMU_RELOC_CHECK=<span>` runs the relocation completeness check;
  - `KEMU_PERF_MAP` writes a perf map of translated blocks.

**Not done yet:**

- a real vDSO (time calls currently go through syscalls);
- rseq;
- perf callchains through translated code;
- `/proc/<pid>/kemu/stats`;
- the LSM hook and CET-SS option;
- the code-cache verifier (§12.2);
- LTP runs.

Translator speed is about 180 ns per guest instruction; most of it is fixed
per-block cost (header, entries, exit trampolines, metadata).
