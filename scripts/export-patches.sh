#!/bin/bash
# Export kemu's changes to existing Linux files as a patch series, one
# patch per hook area. New kemu files live in overlay/ instead.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
linux=${LINUX:-$HOME/src/linux-6.18}
out=$here/patches
rm -f "$out"/*.patch
n=0
emit() {
	local name=$1; shift
	n=$((n + 1))
	local f
	f=$(printf '%s/%04d-%s.patch' "$out" "$n" "$name")
	git -C "$linux" diff HEAD -- "$@" > "$f"
	[ -s "$f" ] || { rm -f "$f"; n=$((n - 1)); }
}
emit kemu-build             kernel/Makefile arch/x86/Kbuild fs/Kconfig.binfmt
emit kemu-task-mm-fields    include/linux/sched.h include/linux/mm_types.h
emit kemu-x86-entry         arch/x86/entry/syscall_64.c arch/x86/include/asm/entry-common.h
emit kemu-x86-signal        arch/x86/kernel/signal.c
emit kemu-x86-process       arch/x86/kernel/process.c arch/x86/include/asm/ptrace.h
emit kemu-syscall-arch      arch/x86/include/asm/syscall.h
emit kemu-fork-exit-exec    kernel/fork.c kernel/exit.c fs/exec.c
emit kemu-openat2           fs/open.c
emit kemu-x86-fault         arch/x86/mm/fault.c arch/x86/kernel/traps.c
emit kemu-mm                mm/vma.c mm/mprotect.c mm/mremap.c mm/mmap.c mm/memory.c
emit kemu-proc              fs/proc/
emit kemu-ptrace            kernel/ptrace.c arch/x86/kernel/ptrace.c
emit kemu-rseq              kernel/rseq.c
emit kemu-perf              kernel/events/ arch/x86/events/
# Anything else touched must be listed above.
other=$(git -C "$linux" diff HEAD --name-only | grep -v -E '^(kernel/Makefile|arch/x86/Kbuild|fs/Kconfig.binfmt|include/linux/sched.h|include/linux/mm_types.h|arch/x86/entry/syscall_64.c|arch/x86/include/asm/entry-common.h|arch/x86/kernel/signal.c|arch/x86/kernel/process.c|arch/x86/include/asm/ptrace.h|arch/x86/include/asm/syscall.h|kernel/fork.c|kernel/exit.c|fs/exec.c|fs/open.c|arch/x86/mm/fault.c|arch/x86/kernel/traps.c|mm/(vma|mprotect|mremap|mmap|memory).c|fs/proc/.*|kernel/ptrace.c|arch/x86/kernel/ptrace.c|kernel/rseq.c|kernel/events/.*|arch/x86/events/.*)$' || true)
if [ -n "$other" ]; then echo "unlisted files changed: $other" >&2; exit 1; fi
ls "$out"
