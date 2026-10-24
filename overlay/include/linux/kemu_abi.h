/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kemu: layout of the per-thread guest CPU state page and the kemu
 * operation numbers used by translated code.
 *
 * This header is shared by C, by the user-mode stubs (assembly) and, as a
 * mirror with compile-time offset checks, by rust/kemu_core/src/state.rs.
 * Keep all three in sync.
 */
#ifndef _LINUX_KEMU_ABI_H
#define _LINUX_KEMU_ABI_H

/* Guest architectural state. */
#define KEMU_CPU_X(n)		((n) * 8)	/* X0..X30 */
#define KEMU_CPU_SP		248
#define KEMU_CPU_PC		256
#define KEMU_CPU_NZCV		264	/* architectural, bits 31:28 */
#define KEMU_CPU_FPCR		272	/* u32 */
#define KEMU_CPU_FPSR		276	/* u32 */
#define KEMU_CPU_TPIDR		280
#define KEMU_CPU_TPIDRRO	288
#define KEMU_CPU_EXCL_ADDR	296	/* exclusive monitor address, ~0 = open */
#define KEMU_CPU_EXCL_SIZE	304	/* access size in bytes (pairs: total) */
#define KEMU_CPU_EXCL_VAL	312	/* 16 bytes: value(s) seen by LDXR/LDXP */

/* Translated-code private area. */
#define KEMU_CPU_HOST_RSP	328	/* host return stack pointer save */
#define KEMU_CPU_HOST_RSP_TOP	336	/* reset value of the host return stack */
#define KEMU_CPU_SCRATCH	344	/* 8 x u64 scratch slots for stubs */
#define KEMU_CPU_EXIT_INFO	408	/* argument passed with kemu ops */
#define KEMU_CPU_FLAGS_X86	416	/* lazily saved host flags image */

#define KEMU_CPU_V(n)		(512 + (n) * 16)	/* V0..V31, 16 bytes each */
#define KEMU_CPU_STATE_SIZE	1024

/* Size of the per-thread slot: state page + host return stack + guards. */
#define KEMU_THREAD_STATE_PAGES	1
#define KEMU_THREAD_RSTACK_PAGES 16
#define KEMU_THREAD_SLOT_PAGES	32	/* includes unmapped guard pages */

/*
 * kemu operations, passed in %rax to the `syscall` instruction by
 * translated code. Every syscall from a kemu task is interpreted as one of
 * these; anything else raises SIGSYS.
 */
#define KEMU_OP_BASE		0x6b656d00
#define KEMU_OP_SVC		(KEMU_OP_BASE + 0)	/* guest svc #0 */
#define KEMU_OP_TRANSLATE	(KEMU_OP_BASE + 1)	/* lookup miss for guest PC in state */
#define KEMU_OP_HELPER		(KEMU_OP_BASE + 2)	/* interpret one insn at guest PC */
#define KEMU_OP_CHAIN		(KEMU_OP_BASE + 3)	/* translate + patch exit (EXIT_INFO) */
#define KEMU_OP_MAX		(KEMU_OP_BASE + 4)

#endif /* _LINUX_KEMU_ABI_H */
