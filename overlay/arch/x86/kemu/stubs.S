/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kemu user-mode stubs. This is a template copied into the first page of
 * every kemu code region; it runs in user mode and must be position
 * independent.
 */
#include <linux/linkage.h>
#include <linux/kemu_abi.h>

	.section .rodata, "a"
	.balign 64
SYM_DATA_START(kemu_stubs_start)

/*
 * Resume guest execution at the PC in the state page (%gs). Until the JIT
 * lands, the kernel interprets and returns the next stub in %rax.
 */
SYM_INNER_LABEL(kemu_stub_dispatch, SYM_L_GLOBAL)
	movl	$KEMU_OP_TRANSLATE, %eax
	syscall
	jmp	*%rax

	.balign 16
/* Perform the guest syscall described by the state page. */
SYM_INNER_LABEL(kemu_stub_svc, SYM_L_GLOBAL)
	movl	$KEMU_OP_SVC, %eax
	syscall
	jmp	kemu_stub_dispatch

	.balign 16
SYM_INNER_LABEL(kemu_stubs_end, SYM_L_GLOBAL)
SYM_DATA_END(kemu_stubs_start)
