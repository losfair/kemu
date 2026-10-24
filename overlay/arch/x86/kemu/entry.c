// SPDX-License-Identifier: GPL-2.0
/*
 * kemu: x86_64 syscall entry for kemu tasks. Every `syscall` from a kemu
 * task is a kemu operation (see include/linux/kemu_abi.h).
 */

#include <linux/kernel.h>
#include <linux/entry-common.h>
#include <linux/kemu.h>
#include <linux/kemu_abi.h>
#include <asm/syscall.h>

void kemu_svc(struct pt_regs *regs);
void kemu_op(struct pt_regs *regs, unsigned long op);

static __always_inline bool kemu_sysret_ok(struct pt_regs *regs)
{
	if (cpu_feature_enabled(X86_FEATURE_XENPV))
		return false;
	if (unlikely(regs->cx != regs->ip || regs->r11 != regs->flags))
		return false;
	if (unlikely(regs->cs != __USER_CS || regs->ss != __USER_DS))
		return false;
	if (unlikely(regs->ip >= TASK_SIZE_MAX))
		return false;
	if (unlikely(regs->flags & (X86_EFLAGS_RF | X86_EFLAGS_TF)))
		return false;
	return true;
}

__visible noinstr bool kemu_do_syscall(struct pt_regs *regs, int nr)
{
	enter_from_user_mode(regs);
	instrumentation_begin();
	local_irq_enable();

	if ((unsigned int)nr == KEMU_OP_SVC) {
		kemu_svc(regs);
		instrumentation_end();
		syscall_exit_to_user_mode(regs);
	} else {
		/* Not a syscall: no syscall entry/exit work, like an exception. */
		regs->orig_ax = -1;
		kemu_op(regs, (unsigned int)nr);
		local_irq_disable_exit_to_user();
		exit_to_user_mode_prepare(regs);
		instrumentation_end();
		exit_to_user_mode();
	}
	return kemu_sysret_ok(regs);
}
