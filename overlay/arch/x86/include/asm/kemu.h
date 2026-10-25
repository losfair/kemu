/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_KEMU_H
#define _ASM_X86_KEMU_H

#include <linux/entry-common.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <asm/elf.h>
#include <asm/prctl.h>
#include <asm/proto.h>

/* Opt in only when asynchronous recovery can capture user XMM0..7. */
#define KEMU_ARCH_VECTOR_CACHE 1
void kemu_arch_read_xmm(u64 xmm[8][2]);

#define kemu_reg(regs, name) ((regs)->name)

static inline long kemu_syscall_enter(struct pt_regs *regs)
{
	return syscall_enter_from_user_mode_work(regs, regs->orig_ax);
}

static inline void kemu_set_gs(unsigned long base)
{
	do_arch_prctl_64(current, ARCH_SET_GS, base);
}

static inline void kemu_clone_tls(struct task_struct *p, unsigned long gs,
				  bool reset_fs)
{
	if (reset_fs) {
		p->thread.fsbase = 0;
		p->thread.fsindex = 0;
	}
	p->thread.gsbase = gs;
	p->thread.gsindex = 0;
}

static inline long kemu_fault_trap(void)
{
	return current->thread.trap_nr;
}

static inline unsigned long kemu_fault_address(void)
{
	return current->thread.cr2;
}

static inline unsigned long kemu_fault_error(void)
{
	return current->thread.error_code;
}

static inline void kemu_set_personality(void)
{
	set_personality_64bit();
}

#endif
