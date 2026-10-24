/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kemu: in-kernel AArch64 user-mode emulation. Hooks called from core
 * kernel code. Everything here compiles to nothing without CONFIG_KEMU.
 */
#ifndef _LINUX_KEMU_H
#define _LINUX_KEMU_H

#include <linux/types.h>
#include <linux/jump_label.h>

struct task_struct;
struct mm_struct;
struct pt_regs;
struct kernel_clone_args;
struct linux_binprm;

#ifdef CONFIG_KEMU

DECLARE_STATIC_KEY_FALSE(kemu_active_key);

/* True if @t runs an AArch64 guest. */
#define task_is_kemu(t) \
	(static_branch_unlikely(&kemu_active_key) && (t)->kemu)

/* x86 syscall entry for kemu tasks (noinstr). Returns true for SYSRET. */
bool kemu_do_syscall(struct pt_regs *regs, int nr);

/* Called with interrupts disabled right before returning to user mode. */
void kemu_exit_to_user(struct pt_regs *regs);

/* Signal delivery and syscall restart for kemu tasks. */
void kemu_do_signal(struct pt_regs *regs);

/* mm / task lifecycle. */
int kemu_dup_mm(struct mm_struct *oldmm, struct mm_struct *mm);
void kemu_mm_release(struct mm_struct *mm);
int kemu_copy_thread(struct task_struct *p, const struct kernel_clone_args *args);
void kemu_thread_exit(struct task_struct *tsk);
void kemu_exec_release(struct task_struct *tsk, struct mm_struct *old_mm);

/* Guest view helpers used by generic code. */
unsigned long kemu_user_sp(struct task_struct *tsk);

#else /* !CONFIG_KEMU */

#define task_is_kemu(t) false

static inline void kemu_exit_to_user(struct pt_regs *regs) { }
static inline void kemu_do_signal(struct pt_regs *regs) { }
static inline int kemu_dup_mm(struct mm_struct *oldmm, struct mm_struct *mm) { return 0; }
static inline void kemu_mm_release(struct mm_struct *mm) { }
static inline int kemu_copy_thread(struct task_struct *p,
				   const struct kernel_clone_args *args) { return 0; }
static inline void kemu_thread_exit(struct task_struct *tsk) { }
static inline void kemu_exec_release(struct task_struct *tsk, struct mm_struct *old_mm) { }

#endif /* CONFIG_KEMU */

#endif /* _LINUX_KEMU_H */
