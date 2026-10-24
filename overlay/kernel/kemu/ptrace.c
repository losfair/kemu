// SPDX-License-Identifier: GPL-2.0
/*
 * kemu: arm64 ptrace view of kemu tasks (DESIGN.md §11.3).
 *
 * The tracee is always stopped in the kernel when its registers are
 * accessed, so its state page is authoritative.
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/regset.h>
#include <linux/elf.h>

#include "kemu_internal.h"

#define KEMU_PSR_NZCV	0xf0000000ULL

/* arm64 user_pt_regs: x0-x30, sp, pc, pstate. */
static int kemu_gpr_get(struct task_struct *target, const struct user_regset *regset,
			struct membuf to)
{
	struct kemu_cpu *cpu = target->kemu->cpu;

	membuf_write(&to, cpu->x, sizeof(cpu->x));
	membuf_store(&to, cpu->sp);
	membuf_store(&to, cpu->pc);
	return membuf_store(&to, cpu->nzcv & KEMU_PSR_NZCV);
}

/* Keep the syscall view in pt_regs in sync while stopped in a syscall. */
static void kemu_sync_syscall_view(struct task_struct *target)
{
	struct kemu_thread *kt = target->kemu;
	struct pt_regs *regs = task_pt_regs(target);

	if (!(kt->flags & KEMU_TF_IN_SVC))
		return;
	regs->di = kt->cpu->x[0];
	regs->si = kt->cpu->x[1];
	regs->dx = kt->cpu->x[2];
	regs->r10 = kt->cpu->x[3];
	regs->r8 = kt->cpu->x[4];
	regs->r9 = kt->cpu->x[5];
}

static int kemu_gpr_set(struct task_struct *target, const struct user_regset *regset,
			unsigned int pos, unsigned int count, const void *kbuf,
			const void __user *ubuf)
{
	struct kemu_thread *kt = target->kemu;
	u64 r[34];
	int err;

	memcpy(r, kt->cpu->x, sizeof(kt->cpu->x));
	r[31] = kt->cpu->sp;
	r[32] = kt->cpu->pc;
	r[33] = kt->cpu->nzcv & KEMU_PSR_NZCV;
	err = user_regset_copyin(&pos, &count, &kbuf, &ubuf, r, 0, sizeof(r));
	if (err)
		return err;
	/* Only EL0t AArch64 state is valid; keep NZCV only. */
	if (r[33] & 0x3df)
		return -EINVAL;
	memcpy(kt->cpu->x, r, sizeof(kt->cpu->x));
	kt->cpu->sp = r[31];
	kt->cpu->pc = r[32];
	kt->cpu->nzcv = r[33] & KEMU_PSR_NZCV;
	kemu_sync_syscall_view(target);
	kemu_redirect(kt);
	return 0;
}

/* arm64 user_fpsimd_state: vregs[32], fpsr, fpcr, reserved[2]. */
static int kemu_fpr_get(struct task_struct *target, const struct user_regset *regset,
			struct membuf to)
{
	struct kemu_cpu *cpu = target->kemu->cpu;
	u32 rsv[2] = { 0, 0 };

	membuf_write(&to, cpu->v, sizeof(cpu->v));
	membuf_store(&to, cpu->fpsr);
	membuf_store(&to, cpu->fpcr);
	return membuf_write(&to, rsv, sizeof(rsv));
}

static int kemu_fpr_set(struct task_struct *target, const struct user_regset *regset,
			unsigned int pos, unsigned int count, const void *kbuf,
			const void __user *ubuf)
{
	struct kemu_cpu *cpu = target->kemu->cpu;
	struct {
		u64 v[32][2];
		u32 fpsr, fpcr, rsv[2];
	} f;
	int err;

	memcpy(f.v, cpu->v, sizeof(f.v));
	f.fpsr = cpu->fpsr;
	f.fpcr = cpu->fpcr;
	f.rsv[0] = f.rsv[1] = 0;
	err = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &f, 0, sizeof(f));
	if (err)
		return err;
	memcpy(cpu->v, f.v, sizeof(f.v));
	cpu->fpsr = f.fpsr;
	cpu->fpcr = f.fpcr;
	return 0;
}

static int kemu_tls_get(struct task_struct *target, const struct user_regset *regset,
			struct membuf to)
{
	return membuf_store(&to, target->kemu->cpu->tpidr);
}

static int kemu_tls_set(struct task_struct *target, const struct user_regset *regset,
			unsigned int pos, unsigned int count, const void *kbuf,
			const void __user *ubuf)
{
	u64 tls = target->kemu->cpu->tpidr;
	int err = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &tls, 0, sizeof(tls));

	if (!err)
		target->kemu->cpu->tpidr = tls;
	return err;
}

static int kemu_syscall_get(struct task_struct *target, const struct user_regset *regset,
			    struct membuf to)
{
	int nr = (target->kemu->flags & KEMU_TF_IN_SVC) ?
		 (int)task_pt_regs(target)->orig_ax : -1;

	return membuf_store(&to, nr);
}

static int kemu_syscall_set(struct task_struct *target, const struct user_regset *regset,
			    unsigned int pos, unsigned int count, const void *kbuf,
			    const void __user *ubuf)
{
	int nr = (target->kemu->flags & KEMU_TF_IN_SVC) ?
		 (int)task_pt_regs(target)->orig_ax : -1;
	int err = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &nr, 0, sizeof(nr));

	if (err)
		return err;
	if (target->kemu->flags & KEMU_TF_IN_SVC)
		task_pt_regs(target)->orig_ax = nr;
	return 0;
}

/* No hardware breakpoints/watchpoints: report zero slots. */
static int kemu_hwdebug_get(struct task_struct *target, const struct user_regset *regset,
			    struct membuf to)
{
	u32 info[2] = { 0, 0 };

	membuf_write(&to, info, sizeof(info));
	return membuf_zero(&to, 16 * 16);
}

static int kemu_hwdebug_set(struct task_struct *target, const struct user_regset *regset,
			    unsigned int pos, unsigned int count, const void *kbuf,
			    const void __user *ubuf)
{
	return -EINVAL;
}

#define NT_ARM_TLS_		0x401
#define NT_ARM_HW_BREAK_	0x402
#define NT_ARM_HW_WATCH_	0x403
#define NT_ARM_SYSTEM_CALL_	0x404

static const struct user_regset kemu_regsets[] = {
	{
		.core_note_type = NT_PRSTATUS,
		.n = 34, .size = sizeof(u64), .align = sizeof(u64),
		.regset_get = kemu_gpr_get, .set = kemu_gpr_set,
	},
	{
		.core_note_type = NT_PRFPREG,
		.n = 528 / sizeof(u32), .size = sizeof(u32), .align = sizeof(u32),
		.regset_get = kemu_fpr_get, .set = kemu_fpr_set,
	},
	{
		.core_note_type = NT_ARM_TLS_,
		.n = 1, .size = sizeof(u64), .align = sizeof(u64),
		.regset_get = kemu_tls_get, .set = kemu_tls_set,
	},
	{
		.core_note_type = NT_ARM_HW_BREAK_,
		.n = 264 / sizeof(u32), .size = sizeof(u32), .align = sizeof(u32),
		.regset_get = kemu_hwdebug_get, .set = kemu_hwdebug_set,
	},
	{
		.core_note_type = NT_ARM_HW_WATCH_,
		.n = 264 / sizeof(u32), .size = sizeof(u32), .align = sizeof(u32),
		.regset_get = kemu_hwdebug_get, .set = kemu_hwdebug_set,
	},
	{
		.core_note_type = NT_ARM_SYSTEM_CALL_,
		.n = 1, .size = sizeof(int), .align = sizeof(int),
		.regset_get = kemu_syscall_get, .set = kemu_syscall_set,
	},
};

const struct user_regset_view kemu_regset_view = {
	.name = "aarch64", .e_machine = EM_AARCH64,
	.regsets = kemu_regsets, .n = ARRAY_SIZE(kemu_regsets),
};

/* x86 arch_ptrace() for kemu tracees: only the generic requests apply. */
long kemu_arch_ptrace(struct task_struct *child, long request,
		      unsigned long addr, unsigned long data)
{
	return ptrace_request(child, request, addr, data);
}

/* PTRACE_SINGLESTEP: step guest instructions through the interpreter. */
void kemu_user_step(struct task_struct *child, bool on)
{
	struct kemu_thread *kt = child->kemu;

	if (on)
		kt->flags |= KEMU_TF_STEP;
	else
		kt->flags &= ~(KEMU_TF_STEP | KEMU_TF_STEP_SVC);
	kemu_redirect(kt);
}
