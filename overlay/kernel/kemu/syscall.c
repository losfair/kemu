// SPDX-License-Identifier: GPL-2.0
/*
 * kemu: handling of kemu operations issued by translated code / stubs, and
 * the guest (arm64 asm-generic) syscall ABI.
 *
 * For KEMU_OP_SVC the guest state lives entirely in the CPU state page.
 * We present the guest syscall to the generic entry code through a
 * "syscall view" of pt_regs (orig_ax = arm64 nr, di..r9 = X0..X5) so that
 * seccomp, ptrace, audit and tracepoints see the guest ABI unchanged.
 * Translated code reloads all guest registers from the state page after
 * the syscall instruction, so clobbering the host registers is fine.
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/entry-common.h>
#include <linux/syscalls.h>
#include <linux/signal.h>
#include <asm/syscall.h>

#include "kemu_internal.h"
#include "syscall_table.h"

/* Instructions interpreted per KEMU_OP_TRANSLATE before returning to user. */
#define KEMU_INTERP_BUDGET	65536

static void kemu_load_syscall_view(struct pt_regs *regs, struct kemu_cpu *cpu)
{
	regs->orig_ax = READ_ONCE(cpu->x[8]);
	regs->di = READ_ONCE(cpu->x[0]);
	regs->si = READ_ONCE(cpu->x[1]);
	regs->dx = READ_ONCE(cpu->x[2]);
	regs->r10 = READ_ONCE(cpu->x[3]);
	regs->r8 = READ_ONCE(cpu->x[4]);
	regs->r9 = READ_ONCE(cpu->x[5]);
	regs->ax = -ENOSYS;
}

/*
 * Syscall arguments may have been changed by a tracer or seccomp through
 * the syscall view; propagate them back to the guest registers.
 */
static void kemu_store_syscall_args(struct pt_regs *regs, struct kemu_cpu *cpu)
{
	cpu->x[0] = regs->di;
	cpu->x[1] = regs->si;
	cpu->x[2] = regs->dx;
	cpu->x[3] = regs->r10;
	cpu->x[4] = regs->r8;
	cpu->x[5] = regs->r9;
}

static long kemu_dispatch(struct pt_regs *regs, long nr)
{
	if (nr < 0 || nr >= KEMU_NR_SYSCALLS)
		return -ENOSYS;
	return kemu_syscall_table(regs, nr);
}

/* KEMU_OP_SVC: a guest `svc #0`. The guest PC already points past it. */
void kemu_svc(struct pt_regs *regs)
{
	struct kemu_thread *kt = current->kemu;
	struct kemu_cpu *cpu = kt->cpu;
	u64 next_pc;
	long nr;

	kemu_enter_op(kt);
	next_pc = cpu->pc;
	kemu_load_syscall_view(regs, cpu);
	kt->orig_x0 = regs->di;
	kt->flags |= KEMU_TF_IN_SVC;

	nr = syscall_enter_from_user_mode_work(regs, regs->orig_ax);
	kemu_store_syscall_args(regs, cpu);
	if (nr != -1)
		regs->ax = kemu_dispatch(regs, nr);
	if (kemu_debug >= 2)
		pr_info("kemu: %s[%d] sys %ld(%lx, %lx, %lx, %lx) = %lx pc %llx\n",
			current->comm, task_pid_nr(current), nr, regs->di, regs->si,
			regs->dx, regs->r10, regs->ax, cpu->pc);

	/* exec may have replaced (or dropped) the kemu state. */
	if (current->kemu != kt)
		return;
	if (kt->flags & KEMU_TF_IN_SVC)
		WRITE_ONCE(kt->cpu->x[0], regs->ax);
	/* The guest PC changed (e.g. rt_sigreturn): resume at dispatch. */
	if (READ_ONCE(cpu->pc) != next_pc)
		kemu_redirect(kt);
	if (atomic_read(&current->mm->kemu->flush_pending) &&
	    atomic_xchg(&current->mm->kemu->flush_pending, 0)) {
		struct kemu_mm *km = current->mm->kemu;

		mutex_lock(&km->lock);
		kemu_jit_flush(km);
		mutex_unlock(&km->lock);
	}
	if (kt->flags & KEMU_TF_STEP_SVC) {
		kt->flags &= ~KEMU_TF_STEP_SVC;
		force_sig_fault(SIGTRAP, TRAP_TRACE, (void __user *)cpu->pc);
		kemu_redirect(kt);
	}
}

/*
 * Run the reference interpreter from the current guest state, then return
 * to a user stub: dispatch (keep going) or svc (perform a guest syscall).
 */
unsigned long kemu_interp(struct kemu_thread *kt, struct kemu_mm *km, u32 budget)
{
	struct kemu_rs_exit ex;
	u64 pc;

	kt->shadow = *kt->cpu;
	kemu_rs_interp(&kt->shadow, budget, &ex);
	*kt->cpu = kt->shadow;
	km->interp_insns += ex.retired;
	pc = READ_ONCE(kt->cpu->pc);

	switch (ex.kind) {
	case KEMU_EXIT_SVC:
		return kemu_stub(km, km->stubs.interp_svc);
	case KEMU_EXIT_BRK:
		force_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *)pc);
		break;
	case KEMU_EXIT_UNDEF:
		force_sig_fault(SIGILL, ILL_ILLOPC, (void __user *)pc);
		break;
	case KEMU_EXIT_FAULT:
		kemu_force_fault(ex.addr, ex.access, ex.aux);
		break;
	case KEMU_EXIT_ICINV:
		if (kemu_jit_enabled) {
			mutex_lock(&km->lock);
			kemu_jit_flush(km);
			mutex_unlock(&km->lock);
		}
		break;
	case KEMU_EXIT_BUDGET:
	default:
		break;
	}
	return kemu_stub(km, km->stubs.dispatch);
}

/* Non-svc kemu operations. regs->ax is the value returned to the stub. */
void kemu_op(struct pt_regs *regs, unsigned long op)
{
	struct kemu_thread *kt = current->kemu;
	struct kemu_mm *km = current->mm->kemu;

	kemu_enter_op(kt);
	if (op == KEMU_OP_STEP) {
		regs->ax = kemu_op_step(kt, km);
		return;
	}
	if (kemu_jit_enabled) {
		regs->ax = kemu_jit_op(regs, op);
		return;
	}
	switch (op) {
	case KEMU_OP_TRANSLATE:
	case KEMU_OP_HELPER:
	case KEMU_OP_CHAIN:
		regs->ax = kemu_interp(kt, km, KEMU_INTERP_BUDGET);
		break;
	default:
		/* Not something translated code ever does. */
		force_sig(SIGSYS);
		regs->ax = kemu_stub(km, km->stubs.dispatch);
		kemu_redirect(kt);
		break;
	}
}
