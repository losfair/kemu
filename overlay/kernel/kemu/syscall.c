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
#include <linux/syscalls.h>
#include <linux/signal.h>
#include <asm/syscall.h>

#include "kemu_internal.h"
#include "syscall_table.h"

/* Instructions interpreted per KEMU_OP_TRANSLATE before returning to user. */
#define KEMU_INTERP_BUDGET	65536

static void kemu_load_syscall_view(struct pt_regs *regs, struct kemu_cpu *cpu)
{
	kemu_reg(regs, orig_ax) = READ_ONCE(cpu->x[8]);
	kemu_reg(regs, di) = READ_ONCE(cpu->x[0]);
	kemu_reg(regs, si) = READ_ONCE(cpu->x[1]);
	kemu_reg(regs, dx) = READ_ONCE(cpu->x[2]);
	kemu_reg(regs, r10) = READ_ONCE(cpu->x[3]);
	kemu_reg(regs, r8) = READ_ONCE(cpu->x[4]);
	kemu_reg(regs, r9) = READ_ONCE(cpu->x[5]);
	kemu_reg(regs, ax) = -ENOSYS;
}

/*
 * Syscall arguments may have been changed by a tracer or seccomp through
 * the syscall view; propagate them back to the guest registers.
 */
static void kemu_store_syscall_args(struct pt_regs *regs, struct kemu_cpu *cpu)
{
	cpu->x[0] = kemu_reg(regs, di);
	cpu->x[1] = kemu_reg(regs, si);
	cpu->x[2] = kemu_reg(regs, dx);
	cpu->x[3] = kemu_reg(regs, r10);
	cpu->x[4] = kemu_reg(regs, r8);
	cpu->x[5] = kemu_reg(regs, r9);
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
	struct mm_struct *old_mm = current->mm;
	struct kemu_cpu *cpu = kt->cpu;
	u64 next_pc;
	long nr;

	kemu_enter_op(kt);
	next_pc = cpu->pc;
	kemu_load_syscall_view(regs, cpu);
	kt->orig_x0 = kemu_reg(regs, di);
	kt->flags |= KEMU_TF_IN_SVC;

	nr = kemu_syscall_enter(regs);
	kemu_store_syscall_args(regs, cpu);
	if (nr != -1)
		kemu_reg(regs, ax) = kemu_dispatch(regs, nr);

	/*
	 * A successful execve frees this thread's kemu state and its state
	 * page (kemu_exec_release + the old mm's teardown). The new kemu_thread
	 * can reuse the same slab object, so compare the mm too before touching
	 * anything behind @kt or @cpu.
	 */
	if (current->kemu != kt || current->mm != old_mm)
		return;

	if (kemu_debug >= 2)
		pr_info("kemu: %s[%d] sys %ld(%lx, %lx, %lx, %lx) = %lx pc %llx\n",
			current->comm, task_pid_nr(current), nr, kemu_reg(regs, di), kemu_reg(regs, si),
			kemu_reg(regs, dx), kemu_reg(regs, r10), kemu_reg(regs, ax), cpu->pc);

	/*
	 * Guest x0 gets the return value, except when seccomp/syscall-user-
	 * dispatch rolled the syscall back (RET_TRAP, RET_KILL). x86 rollback
	 * writes orig_ax (here the arm64 syscall nr) into ax, but arm64 restores
	 * orig_x0; a SIGSYS broker (Chromium, Firefox) reads orig_x0 from the
	 * frame. A rollback is the skip (nr == -1) whose ax equals orig_ax; an
	 * errno skip (RET_ERRNO) has ax = -errno and is written normally.
	 */
	if (kt->flags & KEMU_TF_IN_SVC) {
		if (nr == -1 && kemu_reg(regs, ax) == kemu_reg(regs, orig_ax))
			WRITE_ONCE(kt->cpu->x[0], kt->orig_x0);
		else
			WRITE_ONCE(kt->cpu->x[0], kemu_reg(regs, ax));
	}
	/* The guest PC changed (e.g. rt_sigreturn): resume at dispatch. */
	if (READ_ONCE(cpu->pc) != next_pc)
		kemu_redirect(kt);
	if (atomic_read(&current->mm->kemu->flush_pending))
		kemu_jit_pending(current->mm->kemu);
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
			kemu_jit_invalidate(km, ex.addr, ex.addr + 1);
			mutex_unlock(&km->lock);
		}
		break;
	case KEMU_EXIT_BUDGET:
	default:
		break;
	}
	return kemu_stub(km, km->stubs.dispatch);
}

/* Non-svc kemu operations. kemu_reg(regs, ax) is the value returned to the stub. */
void kemu_op(struct pt_regs *regs, unsigned long op)
{
	struct kemu_thread *kt = current->kemu;
	struct kemu_mm *km = current->mm->kemu;

	kemu_enter_op(kt);
	if (op == KEMU_OP_STEP) {
		kemu_reg(regs, ax) = kemu_op_step(kt, km);
		return;
	}
	if (kemu_jit_enabled) {
		kemu_reg(regs, ax) = kemu_jit_op(regs, op);
		return;
	}
	switch (op) {
	case KEMU_OP_TRANSLATE:
	case KEMU_OP_HELPER:
	case KEMU_OP_CHAIN:
		kemu_reg(regs, ax) = kemu_interp(kt, km, KEMU_INTERP_BUDGET);
		break;
	default:
		/* Not something translated code ever does. */
		force_sig(SIGSYS);
		kemu_reg(regs, ax) = kemu_stub(km, km->stubs.dispatch);
		kemu_redirect(kt);
		break;
	}
}
