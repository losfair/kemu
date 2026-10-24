// SPDX-License-Identifier: GPL-2.0
/*
 * kemu: arm64 signal delivery, syscall restart and rt_sigreturn.
 *
 * Mirrors arch/arm64/kernel/signal.c. Frame contents are built and parsed
 * by Rust (sigframe.rs); this file does the policy and user copies.
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/signal.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/resume_user_mode.h>
#include <asm/trap_pf.h>
#include <asm/trapnr.h>

#include "kemu_internal.h"

/* arm64 ESR encodings reported in esr_context. */
#define ESR_EC_SHIFT		26
#define ESR_EC_DABT_LOW		0x24
#define ESR_EC_IABT_LOW		0x20
#define ESR_IL			BIT(25)
#define ESR_WNR			BIT(6)
#define ESR_FSC_TRANS_L3	0x07
#define ESR_FSC_PERM_L3		0x0f
#define ESR_FSC_ALIGN		0x21

void kemu_force_fault(u64 addr, int access, bool align)
{
	struct kemu_thread *kt = current->kemu;
	struct mm_struct *mm = current->mm;
	u64 esr = ESR_IL;
	bool mapped;

	if (access == KEMU_ACCESS_EXEC)
		esr |= (u64)ESR_EC_IABT_LOW << ESR_EC_SHIFT;
	else
		esr |= (u64)ESR_EC_DABT_LOW << ESR_EC_SHIFT;
	if (access == KEMU_ACCESS_WRITE)
		esr |= ESR_WNR;

	kt->fault_addr = addr;
	if (align) {
		kt->fault_esr = esr | ESR_FSC_ALIGN;
		force_sig_fault(SIGBUS, BUS_ADRALN, (void __user *)addr);
		return;
	}

	mmap_read_lock(mm);
	mapped = vma_lookup(mm, addr) != NULL;
	mmap_read_unlock(mm);
	kt->fault_esr = esr | (mapped ? ESR_FSC_PERM_L3 : ESR_FSC_TRANS_L3);
	force_sig_fault(SIGSEGV, mapped ? SEGV_ACCERR : SEGV_MAPERR,
			(void __user *)addr);
}

static unsigned long kemu_sigtramp(struct ksignal *ksig)
{
	struct kemu_mm *km = current->mm->kemu;

	if (ksig->ka.sa.sa_flags & SA_RESTORER)
		return (unsigned long)ksig->ka.sa.sa_restorer;
	return km->vdso_base;
}

static int kemu_setup_rt_frame(struct ksignal *ksig, sigset_t *set)
{
	struct kemu_thread *kt = current->kemu;
	struct kemu_cpu *cpu = kt->cpu;
	unsigned long sp, next_frame, frame;
	u64 fault_addr = 0, esr = 0;
	u64 rec[2];
	u8 *buf;
	int err = 0;
	int sig = ksig->sig;

	sp = sigsp(cpu->sp, ksig);
	next_frame = round_down(sp - sizeof(rec), 16);
	frame = round_down(next_frame, 16) - KEMU_SIGFRAME_SIZE;

	if ((sig == SIGSEGV || sig == SIGBUS) && !kt->fault_esr &&
	    current->thread.trap_nr == X86_TRAP_PF) {
		/* A fault in translated code: describe it as an arm64 abort. */
		unsigned long ec = current->thread.error_code;

		kt->fault_addr = current->thread.cr2;
		kt->fault_esr = ESR_IL | ((u64)((ec & X86_PF_INSTR) ? ESR_EC_IABT_LOW :
						ESR_EC_DABT_LOW) << ESR_EC_SHIFT) |
				((ec & X86_PF_WRITE) ? ESR_WNR : 0) |
				((ec & X86_PF_PROT) ? ESR_FSC_PERM_L3 : ESR_FSC_TRANS_L3);
	}
	if ((sig == SIGSEGV || sig == SIGBUS) && kt->fault_esr) {
		fault_addr = kt->fault_addr;
		esr = kt->fault_esr;
	}
	kt->fault_esr = 0;

	buf = kzalloc(KEMU_SIGFRAME_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	copy_siginfo_to_external((siginfo_t *)buf, &ksig->info);
	kt->shadow = *cpu;
	err = kemu_rs_build_ucontext(buf + KEMU_SIGINFO_SIZE, KEMU_UCONTEXT_SIZE,
				     &kt->shadow, set->sig[0], current->sas_ss_sp,
				     sas_ss_flags(cpu->sp), current->sas_ss_size,
				     fault_addr, esr);
	if (!err && copy_to_user((void __user *)frame, buf, KEMU_SIGFRAME_SIZE))
		err = -EFAULT;
	kfree(buf);
	if (err)
		return err;

	rec[0] = cpu->x[29];
	rec[1] = cpu->x[30];
	if (copy_to_user((void __user *)next_frame, rec, sizeof(rec)))
		return -EFAULT;
	if (current->sas_ss_flags & SS_AUTODISARM)
		sas_ss_reset(current);

	cpu->x[0] = sig;
	if (ksig->ka.sa.sa_flags & SA_SIGINFO) {
		cpu->x[1] = frame;
		cpu->x[2] = frame + KEMU_SIGINFO_SIZE;
	}
	cpu->sp = frame;
	cpu->x[29] = next_frame;
	cpu->x[30] = kemu_sigtramp(ksig);
	cpu->pc = (unsigned long)ksig->ka.sa.sa_handler;
	cpu->excl_addr = ~0ULL;
	kemu_redirect(kt);
	return 0;
}

void kemu_do_signal(struct pt_regs *regs)
{
	struct kemu_thread *kt = current->kemu;
	struct kemu_cpu *cpu = kt->cpu;
	bool syscall = kt->flags & KEMU_TF_IN_SVC;
	u64 continuation = cpu->pc, restart = continuation - 4;
	long retval = 0;
	struct ksignal ksig;

	kemu_materialize(regs);
	if (kemu_debug)
		pr_info("kemu: %s[%d] signal pending %lx at pc %llx (host ip %lx trap %ld cr2 %lx err %lx) x0=%llx sp=%llx lr=%llx\n",
			current->comm, task_pid_nr(current), current->pending.signal.sig[0],
			cpu->pc, regs->ip, current->thread.trap_nr, current->thread.cr2,
			current->thread.error_code, cpu->x[0], cpu->sp, cpu->x[30]);
	if (kemu_debug) {
		u64 fp = cpu->x[29], fr[2];
		int i;

		for (i = 0; i < 10 && fp && !copy_from_user(fr, (void __user *)fp, 16); i++) {
			pr_info("kemu:   frame %d: ret %llx (fp %llx)\n", i, fr[1], fp);
			fp = fr[0];
		}
		pr_info("kemu:   x1=%llx x2=%llx x19=%llx x20=%llx x21=%llx\n",
			cpu->x[1], cpu->x[2], cpu->x[19], cpu->x[20], cpu->x[21]);
		if (sigismember(&current->pending.signal, SIGILL)) {
			u32 w = 0;

			if (!get_user(w, (u32 __user *)cpu->pc))
				pr_info("kemu:   SIGILL insn %08x\n", w);
		}
	}

	if (syscall) {
		retval = (long)cpu->x[0];
		kt->flags &= ~KEMU_TF_IN_SVC;
		regs->orig_ax = -1;
		switch (retval) {
		case -ERESTARTNOHAND:
		case -ERESTARTSYS:
		case -ERESTARTNOINTR:
		case -ERESTART_RESTARTBLOCK:
			cpu->x[0] = kt->orig_x0;
			cpu->pc = restart;
			break;
		}
	}

	if (get_signal(&ksig)) {
		if (kemu_debug)
			pr_info("kemu: %s[%d] sig %d code %d addr %px at pc %llx (host ip %lx) x0=%llx sp=%llx lr=%llx\n",
				current->comm, task_pid_nr(current), ksig.sig, ksig.info.si_code,
				ksig.info.si_addr, cpu->pc, regs->ip, cpu->x[0], cpu->sp, cpu->x[30]);
		if (syscall && cpu->pc == restart &&
		    (retval == -ERESTARTNOHAND ||
		     retval == -ERESTART_RESTARTBLOCK ||
		     (retval == -ERESTARTSYS &&
		      !(ksig.ka.sa.sa_flags & SA_RESTART)))) {
			cpu->x[0] = -EINTR;
			cpu->pc = continuation;
		}
		signal_setup_done(kemu_setup_rt_frame(&ksig, sigmask_to_save()),
				  &ksig, 0);
		return;
	}

	if (syscall && cpu->pc == restart && retval == -ERESTART_RESTARTBLOCK)
		cpu->x[8] = KEMU_NR_restart_syscall;

	restore_saved_sigmask();
}

long kemu_sys_rt_sigreturn(struct pt_regs *regs)
{
	struct kemu_thread *kt = current->kemu;
	struct kemu_cpu *cpu = kt->cpu;
	unsigned long frame = cpu->sp;
	sigset_t set;
	u64 mask;
	u8 *buf;
	int err;

	/* Always make any pending restarted system calls return -EINTR. */
	current->restart_block.fn = do_no_restart_syscall;
	kt->flags &= ~KEMU_TF_IN_SVC;

	if (frame & 15)
		goto badframe;
	buf = kmalloc(KEMU_SIGFRAME_SIZE, GFP_KERNEL);
	if (!buf)
		goto badframe;
	if (copy_from_user(buf, (void __user *)frame, KEMU_SIGFRAME_SIZE)) {
		kfree(buf);
		goto badframe;
	}
	kt->shadow = *cpu;
	err = kemu_rs_restore_ucontext(buf + KEMU_SIGINFO_SIZE, KEMU_UCONTEXT_SIZE,
				       &kt->shadow, &mask);
	kfree(buf);
	if (err)
		goto badframe;

	set.sig[0] = mask;
	set_current_blocked(&set);
	if (restore_altstack((stack_t __user *)(frame + KEMU_SIGINFO_SIZE +
						 KEMU_UC_STACK_OFF)))
		goto badframe;

	*cpu = kt->shadow;
	cpu->excl_addr = ~0ULL;
	kemu_redirect(kt);
	return cpu->x[0];

badframe:
	force_sig(SIGSEGV);
	kemu_redirect(kt);
	return 0;
}
