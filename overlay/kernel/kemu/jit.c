// SPDX-License-Identifier: GPL-2.0
/*
 * kemu: code cache management for the JIT (DESIGN.md §10).
 *
 * Translated blocks are appended to 1 MiB vmalloc'd chunks that are mapped
 * read-only/executable into the guest's address space. Chunk 0 holds only
 * the user-mode stubs. Every block start is recorded in a per-chunk
 * bitmap so a host PC can be mapped back to its block (and from there,
 * using the block's metadata, to the exact guest state).
 *
 * Invalidation (IC IVAU) flushes the whole cache: live chunks are retired
 * and only freed once every thread of the mm has returned to user mode
 * past the flush (and fixed up any stale host PC on the way).
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/bitmap.h>

#include "kemu_internal.h"

bool kemu_jit_enabled = true;
int kemu_debug;

static int __init kemu_debug_setup(char *str)
{
	return kstrtoint(str, 0, &kemu_debug) == 0;
}
__setup("kemu.debug=", kemu_debug_setup);

static int __init kemu_jit_setup(char *str)
{
	return kstrtobool(str, &kemu_jit_enabled) == 0;
}
__setup("kemu.jit=", kemu_jit_setup);

static unsigned long kemu_table_mask8(void)
{
	return (KEMU_TABLE_ENTRIES - 1) << 3;
}

/* Called from kemu_setup_mm with the stub chunk allocated. */
int kemu_jit_init(struct kemu_mm *km)
{
	unsigned long *t = km->table;
	unsigned long miss;
	int i, err;

	err = kemu_rs_gen_stubs(km->chunks[0], KEMU_STUBS_SIZE, km->table_base,
				kemu_table_mask8(), &km->stubs);
	if (err)
		return err;
	km->chunk_used[0] = KEMU_STUBS_SIZE;
	km->cur_chunk = -1;
	miss = kemu_stub(km, km->stubs.miss);
	for (i = 0; i < KEMU_TABLE_ENTRIES; i++)
		t[i] = miss;
	km->scratch = kvzalloc(kemu_rs_scratch_size(), GFP_KERNEL_ACCOUNT);
	return km->scratch ? 0 : -ENOMEM;
}

static void kemu_chunk_free(struct kemu_mm *km, int c)
{
	vfree(km->chunks[c]);
	kvfree(km->blockmap[c]);
	km->chunks[c] = NULL;
	km->blockmap[c] = NULL;
	km->chunk_used[c] = 0;
	km->chunk_retired[c] = 0;
}

void kemu_jit_free(struct kemu_mm *km)
{
	int c;

	for (c = 1; c < KEMU_MAX_CHUNKS; c++)
		kemu_chunk_free(km, c);
	xa_destroy(&km->blocks);
	kvfree(km->scratch);
	km->scratch = NULL;
}

/* ---- threads / epochs ---- */

static u64 kemu_min_epoch_seen(struct kemu_mm *km)
{
	struct kemu_thread *kt;
	u64 min = km->epoch;

	spin_lock(&km->threads_lock);
	list_for_each_entry(kt, &km->threads, node)
		min = min_t(u64, min, READ_ONCE(kt->epoch_seen));
	spin_unlock(&km->threads_lock);
	return min;
}

/* Free retired chunks no thread can still be executing in. */
static void kemu_reclaim(struct kemu_mm *km)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	u64 min = kemu_min_epoch_seen(km);
	int c;

	for (c = 1; c < KEMU_MAX_CHUNKS; c++)
		if (km->chunk_retired[c] && km->chunk_retired[c] <= min)
			break;
	if (c == KEMU_MAX_CHUNKS)
		return;

	mmap_read_lock(mm);
	down_write(&km->chunk_sem);
	vma = vma_lookup(mm, km->code_base);
	for (c = 1; c < KEMU_MAX_CHUNKS; c++) {
		if (!km->chunk_retired[c] || km->chunk_retired[c] > min)
			continue;
		if (vma)
			zap_vma_ptes(vma, km->code_base + c * KEMU_CHUNK_SIZE,
				     KEMU_CHUNK_SIZE);
		kemu_chunk_free(km, c);
	}
	up_write(&km->chunk_sem);
	mmap_read_unlock(mm);
}

/* Flush every translation of the mm. km->lock held. */
void kemu_jit_flush(struct kemu_mm *km)
{
	unsigned long *t = km->table;
	unsigned long miss = kemu_stub(km, km->stubs.miss);
	struct kemu_thread *kt;
	int c, i;

	km->epoch++;
	km->flushes++;
	for (i = 0; i < KEMU_TABLE_ENTRIES; i++)
		WRITE_ONCE(t[i], miss);
	xa_destroy(&km->blocks);
	for (c = 1; c < KEMU_MAX_CHUNKS; c++)
		if (km->chunks[c] && !km->chunk_retired[c])
			km->chunk_retired[c] = km->epoch;
	km->cur_chunk = -1;

	/* Make every other thread pass through the kernel to fix up. */
	spin_lock(&km->threads_lock);
	list_for_each_entry(kt, &km->threads, node)
		if (kt->task != current)
			kick_process(kt->task);
	spin_unlock(&km->threads_lock);
}

/* Start a fresh chunk. km->lock held. */
static int kemu_chunk_new(struct kemu_mm *km)
{
	void *mem;
	unsigned long *bm;
	int c;

	kemu_reclaim(km);
	for (c = 1; c < KEMU_MAX_CHUNKS; c++)
		if (!km->chunks[c])
			break;
	if (c == KEMU_MAX_CHUNKS) {
		/* Out of code space: flush; a later call can reclaim. */
		kemu_jit_flush(km);
		return -EAGAIN;
	}
	mem = __vmalloc(KEMU_CHUNK_SIZE, GFP_KERNEL_ACCOUNT);
	bm = kvzalloc(BITS_TO_LONGS(KEMU_BLOCKMAP_BITS) * sizeof(long),
		      GFP_KERNEL_ACCOUNT);
	if (!mem || !bm) {
		vfree(mem);
		kvfree(bm);
		return -ENOMEM;
	}
	down_write(&km->chunk_sem);
	km->blockmap[c] = bm;
	km->chunk_used[c] = 0;
	km->chunk_retired[c] = 0;
	WRITE_ONCE(km->chunks[c], mem);
	up_write(&km->chunk_sem);
	km->cur_chunk = c;
	return 0;
}

/* ---- block lookup ---- */

/*
 * Find the block containing code-region offset @off (in a live or retired
 * chunk). Returns the kernel address of the block start and its size.
 */
static u8 *kemu_find_block(struct kemu_mm *km, unsigned long off, size_t *len)
{
	unsigned long c = off >> KEMU_CHUNK_SHIFT, in = off & (KEMU_CHUNK_SIZE - 1);
	unsigned long bit;
	u64 gpc;
	u32 main;
	size_t sz;
	u8 *blk;

	if (c == 0 || c >= KEMU_MAX_CHUNKS || !km->chunks[c] || in >= km->chunk_used[c])
		return NULL;
	bit = find_last_bit(km->blockmap[c], in / KEMU_BLOCK_ALIGN + 1);
	if (bit > in / KEMU_BLOCK_ALIGN)
		return NULL;
	blk = km->chunks[c] + bit * KEMU_BLOCK_ALIGN;
	sz = kemu_rs_block_info(blk, km->chunk_used[c] - bit * KEMU_BLOCK_ALIGN, &gpc, &main);
	if (!sz || in >= bit * KEMU_BLOCK_ALIGN + sz)
		return NULL;
	*len = sz;
	return blk;
}

/* Insert/refresh the lookup-table entry for a block. */
static void kemu_table_set(struct kemu_mm *km, u64 pc, unsigned long check)
{
	unsigned long *t = km->table;

	WRITE_ONCE(t[(pc >> 2) & (KEMU_TABLE_ENTRIES - 1)], check);
}

/*
 * Return the main entry (user address) of the translation of @pc,
 * translating it if needed. km->lock held.
 */
static int kemu_translate(struct kemu_mm *km, u64 pc, unsigned long *main,
			  struct kemu_trans *res)
{
	void *v = xa_load(&km->blocks, pc >> 2);
	unsigned long off, uaddr;
	int c, err, tries = 0;
	u64 gpc;
	u32 moff;
	u8 *out;

	if (pc & 3)
		return -EINVAL;
	if (v) {
		off = xa_to_value(v);
		c = off >> KEMU_CHUNK_SHIFT;
		if (!kemu_rs_block_info(km->chunks[c] + (off & (KEMU_CHUNK_SIZE - 1)),
					km->chunk_used[c] - (off & (KEMU_CHUNK_SIZE - 1)),
					&gpc, &moff) || gpc != pc)
			return -EIO;
		kemu_table_set(km, pc, km->code_base + off + 32);
		*main = km->code_base + off + moff;
		return 0;
	}

	for (;;) {
		if (km->cur_chunk < 0) {
			err = kemu_chunk_new(km);
			if (err == -EAGAIN && tries++ < 2)
				continue;
			if (err)
				return err;
		}
		c = km->cur_chunk;
		out = km->chunks[c] + km->chunk_used[c];
		uaddr = km->code_base + c * KEMU_CHUNK_SIZE + km->chunk_used[c];
		err = kemu_rs_translate(km->scratch, pc, out,
					KEMU_CHUNK_SIZE - km->chunk_used[c], uaddr,
					km->code_base, &km->stubs, res);
		if (err == -ENOSPC && km->chunk_used[c] > 0 && tries++ < 4) {
			km->cur_chunk = -1;
			continue;
		}
		if (err)
			return err;
		break;
	}
	off = c * KEMU_CHUNK_SIZE + km->chunk_used[c];
	set_bit(km->chunk_used[c] / KEMU_BLOCK_ALIGN, km->blockmap[c]);
	km->chunk_used[c] += ALIGN(res->size, KEMU_BLOCK_ALIGN);
	err = xa_err(xa_store(&km->blocks, pc >> 2, xa_mk_value(off), GFP_KERNEL));
	if (err)
		return err;
	km->translations++;
	kemu_table_set(km, pc, km->code_base + off + res->check_off);
	*main = km->code_base + off + res->main_off;
	return 0;
}

/* Patch a block exit (rel32 at user address @site) to jump to @main. */
static void kemu_chain(struct kemu_mm *km, unsigned long site, u64 target,
		       unsigned long main)
{
	unsigned long off;
	u8 *blk;
	size_t len;
	u64 t;
	s64 rel;

	if (site < km->code_base || site >= km->code_base + KEMU_CODE_SIZE || (site & 3))
		return;
	off = site - km->code_base;
	blk = kemu_find_block(km, off, &len);
	if (!blk || km->chunk_retired[off >> KEMU_CHUNK_SHIFT])
		return;
	if (!kemu_rs_find_exit(blk, len, ((u8 *)km->chunks[off >> KEMU_CHUNK_SHIFT] +
					   (off & (KEMU_CHUNK_SIZE - 1))) - blk, &t) ||
	    t != target)
		return;
	rel = (s64)main - (s64)(site + 4);
	if (rel != (s32)rel)
		return;
	WRITE_ONCE(*(u32 *)((u8 *)km->chunks[off >> KEMU_CHUNK_SHIFT] +
			    (off & (KEMU_CHUNK_SIZE - 1))), (u32)(s32)rel);
	km->chains++;
}

/* ---- kernel <-> translated-code state ---- */

/* Entering a kemu op from user stubs: page becomes authoritative. */
void kemu_enter_op(struct kemu_thread *kt)
{
	struct kemu_cpu *cpu = kt->cpu;

	if (kt->flags & KEMU_TF_KSTATE)
		return;
	cpu->nzcv = kemu_rs_nzcv_from_image(READ_ONCE(cpu->flags_x86));
	kt->flags |= KEMU_TF_KSTATE;
}

static void kemu_host_regs(struct pt_regs *regs, struct kemu_host_regs *h)
{
	h->gpr[0] = regs->ax;
	h->gpr[1] = regs->cx;
	h->gpr[2] = regs->dx;
	h->gpr[3] = regs->bx;
	h->gpr[4] = regs->sp;
	h->gpr[5] = regs->bp;
	h->gpr[6] = regs->si;
	h->gpr[7] = regs->di;
	h->gpr[8] = regs->r8;
	h->gpr[9] = regs->r9;
	h->gpr[10] = regs->r10;
	h->gpr[11] = regs->r11;
	h->gpr[12] = regs->r12;
	h->gpr[13] = regs->r13;
	h->gpr[14] = regs->r14;
	h->gpr[15] = regs->r15;
	h->rflags = regs->flags;
}

static u32 kemu_stub_info(struct kemu_mm *km, u32 off)
{
	u32 i;

	for (i = 0; i < km->stubs.nranges && i < 16; i++)
		if (off >= km->stubs.ranges[i][0] && off < km->stubs.ranges[i][1])
			return km->stubs.ranges[i][2];
	return KEMU_STUB_PAGE_STATE;
}

/*
 * Make the state page authoritative for a thread interrupted (not via a
 * kemu op) while running stubs or translated code.
 */
void kemu_materialize(struct pt_regs *regs)
{
	struct kemu_thread *kt = current->kemu;
	struct kemu_mm *km = current->mm->kemu;
	struct kemu_cpu *cpu = kt->cpu;
	struct kemu_host_regs h;
	unsigned long ip = regs->ip, off;
	u8 *blk;
	size_t len;

	if (kt->flags & KEMU_TF_KSTATE)
		goto out;
	kemu_host_regs(regs, &h);
	kt->shadow = *cpu;
	if (ip >= km->code_base && ip < km->code_base + KEMU_STUBS_SIZE) {
		switch (kemu_stub_info(km, ip - km->code_base)) {
		case KEMU_STUB_PINNED_LIVE_PC_RAX:
			kt->shadow.pc = regs->ax;
			fallthrough;
		case KEMU_STUB_PINNED_LIVE:
			kemu_rs_pinned_from_host(&h, &kt->shadow);
			break;
		default:
			break;
		}
		kt->shadow.nzcv = kemu_rs_nzcv_from_image(kt->shadow.flags_x86);
	} else if (ip >= km->code_base && ip < km->code_base + KEMU_CODE_SIZE) {
		off = ip - km->code_base;
		blk = kemu_find_block(km, off, &len);
		if (!blk || !kemu_rs_recover(blk, len,
					     ((u8 *)km->chunks[off >> KEMU_CHUNK_SHIFT] +
					      (off & (KEMU_CHUNK_SIZE - 1))) - blk,
					     &h, &kt->shadow)) {
			pr_warn_ratelimited("kemu: %s[%d]: cannot recover state at %lx\n",
					    current->comm, task_pid_nr(current), ip);
			force_sig(SIGKILL);
		}
	} else {
		/* Interpreter mode keeps the page authoritative at all times. */
		kt->shadow.nzcv = kemu_rs_nzcv_from_image(kt->shadow.flags_x86);
	}
	*cpu = kt->shadow;
	kt->flags |= KEMU_TF_KSTATE;
out:
	kemu_redirect(kt);
}

/*
 * Called on every exit to user mode (IRQs off). Converts the state back to
 * the translated-code representation and fixes up threads that may still
 * reference code retired by a flush.
 */
void kemu_jit_exit_to_user(struct kemu_thread *kt, struct pt_regs *regs)
{
	struct kemu_mm *km = current->mm->kemu;
	u64 epoch = READ_ONCE(km->epoch);

	if (kt->epoch_seen != epoch) {
		if (!(kt->flags & KEMU_TF_KSTATE) && regs->ip >= km->code_base &&
		    regs->ip < km->code_base + KEMU_CODE_SIZE)
			kemu_materialize(regs);
		else
			kemu_redirect(kt);
		WRITE_ONCE(kt->epoch_seen, epoch);
	}
	if (kt->flags & KEMU_TF_KSTATE) {
		kt->cpu->flags_x86 = kemu_rs_image_from_nzcv(kt->cpu->nzcv);
		kt->flags &= ~KEMU_TF_KSTATE;
	}
}

/* ---- kemu ops from stubs ---- */

static unsigned long kemu_op_translate(struct kemu_thread *kt, struct kemu_mm *km,
				       bool chain)
{
	struct kemu_trans res = {};
	u64 pc = kt->cpu->pc;
	unsigned long main;
	int err;

	mutex_lock(&km->lock);
	err = kemu_translate(km, pc, &main, &res);
	if (!err && chain)
		kemu_chain(km, kt->cpu->exit_info, pc, main);
	mutex_unlock(&km->lock);

	switch (err) {
	case 0:
		return main;
	case -EFAULT:
		kemu_force_fault(res.fault_addr, KEMU_ACCESS_EXEC, false);
		break;
	case -EINVAL:
		kemu_force_fault(pc, KEMU_ACCESS_EXEC, true);
		break;
	default:
		/* Couldn't translate (e.g. ENOMEM): interpret a little. */
		return kemu_interp(kt, km, 256);
	}
	kemu_redirect(kt);
	return kemu_stub(km, km->stubs.dispatch);
}

static void kemu_op_helper(struct kemu_thread *kt, struct kemu_mm *km)
{
	struct kemu_rs_exit ex;
	u64 pc = kt->cpu->pc;

	km->helpers++;
	kt->shadow = *kt->cpu;
	kemu_rs_interp(&kt->shadow, 1, &ex);
	*kt->cpu = kt->shadow;
	switch (ex.kind) {
	case KEMU_EXIT_BUDGET:
		if (kt->cpu->pc != pc + 4)
			kemu_redirect(kt);
		return;
	case KEMU_EXIT_ICINV:
		mutex_lock(&km->lock);
		kemu_jit_flush(km);
		mutex_unlock(&km->lock);
		kemu_redirect(kt);
		return;
	case KEMU_EXIT_BRK:
		force_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *)kt->cpu->pc);
		break;
	case KEMU_EXIT_UNDEF:
		force_sig_fault(SIGILL, ILL_ILLOPC, (void __user *)kt->cpu->pc);
		break;
	case KEMU_EXIT_FAULT:
		kemu_force_fault(ex.addr, ex.access, ex.aux);
		break;
	default:
		break;
	}
	kemu_redirect(kt);
}

/* PTRACE_SINGLESTEP: execute one guest instruction, then trap. */
unsigned long kemu_op_step(struct kemu_thread *kt, struct kemu_mm *km)
{
	struct kemu_rs_exit ex;

	kt->shadow = *kt->cpu;
	kemu_rs_interp(&kt->shadow, 1, &ex);
	*kt->cpu = kt->shadow;
	kemu_redirect(kt);
	switch (ex.kind) {
	case KEMU_EXIT_SVC:
		kt->flags |= KEMU_TF_STEP_SVC;
		kt->flags &= ~KEMU_TF_REDIRECT;
		return kemu_stub(km, km->stubs.interp_svc);
	case KEMU_EXIT_BRK:
		force_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *)kt->cpu->pc);
		break;
	case KEMU_EXIT_UNDEF:
		force_sig_fault(SIGILL, ILL_ILLOPC, (void __user *)kt->cpu->pc);
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
		fallthrough;
	default:
		force_sig_fault(SIGTRAP, TRAP_TRACE, (void __user *)kt->cpu->pc);
		break;
	}
	return kemu_stub(km, km->stubs.dispatch);
}

/* Handle a non-svc kemu op in JIT mode; returns the value for %rax. */
unsigned long kemu_jit_op(struct pt_regs *regs, unsigned long op)
{
	struct kemu_thread *kt = current->kemu;
	struct kemu_mm *km = current->mm->kemu;

	switch (op) {
	case KEMU_OP_STEP:
		return kemu_op_step(kt, km);
	case KEMU_OP_TRANSLATE:
		return kemu_op_translate(kt, km, false);
	case KEMU_OP_CHAIN:
		return kemu_op_translate(kt, km, true);
	case KEMU_OP_HELPER:
		kemu_op_helper(kt, km);
		return 0;
	}
	force_sig(SIGSYS);
	kemu_redirect(kt);
	return kemu_stub(km, km->stubs.dispatch);
}

/* Fork: copy live chunks, block map and lookup table into the child. */
int kemu_jit_dup(struct kemu_mm *okm, struct kemu_mm *km)
{
	unsigned long idx;
	void *v;
	int c;

	km->scratch = kvzalloc(kemu_rs_scratch_size(), GFP_KERNEL_ACCOUNT);
	if (!km->scratch)
		return -ENOMEM;
	km->stubs = okm->stubs;
	km->epoch = okm->epoch;
	km->cur_chunk = -1;
	for (c = 1; c < KEMU_MAX_CHUNKS; c++) {
		if (!okm->chunks[c] || okm->chunk_retired[c])
			continue;
		km->chunks[c] = __vmalloc(KEMU_CHUNK_SIZE, GFP_KERNEL_ACCOUNT);
		km->blockmap[c] = kvmalloc(BITS_TO_LONGS(KEMU_BLOCKMAP_BITS) * sizeof(long),
					   GFP_KERNEL_ACCOUNT);
		if (!km->chunks[c] || !km->blockmap[c])
			return -ENOMEM;
		memcpy(km->chunks[c], okm->chunks[c], okm->chunk_used[c]);
		memcpy(km->blockmap[c], okm->blockmap[c],
		       BITS_TO_LONGS(KEMU_BLOCKMAP_BITS) * sizeof(long));
		km->chunk_used[c] = okm->chunk_used[c];
		if (c == okm->cur_chunk)
			km->cur_chunk = c;
	}
	xa_for_each(&okm->blocks, idx, v) {
		unsigned long off = xa_to_value(v);

		if (!km->chunks[off >> KEMU_CHUNK_SHIFT])
			continue;
		if (xa_err(xa_store(&km->blocks, idx, v, GFP_KERNEL)))
			return -ENOMEM;
	}
	/* Table entries may point at retired chunks; start clean. */
	{
		unsigned long *t = km->table, miss = kemu_stub(km, km->stubs.miss);
		int i;

		for (i = 0; i < KEMU_TABLE_ENTRIES; i++)
			t[i] = miss;
	}
	return 0;
}
