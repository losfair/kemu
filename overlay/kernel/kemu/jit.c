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
 * Invalidation is targeted: every block records the guest pages it read
 * instructions from (its own page plus flag look-ahead into exit targets),
 * and IC IVAU or the loss of an executable mapping removes just the blocks
 * on the affected pages: out of the lookup table and block index, with
 * jumps chained into them restored. Their code stays in place, so threads
 * still inside them are unaffected; the epoch bump sends every thread back
 * through the dispatcher at its next kernel exit.
 *
 * When code space runs out, the whole cache is flushed: live chunks are
 * retired and only freed once no thread can be executing in them (see
 * kemu_min_epoch_seen).
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task_stack.h>
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

/*
 * Debug: kemu.stress=<n> bumps the epoch and kicks every other thread once
 * per n translations, so that threads are interrupted and their state is
 * recovered (kemu_materialize) at arbitrary points in translated code.
 */
static unsigned int kemu_stress;

static int __init kemu_stress_setup(char *str)
{
	return kstrtouint(str, 0, &kemu_stress) == 0;
}
__setup("kemu.stress=", kemu_stress_setup);

/* Debug: kemu.jitoff=<mask> disables JIT features (see t1::JIT_OFF). */
static u32 kemu_jit_off;

static int __init kemu_jit_off_setup(char *str)
{
	if (kstrtou32(str, 0, &kemu_jit_off))
		return 0;
	kemu_rs_set_jit_off(kemu_jit_off);
	return 1;
}
__setup("kemu.jitoff=", kemu_jit_off_setup);

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

static void kemu_inval_free(struct kemu_mm *km);

static void kemu_chunk_free(struct kemu_mm *km, int c)
{
	void *mem = km->chunks[c];
	unsigned long *bm = km->blockmap[c];

	WRITE_ONCE(km->chunks[c], NULL);
	WRITE_ONCE(km->blockmap[c], NULL);
	km->chunk_used[c] = 0;
	/*
	 * kemu_materialize() reads chunk_retired locklessly and then trusts
	 * the pointers of a live (0) chunk: clear them first.
	 */
	smp_store_release(&km->chunk_retired[c], 0);
	vfree(mem);
	kvfree(bm);
}

void kemu_jit_free(struct kemu_mm *km)
{
	int c;

	for (c = 1; c < KEMU_MAX_CHUNKS; c++)
		kemu_chunk_free(km, c);
	xa_destroy(&km->blocks);
	kemu_inval_free(km);
	xa_destroy(&km->tbi_pcs);
	kvfree(km->scratch);
	km->scratch = NULL;
}

/* ---- threads / epochs ---- */

/*
 * Can @kt still need code retired before the current epoch? The epoch
 * check in kemu_jit_exit_to_user() runs after the last reschedule point,
 * with IRQs off. So a thread that is current (in a kemu op), or switched
 * out with its guest state already in the state page (blocked in a guest
 * syscall or op), re-reads the epoch and is redirected to the dispatcher
 * before it runs guest code again, without looking at old blocks.
 * Without this, one thread sleeping in futex() would pin every retired
 * chunk. A thread interrupted inside translated code still pins them
 * (kemu_materialize() reads the block's metadata), but it is runnable.
 */
static bool kemu_thread_pins_code(struct kemu_mm *km, struct kemu_thread *kt)
{
	unsigned long ip;

	if (kt->task == current)
		return false;
	if (task_curr(kt->task))
		return true;
	if (READ_ONCE(kt->flags) & KEMU_TF_KSTATE)
		return false;
	ip = kemu_reg(task_pt_regs(kt->task), ip);
	return ip >= km->code_base + KEMU_CHUNK_SIZE && ip < km->code_base + KEMU_CODE_SIZE;
}

static u64 kemu_min_epoch_seen(struct kemu_mm *km)
{
	struct kemu_thread *kt;
	u64 min = km->epoch;

	/* Order the epoch bump before sampling which tasks are running. */
	smp_mb();
	spin_lock(&km->threads_lock);
	list_for_each_entry(kt, &km->threads, node)
		if (kemu_thread_pins_code(km, kt))
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

/* ---- targeted invalidation (all with km->lock held) ---- */

/* Append @off to *@pv, reallocating; *@pv is only replaced on success. */
static struct kemu_pgvec *kemu_pgvec_add(struct kemu_pgvec *v, u32 off)
{
	struct kemu_pgvec *n;
	u32 cap;

	if (v && v->n < v->cap) {
		v->off[v->n++] = off;
		return v;
	}
	cap = v ? v->cap * 2 : 4;
	n = kmalloc(struct_size(n, off, cap), GFP_KERNEL_ACCOUNT);
	if (!n)
		return NULL;
	n->n = v ? v->n : 0;
	n->cap = cap;
	if (v)
		memcpy(n->off, v->off, v->n * sizeof(u32));
	n->off[n->n++] = off;
	return n;
}

static int kemu_blk_register(struct kemu_mm *km, u32 off, u64 pc, u32 size,
			     const u64 *pages, int npages)
{
	struct kemu_blkinfo *bi = kzalloc(sizeof(*bi), GFP_KERNEL_ACCOUNT);
	struct kemu_pgvec *v, *n;
	unsigned long idx;
	int i;

	if (!bi)
		return -ENOMEM;
	bi->pc = pc;
	bi->off = off;
	bi->size = size;
	if (xa_err(xa_store(&km->binfo, off / KEMU_BLOCK_ALIGN, bi, GFP_KERNEL_ACCOUNT))) {
		kfree(bi);
		return -ENOMEM;
	}
	if (npages < 0) {
		n = kemu_pgvec_add(km->wide, off);
		if (!n)
			goto fail;
		if (n != km->wide)
			kfree(km->wide);
		km->wide = n;
		return 0;
	}
	for (i = 0; i < npages; i++) {
		idx = pages[i] >> PAGE_SHIFT;
		v = xa_load(&km->pages, idx);
		n = kemu_pgvec_add(v, off);
		if (!n)
			goto fail;
		if (n != v) {
			if (xa_err(xa_store(&km->pages, idx, n, GFP_KERNEL_ACCOUNT))) {
				kfree(n);
				goto fail;
			}
			kfree(v);
		}
	}
	return 0;
fail:
	/* Index entries already added just name a dead offset. */
	xa_erase(&km->binfo, off / KEMU_BLOCK_ALIGN);
	kfree(bi);
	return -ENOMEM;
}

static u32 *kemu_site_ptr(struct kemu_mm *km, u32 site)
{
	unsigned long c = site >> KEMU_CHUNK_SHIFT;

	if (c == 0 || c >= KEMU_MAX_CHUNKS || !km->chunks[c] || km->chunk_retired[c])
		return NULL;
	return (u32 *)((u8 *)km->chunks[c] + (site & (KEMU_CHUNK_SIZE - 1)));
}

/* Remove a block from the lookup structures and unchain jumps into it. */
static void kemu_blk_kill(struct kemu_mm *km, u32 off)
{
	struct kemu_blkinfo *bi = xa_erase(&km->binfo, off / KEMU_BLOCK_ALIGN);
	unsigned long *t = km->table, lo, hi, e;
	u32 i, *p;
	void *v;

	if (!bi)
		return;
	v = xa_load(&km->blocks, bi->pc >> 2);
	if (v && xa_to_value(v) == off)
		xa_erase(&km->blocks, bi->pc >> 2);
	lo = km->code_base + off;
	hi = lo + bi->size;
	i = (bi->pc >> 2) & (KEMU_TABLE_ENTRIES - 1);
	e = READ_ONCE(t[i]);
	if (e >= lo && e < hi)
		WRITE_ONCE(t[i], kemu_stub(km, km->stubs.miss));
	for (i = 0; i < bi->nin; i++) {
		p = kemu_site_ptr(km, bi->in[i].site);
		v = xa_load(&km->sites, bi->in[i].site);
		/* Only if it still jumps here (an IC site may have moved on). */
		if (p && v && READ_ONCE(*p) == bi->in[i].val)
			WRITE_ONCE(*p, (u32)xa_to_value(v));
	}
	kfree(bi->in);
	kfree(bi);
	km->killed++;
}

/* Remove every translation that read instructions in [lo, hi). */
void kemu_jit_invalidate(struct kemu_mm *km, u64 lo, u64 hi)
{
	unsigned long idx, killed = km->killed;
	struct kemu_pgvec *v;
	u32 i;

	if (lo >= hi)
		return;
	km->invals++;
	xa_for_each_range(&km->pages, idx, v, lo >> PAGE_SHIFT, (hi - 1) >> PAGE_SHIFT) {
		xa_erase(&km->pages, idx);
		for (i = 0; i < v->n; i++)
			kemu_blk_kill(km, v->off[i]);
		kfree(v);
	}
	if (km->wide) {
		for (i = 0; i < km->wide->n; i++)
			kemu_blk_kill(km, km->wide->off[i]);
		kfree(km->wide);
		km->wide = NULL;
	}
	/* Send threads back through the dispatcher (see kemu_jit_flush). */
	if (km->killed != killed)
		smp_store_release(&km->epoch, km->epoch + 1);
}

/* Apply invalidations recorded by kemu_unmapped(). */
void kemu_jit_pending(struct kemu_mm *km)
{
	u64 lo, hi;

	spin_lock(&km->pend_lock);
	if (!atomic_xchg(&km->flush_pending, 0)) {
		spin_unlock(&km->pend_lock);
		return;
	}
	lo = km->pend_lo;
	hi = km->pend_hi;
	spin_unlock(&km->pend_lock);
	mutex_lock(&km->lock);
	kemu_jit_invalidate(km, lo, hi);
	mutex_unlock(&km->lock);
}

static void kemu_inval_free(struct kemu_mm *km)
{
	struct kemu_blkinfo *bi;
	struct kemu_pgvec *v;
	unsigned long idx;

	xa_for_each(&km->binfo, idx, bi) {
		kfree(bi->in);
		kfree(bi);
	}
	xa_destroy(&km->binfo);
	xa_for_each(&km->pages, idx, v)
		kfree(v);
	xa_destroy(&km->pages);
	xa_destroy(&km->sites);
	kfree(km->wide);
	km->wide = NULL;
}

/* Fork: copy the invalidation index along with the code. */
static int kemu_inval_dup(struct kemu_mm *okm, struct kemu_mm *km)
{
	struct kemu_blkinfo *bi, *nb;
	struct kemu_pgvec *v, *nv;
	unsigned long idx;
	void *e;

	xa_for_each(&okm->binfo, idx, bi) {
		nb = kmemdup(bi, sizeof(*bi), GFP_KERNEL_ACCOUNT);
		if (!nb)
			return -ENOMEM;
		nb->in = bi->cap ? kmemdup_array(bi->in, bi->cap, sizeof(*bi->in),
						 GFP_KERNEL_ACCOUNT) : NULL;
		if ((bi->cap && !nb->in) ||
		    xa_err(xa_store(&km->binfo, idx, nb, GFP_KERNEL_ACCOUNT))) {
			kfree(nb->in);
			kfree(nb);
			return -ENOMEM;
		}
	}
	xa_for_each(&okm->pages, idx, v) {
		nv = kmemdup(v, struct_size(v, off, v->cap), GFP_KERNEL_ACCOUNT);
		if (!nv || xa_err(xa_store(&km->pages, idx, nv, GFP_KERNEL_ACCOUNT))) {
			kfree(nv);
			return -ENOMEM;
		}
	}
	if (okm->wide) {
		km->wide = kmemdup(okm->wide, struct_size(okm->wide, off, okm->wide->cap),
				   GFP_KERNEL_ACCOUNT);
		if (!km->wide)
			return -ENOMEM;
	}
	xa_for_each(&okm->sites, idx, e)
		if (xa_err(xa_store(&km->sites, idx, e, GFP_KERNEL_ACCOUNT)))
			return -ENOMEM;
	return 0;
}

/* Flush every translation of the mm. km->lock held. */
void kemu_jit_flush(struct kemu_mm *km)
{
	unsigned long *t = km->table;
	unsigned long miss = kemu_stub(km, km->stubs.miss);
	struct kemu_thread *kt;
	u64 epoch = km->epoch + 1;
	int c, i;

	km->flushes++;
	for (i = 0; i < KEMU_TABLE_ENTRIES; i++)
		WRITE_ONCE(t[i], miss);
	xa_destroy(&km->blocks);
	kemu_inval_free(km);
	for (c = 1; c < KEMU_MAX_CHUNKS; c++)
		if (km->chunks[c] && !km->chunk_retired[c])
			km->chunk_retired[c] = epoch;
	km->cur_chunk = -1;
	/*
	 * Publish the epoch only now. A thread that sees it in
	 * kemu_jit_exit_to_user() is sent to the dispatcher, which must then
	 * find only the reset table; otherwise it could enter a retired
	 * chunk while claiming the new epoch, and kemu_reclaim() would free
	 * the chunk under it.
	 */
	smp_store_release(&km->epoch, epoch);

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
		/*
		 * Out of code space: flush (unless everything is already
		 * retired and just waiting for running threads to pass
		 * through the kernel); a later call can reclaim.
		 */
		for (c = 1; c < KEMU_MAX_CHUNKS; c++)
			if (km->chunks[c] && !km->chunk_retired[c])
				break;
		if (c < KEMU_MAX_CHUNKS)
			kemu_jit_flush(km);
		return -EAGAIN;
	}
	/*
	 * Zeroed: kemu_code_fault() maps every page of a live chunk, including
	 * the unused tail and the padding between blocks.
	 */
	mem = __vmalloc(KEMU_CHUNK_SIZE, GFP_KERNEL_ACCOUNT | __GFP_ZERO);
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
	/* Publish the blockmap with the chunk (kemu_materialize is lockless). */
	smp_store_release(&km->chunks[c], mem);
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
	u8 *chunk, *blk;

	if (c == 0 || c >= KEMU_MAX_CHUNKS)
		return NULL;
	chunk = smp_load_acquire(&km->chunks[c]);
	if (!chunk || in >= km->chunk_used[c])
		return NULL;
	bit = find_last_bit(km->blockmap[c], in / KEMU_BLOCK_ALIGN + 1);
	if (bit > in / KEMU_BLOCK_ALIGN)
		return NULL;
	blk = chunk + bit * KEMU_BLOCK_ALIGN;
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
	struct kemu_xc_key key;
	unsigned long off, uaddr;
	u64 pages[KEMU_MAX_PAGES];
	bool cacheable, tbi;
	int c, err, tries = 0, npages = -1;
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
		kemu_table_set(km, pc, km->code_base + off + KEMU_BLK_CHECK_OFF);
		*main = km->code_base + off + moff;
		res->ic_entry = km->code_base + off + KEMU_BLK_IC_OFF;
		res->blk_off = off;
		return 0;
	}

	/* Blocks that keep faulting on tagged pointers mask addresses (TBI). */
	tbi = xa_load(&km->tbi_pcs, pc >> 2) != NULL;
	cacheable = !tbi && kemu_xc_key(pc, &key);
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
		if (cacheable && kemu_xc_lookup(&key, pc, out,
						KEMU_CHUNK_SIZE - km->chunk_used[c],
						uaddr - km->code_base, res, pages, &npages)) {
			km->xc_hits++;
			break;
		}
		err = kemu_rs_translate(km->scratch, pc, out,
					KEMU_CHUNK_SIZE - km->chunk_used[c], uaddr,
					km->code_base, &km->stubs, res, cacheable, tbi,
					KEMU_ARCH_VECTOR_CACHE);
		if (err == -ENOSPC && km->chunk_used[c] > 0 && tries++ < 4) {
			km->cur_chunk = -1;
			continue;
		}
		if (err)
			return err;
		npages = kemu_rs_trans_pages(km->scratch, pages, KEMU_MAX_PAGES);
		if (cacheable)
			kemu_xc_insert(&key, km->scratch, pc, out, res,
				       uaddr - km->code_base);
		break;
	}
	off = c * KEMU_CHUNK_SIZE + km->chunk_used[c];
	err = kemu_blk_register(km, off, pc, res->size, pages, npages);
	if (err)
		return err;
	set_bit(km->chunk_used[c] / KEMU_BLOCK_ALIGN, km->blockmap[c]);
	km->chunk_used[c] += ALIGN(res->size, KEMU_BLOCK_ALIGN);
	err = xa_err(xa_store(&km->blocks, pc >> 2, xa_mk_value(off), GFP_KERNEL));
	if (err)
		return err;
	km->translations++;
	kemu_table_set(km, pc, km->code_base + off + res->check_off);
	*main = km->code_base + off + res->main_off;
	res->ic_entry = km->code_base + off + KEMU_BLK_IC_OFF;
	res->blk_off = off;
	return 0;
}

/* Patch a block exit (rel32 at user address @site) to jump to @main. */
static void kemu_chain(struct kemu_mm *km, unsigned long site, u64 target,
		       unsigned long main, unsigned long ic_entry, u32 blk_off)
{
	struct kemu_blkinfo *bi = xa_load(&km->binfo, blk_off / KEMU_BLOCK_ALIGN);
	struct kemu_chain_site *in;
	unsigned long off;
	u32 *p, cur;
	u8 *blk;
	size_t len;
	u64 t;
	u32 kind;
	s64 rel;

	if (site < km->code_base || site >= km->code_base + KEMU_CODE_SIZE || (site & 3) ||
	    (kemu_jit_off & 8))
		return;
	off = site - km->code_base;
	blk = kemu_find_block(km, off, &len);
	if (!blk || km->chunk_retired[off >> KEMU_CHUNK_SHIFT])
		return;
	if (!kemu_rs_find_exit(blk, len, ((u8 *)km->chunks[off >> KEMU_CHUNK_SHIFT] +
					   (off & (KEMU_CHUNK_SIZE - 1))) - blk, &t, &kind))
		return;
	if (kind == KEMU_EXIT_KIND_IC)
		main = ic_entry;	/* the IC entry re-checks the target */
	else if (t != target)
		return;
	rel = (s64)main - (s64)(site + 4);
	if (rel != (s32)rel || !bi)
		return;
	/* Record the jump so invalidating the target can undo it. */
	if (bi->nin == bi->cap) {
		u32 cap = bi->cap ? bi->cap * 2 : 2;

		in = krealloc_array(bi->in, cap, sizeof(*in), GFP_KERNEL_ACCOUNT);
		if (!in)
			return;
		bi->in = in;
		bi->cap = cap;
	}
	p = (u32 *)((u8 *)km->chunks[off >> KEMU_CHUNK_SHIFT] + (off & (KEMU_CHUNK_SIZE - 1)));
	cur = READ_ONCE(*p);
	if (!xa_load(&km->sites, off) &&
	    xa_err(xa_store(&km->sites, off, xa_mk_value(cur), GFP_KERNEL_ACCOUNT)))
		return;
	bi->in[bi->nin].site = off;
	bi->in[bi->nin].val = (u32)(s32)rel;
	bi->nin++;
	WRITE_ONCE(*p, (u32)(s32)rel);
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
	cpu->fpsr = kemu_rs_fpsr_merge(cpu->fpsr, cpu->scratch[KEMU_MXCSR_SLOT]);
	kt->flags |= KEMU_TF_KSTATE;
}

static u32 kemu_host_regs(struct pt_regs *regs, struct kemu_host_regs *h)
{
	h->gpr[0] = kemu_reg(regs, ax);
	h->gpr[1] = kemu_reg(regs, cx);
	h->gpr[2] = kemu_reg(regs, dx);
	h->gpr[3] = kemu_reg(regs, bx);
	h->gpr[4] = kemu_reg(regs, sp);
	h->gpr[5] = kemu_reg(regs, bp);
	h->gpr[6] = kemu_reg(regs, si);
	h->gpr[7] = kemu_reg(regs, di);
	h->gpr[8] = kemu_reg(regs, r8);
	h->gpr[9] = kemu_reg(regs, r9);
	h->gpr[10] = kemu_reg(regs, r10);
	h->gpr[11] = kemu_reg(regs, r11);
	h->gpr[12] = kemu_reg(regs, r12);
	h->gpr[13] = kemu_reg(regs, r13);
	h->gpr[14] = kemu_reg(regs, r14);
	h->gpr[15] = kemu_reg(regs, r15);
	h->rflags = kemu_reg(regs, flags);
#if KEMU_ARCH_VECTOR_CACHE
	return kemu_arch_read_fpu(h->xmm);
#else
	memset(h->xmm, 0, sizeof(h->xmm));
	return 0;
#endif
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
	unsigned long ip = kemu_reg(regs, ip), off, c;
	u8 *blk;
	size_t len;
	u32 mxcsr;

	if (kt->flags & KEMU_TF_KSTATE)
		goto out;
	mxcsr = kemu_host_regs(regs, &h);
	kt->shadow = *cpu;
	if (ip >= km->code_base && ip < km->code_base + KEMU_STUBS_SIZE) {
		u32 info = kemu_stub_info(km, ip - km->code_base);

		kemu_rs_recover_stub(info, &h, &kt->shadow);
		/* During reload (or after rt_sigreturn), live MXCSR can still
		 * describe the previous state. Use the page when authoritative. */
		if (info == KEMU_STUB_PAGE_STATE || info == KEMU_STUB_PAGE_STATE_SVC)
			mxcsr = cpu->scratch[KEMU_MXCSR_SLOT];
	} else if (ip >= km->code_base && ip < km->code_base + KEMU_CODE_SIZE) {
		u64 retired;

		off = ip - km->code_base;
		c = off >> KEMU_CHUNK_SHIFT;
		/*
		 * A chunk retired in an epoch this thread has already
		 * acknowledged is not pinned by it (kemu_min_epoch_seen), so
		 * another thread's kemu_reclaim() may free it under us. Correct
		 * code never runs there: acknowledging an epoch resets the host
		 * return stack. Only a forged return address gets here.
		 */
		retired = smp_load_acquire(&km->chunk_retired[c]);
		blk = retired && retired <= kt->epoch_seen ? NULL : kemu_find_block(km, off, &len);
		if (!blk || !kemu_rs_recover(blk, len,
					     ((u8 *)km->chunks[off >> KEMU_CHUNK_SHIFT] +
					      (off & (KEMU_CHUNK_SIZE - 1))) - blk,
					     &h, &kt->shadow)) {
			pr_warn_ratelimited("kemu: %s[%d]: cannot recover state at %lx (chunk %lu %s retired %llu used %x; epoch %llu seen %llu flags %lx)\n",
					    current->comm, task_pid_nr(current), ip, c,
					    km->chunks[c] ? "live" : "freed", km->chunk_retired[c],
					    km->chunk_used[c], km->epoch, kt->epoch_seen, kt->flags);
			force_sig(SIGKILL);
		}
	} else {
		/* Interpreter mode keeps the page authoritative at all times. */
		kt->shadow.nzcv = kemu_rs_nzcv_from_image(kt->shadow.flags_x86);
		mxcsr = cpu->scratch[KEMU_MXCSR_SLOT];
	}
	/* Stubs may not have spilled MXCSR yet. Preserve live cumulative
	 * exceptions before exit_to_user rebuilds MXCSR from FPSR. */
	kt->shadow.fpsr = kemu_rs_fpsr_merge(kt->shadow.fpsr, mxcsr);
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
	u64 epoch = smp_load_acquire(&km->epoch);

	if (kt->epoch_seen != epoch) {
		if (!(kt->flags & KEMU_TF_KSTATE) && kemu_reg(regs, ip) >= km->code_base &&
		    kemu_reg(regs, ip) < km->code_base + KEMU_CODE_SIZE)
			kemu_materialize(regs);
		else
			kemu_redirect(kt);
		WRITE_ONCE(kt->epoch_seen, epoch);
	}
	if (kt->flags & KEMU_TF_KSTATE) {
		kt->cpu->flags_x86 = kemu_rs_image_from_nzcv(kt->cpu->nzcv);
		kt->cpu->scratch[KEMU_MXCSR_SLOT] =
			kemu_rs_mxcsr_from(kt->cpu->fpcr, kt->cpu->fpsr);
		kt->flags &= ~KEMU_TF_KSTATE;
	}
}

/*
 * #GP in translated code: a non-canonical data address. On arm64 that is a
 * tagged pointer (TBI ignores the top byte) or an address beyond the VA
 * range (a translation fault). Untagged code runs without masking, so run
 * the instruction in the interpreter, which applies TBI, and either carry
 * on or deliver the fault as arm64 would. Blocks that do this often are
 * retranslated with address masking.
 */
#define KEMU_TBI_RETRANSLATE	8

bool kemu_user_gp(struct pt_regs *regs)
{
	struct kemu_thread *kt = current->kemu;
	struct kemu_mm *km = current->mm->kemu;
	unsigned long ip = kemu_reg(regs, ip), off, boff;
	struct kemu_blkinfo *bi;
	struct kemu_rs_exit ex;
	size_t len;
	u8 *blk;

	if (!kt || !km || ip < km->code_base + KEMU_CHUNK_SIZE ||
	    ip >= km->code_base + KEMU_CODE_SIZE)
		return false;
	off = ip - km->code_base;
	kemu_materialize(regs);

	mutex_lock(&km->lock);
	blk = kemu_find_block(km, off, &len);
	if (blk) {
		boff = (off & ~(KEMU_CHUNK_SIZE - 1)) +
		       (blk - (u8 *)km->chunks[off >> KEMU_CHUNK_SHIFT]);
		bi = xa_load(&km->binfo, boff / KEMU_BLOCK_ALIGN);
		if (bi && ++bi->tbi_faults >= KEMU_TBI_RETRANSLATE &&
		    !xa_err(xa_store(&km->tbi_pcs, bi->pc >> 2, xa_mk_value(1), GFP_KERNEL)))
			kemu_blk_kill(km, boff);
	}
	mutex_unlock(&km->lock);

	kt->shadow = *kt->cpu;
	kemu_rs_interp(&kt->shadow, 1, &ex);
	switch (ex.kind) {
	case KEMU_EXIT_BUDGET:
		*kt->cpu = kt->shadow;
		km->tbi_emul++;
		return true;
	case KEMU_EXIT_FAULT:
		kemu_force_fault(ex.addr, ex.access, ex.aux);
		return true;
	default:
		return false;
	}
}

/* ---- kemu ops from stubs ---- */

static unsigned long kemu_op_translate(struct kemu_thread *kt, struct kemu_mm *km,
				       bool chain)
{
	struct kemu_trans res = {};
	u64 pc = kt->cpu->pc;
	u64 t0 = ktime_get_ns();
	unsigned long main;
	int err;

	mutex_lock(&km->lock);
	err = kemu_translate(km, pc, &main, &res);
	/*
	 * The exit site was produced in the epoch this thread last entered
	 * user mode in; after a flush its chunk may be freed or even reused
	 * (kemu_reclaim() doesn't wait for threads that are in the kernel).
	 */
	if (!err && chain && kt->epoch_seen == km->epoch)
		kemu_chain(km, kt->cpu->exit_info, pc, main, res.ic_entry, res.blk_off);
	km->lookups++;
	if (kemu_stress && km->lookups % kemu_stress == 0) {
		struct kemu_thread *o;

		smp_store_release(&km->epoch, km->epoch + 1);
		spin_lock(&km->threads_lock);
		list_for_each_entry(o, &km->threads, node)
			if (o->task != current)
				kick_process(o->task);
		spin_unlock(&km->threads_lock);
	}
	km->translate_ns += ktime_get_ns() - t0;
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
		kemu_jit_invalidate(km, ex.addr, ex.addr + 1);
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
			kemu_jit_invalidate(km, ex.addr, ex.addr + 1);
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
		km->chunks[c] = __vmalloc(KEMU_CHUNK_SIZE, GFP_KERNEL_ACCOUNT | __GFP_ZERO);
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
	if (kemu_inval_dup(okm, km))
		return -ENOMEM;
	/* Table entries may point at retired chunks; start clean. */
	{
		unsigned long *t = km->table, miss = kemu_stub(km, km->stubs.miss);
		int i;

		for (i = 0; i < KEMU_TABLE_ENTRIES; i++)
			t[i] = miss;
	}
	return 0;
}
