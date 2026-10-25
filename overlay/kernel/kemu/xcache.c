// SPDX-License-Identifier: GPL-2.0
/*
 * kemu: shared translation cache for file-backed code (DESIGN.md §10.4).
 *
 * Blocks translated from non-writable file mappings are produced in
 * relocatable mode and a copy is kept here, keyed by (superblock, inode,
 * generation, file offset). Another process (or a later exec) executing
 * the same file offset gets the block by memcpy + relocation instead of
 * retranslating. Before reuse, every guest instruction word the
 * translation depended on is re-read at the new address and compared
 * (kemu_rs_xc_validate), so a modified file or patched text just misses.
 *
 * The cache is global, bounded by kemu.xcache_mb (default 128, LRU), and reclaimable
 * through a shrinker.
 */
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/mm.h>
#include <linux/refcount.h>
#include <linux/shrinker.h>
#include <linux/slab.h>

#include "kemu_internal.h"

struct kemu_xc_entry {
	struct hlist_node hnode;
	struct list_head lru;
	refcount_t ref;
	struct kemu_xc_key key;
	u32 code_len;
	u32 blob_len;
	u32 main_off;
	u32 check_off;
	u32 ninsns;
	u8 data[];		/* code_len bytes of code, then the blob */
};

static bool kemu_xc_enabled = true;
static unsigned long kemu_xc_limit = 128UL << 20;

static int __init kemu_xc_setup(char *str)
{
	return kstrtobool(str, &kemu_xc_enabled) == 0;
}
__setup("kemu.xcache=", kemu_xc_setup);

static int __init kemu_xc_mb_setup(char *str)
{
	unsigned long mb;

	if (kstrtoul(str, 0, &mb))
		return 0;
	kemu_xc_limit = mb << 20;
	return 1;
}
__setup("kemu.xcache_mb=", kemu_xc_mb_setup);

static DEFINE_MUTEX(kemu_xc_lock);
static DEFINE_HASHTABLE(kemu_xc_hash, 12);
static LIST_HEAD(kemu_xc_lru);
static unsigned long kemu_xc_bytes, kemu_xc_count;
atomic_long_t kemu_xc_hits, kemu_xc_misses, kemu_xc_stale;

static u32 kemu_xc_hashkey(const struct kemu_xc_key *k)
{
	return jhash2((const u32 *)k, sizeof(*k) / sizeof(u32), 0);
}

static void kemu_xc_put(struct kemu_xc_entry *e)
{
	if (refcount_dec_and_test(&e->ref))
		kvfree(e);
}

/* kemu_xc_lock held. */
static void kemu_xc_unlink(struct kemu_xc_entry *e)
{
	hash_del(&e->hnode);
	list_del(&e->lru);
	kemu_xc_bytes -= sizeof(*e) + e->code_len + e->blob_len;
	kemu_xc_count--;
	kemu_xc_put(e);
}

/* kemu_xc_lock held. */
static struct kemu_xc_entry *kemu_xc_find(const struct kemu_xc_key *k)
{
	struct kemu_xc_entry *e;

	hash_for_each_possible(kemu_xc_hash, e, hnode, kemu_xc_hashkey(k))
		if (!memcmp(&e->key, k, sizeof(*k)))
			return e;
	return NULL;
}

/*
 * The cache key for guest @pc, if it lies in a non-writable file mapping.
 * Called with km->lock held (same lock order as instruction fetch).
 */
bool kemu_xc_key(u64 pc, struct kemu_xc_key *k)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	struct inode *inode;
	bool ok = false;

	if (!kemu_xc_enabled)
		return false;
	if (mmap_read_lock_killable(mm))
		return false;
	vma = vma_lookup(mm, pc);
	if (vma && vma->vm_file && !(vma->vm_flags & (VM_WRITE | VM_SHARED)) &&
	    (vma->vm_flags & VM_EXEC)) {
		inode = file_inode(vma->vm_file);
		memset(k, 0, sizeof(*k));
		k->sb = (unsigned long)inode->i_sb;
		k->ino = inode->i_ino;
		k->gen = inode->i_generation;
		k->off = ((u64)vma->vm_pgoff << PAGE_SHIFT) + (pc - vma->vm_start);
		ok = true;
	}
	mmap_read_unlock(mm);
	return ok;
}

/*
 * Copy a cached translation of @pc (key @k) to @out (user address
 * @blk_off from the code base). Returns the block size, or 0 on a miss.
 */
size_t kemu_xc_lookup(const struct kemu_xc_key *k, u64 pc, u8 *out, size_t avail,
		      unsigned long blk_off, struct kemu_trans *res, u64 *pages, int *npages)
{
	struct kemu_xc_entry *e;
	size_t ret = 0;

	mutex_lock(&kemu_xc_lock);
	e = kemu_xc_find(k);
	if (e) {
		refcount_inc(&e->ref);
		list_move_tail(&e->lru, &kemu_xc_lru);
	}
	mutex_unlock(&kemu_xc_lock);
	if (!e) {
		atomic_long_inc(&kemu_xc_misses);
		return 0;
	}
	if (e->code_len > avail)
		goto out;
	if (!kemu_rs_xc_validate(e->data + e->code_len, e->blob_len, pc)) {
		atomic_long_inc(&kemu_xc_stale);
		goto out;
	}
	memcpy(out, e->data, e->code_len);
	if (!kemu_rs_xc_apply(e->data + e->code_len, e->blob_len, out, e->code_len,
			      pc, blk_off))
		goto out;
	res->size = e->code_len;
	res->main_off = e->main_off;
	res->check_off = e->check_off;
	res->ninsns = e->ninsns;
	*npages = kemu_rs_xc_pages(e->data + e->code_len, e->blob_len, pc, pages,
				   KEMU_MAX_PAGES);
	ret = e->code_len;
	atomic_long_inc(&kemu_xc_hits);
out:
	kemu_xc_put(e);
	return ret;
}

/* Remember a relocatable translation just made for @pc (key @k). */
void kemu_xc_insert(const struct kemu_xc_key *k, void *scratch, u64 pc,
		    const u8 *code, const struct kemu_trans *res,
		    unsigned long blk_off)
{
	struct kemu_xc_entry *e, *old;
	long blen = kemu_rs_xc_blob_size(scratch);
	size_t sz;

	if (blen < 0 || res->size > U32_MAX)
		return;
	sz = sizeof(*e) + res->size + blen;
	e = kvmalloc(sz, GFP_KERNEL);
	if (!e)
		return;
	if (kemu_rs_xc_blob(scratch, pc, blk_off, e->data + res->size, blen) != blen) {
		kvfree(e);
		return;
	}
	memcpy(e->data, code, res->size);
	refcount_set(&e->ref, 1);
	e->key = *k;
	e->code_len = res->size;
	e->blob_len = blen;
	e->main_off = res->main_off;
	e->check_off = res->check_off;
	e->ninsns = res->ninsns;

	mutex_lock(&kemu_xc_lock);
	old = kemu_xc_find(k);
	if (old)
		kemu_xc_unlink(old);
	hash_add(kemu_xc_hash, &e->hnode, kemu_xc_hashkey(k));
	list_add_tail(&e->lru, &kemu_xc_lru);
	kemu_xc_bytes += sz;
	kemu_xc_count++;
	while (kemu_xc_bytes > kemu_xc_limit && !list_empty(&kemu_xc_lru))
		kemu_xc_unlink(list_first_entry(&kemu_xc_lru, struct kemu_xc_entry, lru));
	mutex_unlock(&kemu_xc_lock);
}

static unsigned long kemu_xc_count_objects(struct shrinker *s, struct shrink_control *sc)
{
	return READ_ONCE(kemu_xc_count) ?: SHRINK_EMPTY;
}

static unsigned long kemu_xc_scan_objects(struct shrinker *s, struct shrink_control *sc)
{
	unsigned long freed = 0;

	if (!mutex_trylock(&kemu_xc_lock))
		return SHRINK_STOP;
	while (freed < sc->nr_to_scan && !list_empty(&kemu_xc_lru)) {
		kemu_xc_unlink(list_first_entry(&kemu_xc_lru, struct kemu_xc_entry, lru));
		freed++;
	}
	mutex_unlock(&kemu_xc_lock);
	return freed;
}

void kemu_xc_stats(unsigned long *entries, unsigned long *bytes)
{
	*entries = READ_ONCE(kemu_xc_count);
	*bytes = READ_ONCE(kemu_xc_bytes);
}

int __init kemu_xc_init(void)
{
	struct shrinker *s;

	s = shrinker_alloc(0, "kemu-xcache");
	if (!s)
		return -ENOMEM;
	s->count_objects = kemu_xc_count_objects;
	s->scan_objects = kemu_xc_scan_objects;
	s->seeks = DEFAULT_SEEKS;
	shrinker_register(s);
	return 0;
}
