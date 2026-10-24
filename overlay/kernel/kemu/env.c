// SPDX-License-Identifier: GPL-2.0
/*
 * kemu: guest memory and host services for the Rust core (kemu_rs.rs).
 * Guest virtual addresses are host user virtual addresses.
 */

#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/mmap_lock.h>
#include <linux/highmem.h>
#include <linux/random.h>
#include <asm/tsc.h>
#include <asm/archrandom.h>

#include "kemu_internal.h"

int kemu_c_read(u64 addr, void *buf, size_t len)
{
	return copy_from_user(buf, (const void __user *)addr, len) ? -EFAULT : 0;
}

int kemu_c_write(u64 addr, const void *buf, size_t len)
{
	return copy_to_user((void __user *)addr, buf, len) ? -EFAULT : 0;
}

/* Refresh the cached executable range containing @pc. */
static int kemu_fetch_check(struct kemu_thread *kt, unsigned long pc)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned int seq;
	int ret = -EFAULT;

	kt->fetch_valid = false;
	if (mmap_read_lock_killable(mm))
		return -EFAULT;
	vma = vma_lookup(mm, pc);
	if (vma) {
		ret = -EACCES;
		if (vma->vm_flags & VM_EXEC) {
			ret = 0;
			if (mmap_lock_speculate_try_begin(mm, &seq)) {
				kt->fetch_start = vma->vm_start;
				kt->fetch_end = vma->vm_end;
				kt->fetch_seq = seq;
				kt->fetch_valid = true;
			}
		}
	}
	mmap_read_unlock(mm);
	return ret;
}

int kemu_c_fetch(u64 pc, u32 *out)
{
	struct kemu_thread *kt = current->kemu;
	int ret;

	if (!kt->fetch_valid || pc < kt->fetch_start || pc + 4 > kt->fetch_end ||
	    mmap_lock_speculate_retry(current->mm, kt->fetch_seq)) {
		ret = kemu_fetch_check(kt, pc);
		if (ret)
			return ret;
	}
	return get_user(*out, (u32 __user *)pc) ? -EFAULT : 0;
}

static int kemu_cmpxchg128(u64 addr, const u64 *exp, const u64 *new, u64 *old)
{
	struct page *page;
	u128 *p, o, e, n;
	void *kaddr;
	int ret;

	ret = get_user_pages_fast(addr & PAGE_MASK, 1, FOLL_WRITE, &page);
	if (ret != 1)
		return -EFAULT;
	kaddr = kmap_local_page(page);
	p = kaddr + (addr & ~PAGE_MASK);
	e = ((u128)exp[1] << 64) | exp[0];
	n = ((u128)new[1] << 64) | new[0];
	o = e;
	try_cmpxchg128(p, &o, n);
	kunmap_local(kaddr);
	set_page_dirty_lock(page);
	put_page(page);
	old[0] = (u64)o;
	old[1] = (u64)(o >> 64);
	return 0;
}

/*
 * Atomic compare-and-exchange on guest memory. Returns 0 and the old value
 * on success (whether or not the exchange happened), -EINVAL for
 * misaligned addresses and -EFAULT for inaccessible ones.
 */
int kemu_c_cmpxchg(u64 addr, u32 size, const u64 *exp, const u64 *new, u64 *old)
{
	if (size == 0 || size > 16 || (size & (size - 1)) || (addr & (size - 1)))
		return -EINVAL;
	old[1] = 0;
	if (size == 16)
		return kemu_cmpxchg128(addr, exp, new, old);

	if (!user_access_begin((void __user *)addr, size))
		return -EFAULT;
	switch (size) {
	case 1: {
		u8 o = exp[0];

		unsafe_try_cmpxchg_user((u8 __user *)addr, &o, (u8)new[0], efault);
		old[0] = o;
		break;
	}
	case 2: {
		u16 o = exp[0];

		unsafe_try_cmpxchg_user((u16 __user *)addr, &o, (u16)new[0], efault);
		old[0] = o;
		break;
	}
	case 4: {
		u32 o = exp[0];

		unsafe_try_cmpxchg_user((u32 __user *)addr, &o, (u32)new[0], efault);
		old[0] = o;
		break;
	}
	case 8: {
		u64 o = exp[0];

		unsafe_try_cmpxchg_user((u64 __user *)addr, &o, new[0], efault);
		old[0] = o;
		break;
	}
	}
	user_access_end();
	return 0;
efault:
	user_access_end();
	return -EFAULT;
}

/*
 * CNTVCT_EL0/CNTFRQ_EL0 are the TSC, scaled down if needed so that the
 * frequency fits CNTFRQ_EL0's 32 bits.
 */
static unsigned int kemu_cnt_shift(void)
{
	u64 f = (u64)tsc_khz * 1000;
	unsigned int s = 0;

	while ((f >> s) > U32_MAX)
		s++;
	return s;
}

u64 kemu_c_cntvct(void)
{
	return rdtsc_ordered() >> kemu_cnt_shift();
}

u64 kemu_c_cntfrq(void)
{
	return ((u64)tsc_khz * 1000) >> kemu_cnt_shift();
}

bool kemu_c_random(u64 *out)
{
	unsigned long v;

	if (rdrand_long(&v)) {
		*out = v;
		return true;
	}
	return false;
}
