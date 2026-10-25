// SPDX-License-Identifier: GPL-2.0
/*
 * kemu: guest memory and host services for the Rust core (kemu_rs.rs).
 * Guest virtual addresses are host user virtual addresses.
 */

#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/mmap_lock.h>

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

/* Validate the atomic access before entering the architecture backend. */
int kemu_c_cmpxchg(u64 addr, u32 size, const u64 *exp, const u64 *new, u64 *old)
{
	if (!size || size > 16 || (size & (size - 1)) || (addr & (size - 1)))
		return -EINVAL;
	old[1] = 0;
	return kemu_arch_cmpxchg(addr, size, exp, new, old);
}

u64 kemu_c_cntvct(void)
{
	return kemu_arch_cntvct();
}

u64 kemu_c_cntfrq(void)
{
	return kemu_arch_cntfrq();
}

bool kemu_c_random(u64 *out)
{
	return kemu_arch_random(out);
}
