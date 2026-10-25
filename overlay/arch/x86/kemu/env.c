// SPDX-License-Identifier: GPL-2.0
/* Native x86 host services for kemu. */
#include <linux/kemu.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <asm/tsc.h>
#include <asm/archrandom.h>

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
 * on success (whether or not the exchange happened), or -EFAULT for
 * inaccessible addresses. The common layer validates size and alignment.
 */
int kemu_arch_cmpxchg(u64 addr, u32 size, const u64 *exp, const u64 *new, u64 *old)
{
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

u64 kemu_arch_cntvct(void)
{
	return rdtsc_ordered() >> kemu_cnt_shift();
}

u64 kemu_arch_cntfrq(void)
{
	return ((u64)tsc_khz * 1000) >> kemu_cnt_shift();
}

bool kemu_arch_random(u64 *out)
{
	unsigned long v;

	if (rdrand_long(&v)) {
		*out = v;
		return true;
	}
	return false;
}
