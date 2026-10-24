// SPDX-License-Identifier: GPL-2.0
/*
 * kemu: per-mm region (stubs, code cache, lookup table, thread slots) and
 * task/mm lifecycle.
 *
 * The region is made of three special mappings whose pages belong to the
 * mm's struct kemu_mm. They are VM_PFNMAP mappings populated on demand by
 * our fault handlers; after fork the child's copies of the PTEs are zapped
 * so the child faults in its own (copied) pages.
 */

#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/binfmts.h>
#include <linux/sched/task_stack.h>
#include <linux/sched/mm.h>
#include <linux/random.h>
#include <linux/elf.h>
#include <linux/highmem.h>
#include <linux/ptrace.h>
#include <asm/processor.h>
#include <asm/proto.h>
#include <asm/prctl.h>

#include "kemu_internal.h"

DEFINE_STATIC_KEY_FALSE(kemu_active_key);

static struct kmem_cache *kemu_thread_cache;

/* ---- fault handlers ---- */

static vm_fault_t kemu_insert(struct vm_area_struct *vma, struct vm_fault *vmf,
			      unsigned long pfn)
{
	return vmf_insert_pfn(vma, vmf->address, pfn);
}

static vm_fault_t kemu_code_fault(const struct vm_special_mapping *sm,
				  struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct kemu_mm *km = vma->vm_mm->kemu;
	unsigned long off = vmf->pgoff << PAGE_SHIFT;
	unsigned long c = off >> KEMU_CHUNK_SHIFT;
	void *chunk;

	if (!km || c >= KEMU_MAX_CHUNKS)
		return VM_FAULT_SIGBUS;
	chunk = READ_ONCE(km->chunks[c]);
	if (!chunk)
		return VM_FAULT_SIGBUS;
	return kemu_insert(vma, vmf,
			   vmalloc_to_pfn(chunk + (off & (KEMU_CHUNK_SIZE - 1))));
}

static vm_fault_t kemu_table_fault(const struct vm_special_mapping *sm,
				   struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct kemu_mm *km = vma->vm_mm->kemu;
	unsigned long off = vmf->pgoff << PAGE_SHIFT;

	if (!km || !km->table || off >= KEMU_TABLE_SIZE)
		return VM_FAULT_SIGBUS;
	return kemu_insert(vma, vmf, vmalloc_to_pfn(km->table + off));
}

static vm_fault_t kemu_slots_fault(const struct vm_special_mapping *sm,
				   struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct kemu_mm *km = vma->vm_mm->kemu;
	unsigned long slot = vmf->pgoff / KEMU_THREAD_SLOT_PAGES;
	unsigned long pg = vmf->pgoff % KEMU_THREAD_SLOT_PAGES;
	struct kemu_slot *s;
	struct page *page;

	if (!km)
		return VM_FAULT_SIGBUS;
	if (pg == KEMU_SLOT_STATE_PG)
		pg = 0;
	else if (pg >= KEMU_SLOT_RSTACK_PG && pg < KEMU_SLOT_RSTACK_TOP_PG)
		pg = pg - KEMU_SLOT_RSTACK_PG + 1;
	else
		return VM_FAULT_SIGSEGV;	/* guard page */

	s = xa_load(&km->slots, slot);
	if (!s)
		return VM_FAULT_SIGSEGV;
	page = s->pages[pg];
	return kemu_insert(vma, vmf, page_to_pfn(page));
}

static int kemu_mremap(const struct vm_special_mapping *sm,
		       struct vm_area_struct *new_vma)
{
	return -EINVAL;
}

static const struct vm_special_mapping kemu_code_mapping = {
	.name = "[kemu-code]",
	.fault = kemu_code_fault,
	.mremap = kemu_mremap,
};

static const struct vm_special_mapping kemu_table_mapping = {
	.name = "[kemu-table]",
	.fault = kemu_table_fault,
	.mremap = kemu_mremap,
};

/*
 * Guest-visible trampoline page used as the return address of signal
 * handlers (arm64's vDSO sigtramp): mov x8, #__NR_rt_sigreturn; svc #0.
 */
static struct page *kemu_tramp_pages[2];

static const struct vm_special_mapping kemu_tramp_mapping = {
	.name = "[vdso]",
	.pages = kemu_tramp_pages,
	.mremap = kemu_mremap,
};

static const struct vm_special_mapping kemu_slots_mapping = {
	.name = "[kemu-slots]",
	.fault = kemu_slots_fault,
	.mremap = kemu_mremap,
};

/* ---- kemu_mm ---- */

static struct kemu_mm *kemu_mm_alloc(void)
{
	struct kemu_mm *km = kzalloc(sizeof(*km), GFP_KERNEL_ACCOUNT);

	if (!km)
		return NULL;
	mutex_init(&km->lock);
	xa_init(&km->slots);
	ida_init(&km->slot_ida);
	return km;
}

static void kemu_mm_free(struct kemu_mm *km)
{
	struct kemu_slot *s;
	unsigned long idx;
	int i;

	xa_for_each(&km->slots, idx, s) {
		for (i = 0; i < KEMU_SLOT_USED_PAGES; i++)
			if (s->pages[i])
				__free_page(s->pages[i]);
		kfree(s);
	}
	xa_destroy(&km->slots);
	ida_destroy(&km->slot_ida);
	for (i = 0; i < KEMU_MAX_CHUNKS; i++)
		vfree(km->chunks[i]);
	vfree(km->table);
	kfree(km);
}

static void *kemu_chunk_alloc(void)
{
	return __vmalloc(KEMU_CHUNK_SIZE, GFP_KERNEL_ACCOUNT | __GFP_ZERO);
}

static struct kemu_slot *kemu_slot_alloc_pages(void)
{
	struct kemu_slot *s = kzalloc(sizeof(*s), GFP_KERNEL_ACCOUNT);
	int i;

	if (!s)
		return NULL;
	for (i = 0; i < KEMU_SLOT_USED_PAGES; i++) {
		s->pages[i] = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
		if (!s->pages[i])
			goto fail;
	}
	return s;
fail:
	while (i--)
		__free_page(s->pages[i]);
	kfree(s);
	return NULL;
}

/* Allocate a free slot index (and its pages if first use). */
static int kemu_slot_get(struct kemu_mm *km)
{
	struct kemu_slot *s;
	int idx, err;

	idx = ida_alloc_max(&km->slot_ida, KEMU_MAX_THREADS - 1, GFP_KERNEL);
	if (idx < 0)
		return idx;
	if (xa_load(&km->slots, idx))
		return idx;	/* reuse pages from an exited thread */
	s = kemu_slot_alloc_pages();
	if (!s) {
		ida_free(&km->slot_ida, idx);
		return -ENOMEM;
	}
	err = xa_err(xa_store(&km->slots, idx, s, GFP_KERNEL));
	if (err) {
		int i;

		ida_free(&km->slot_ida, idx);
		for (i = 0; i < KEMU_SLOT_USED_PAGES; i++)
			__free_page(s->pages[i]);
		kfree(s);
		return err;
	}
	return idx;
}

static unsigned long kemu_slot_base(struct kemu_mm *km, int slot)
{
	return km->slots_base + (unsigned long)slot * KEMU_SLOT_SIZE;
}

static struct kemu_cpu *kemu_slot_cpu(struct kemu_mm *km, int slot)
{
	struct kemu_slot *s = xa_load(&km->slots, slot);

	return s ? page_address(s->pages[0]) : NULL;
}

/* ---- kemu_thread ---- */

static struct kemu_thread *kemu_thread_new(struct kemu_mm *km, int slot)
{
	struct kemu_thread *kt;

	kt = kmem_cache_zalloc(kemu_thread_cache, GFP_KERNEL_ACCOUNT);
	if (!kt)
		return NULL;
	kt->slot = slot;
	kt->cpu = kemu_slot_cpu(km, slot);
	kt->cpu_uaddr = kemu_slot_base(km, slot) + KEMU_SLOT_STATE_PG * PAGE_SIZE;
	kt->rstack_top = kemu_slot_base(km, slot) + KEMU_SLOT_RSTACK_TOP_PG * PAGE_SIZE;
	kt->cpu->host_rsp_top = kt->rstack_top;
	return kt;
}

static void kemu_thread_free(struct kemu_mm *km, struct kemu_thread *kt)
{
	if (km)
		ida_free(&km->slot_ida, kt->slot);
	kmem_cache_free(kemu_thread_cache, kt);
}

void kemu_redirect(struct kemu_thread *kt)
{
	kt->flags |= KEMU_TF_REDIRECT;
}

/* ---- exec ---- */

/*
 * Create the kemu region in the new mm. Called from binfmt_kemu after the
 * ELF image has been mapped (ARCH_SETUP_ADDITIONAL_PAGES).
 */
int kemu_setup_mm(struct linux_binprm *bprm)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	struct kemu_mm *km;
	unsigned long addr;
	int ret;

	km = kemu_mm_alloc();
	if (!km)
		return -ENOMEM;
	km->chunks[0] = kemu_chunk_alloc();
	km->table = vzalloc(KEMU_TABLE_SIZE);
	if (!km->chunks[0] || !km->table) {
		kemu_mm_free(km);
		return -ENOMEM;
	}
	memcpy(km->chunks[0], kemu_stubs_start, kemu_stubs_end - kemu_stubs_start);
	km->code_used = KEMU_STUBS_SIZE;

	if (mmap_write_lock_killable(mm)) {
		kemu_mm_free(km);
		return -EINTR;
	}
	addr = get_unmapped_area(NULL, 0, KEMU_REGION_SIZE, 0, 0);
	if (IS_ERR_VALUE(addr)) {
		ret = addr;
		goto fail;
	}
	km->base = addr;
	km->code_base = addr;
	km->table_base = addr + KEMU_CODE_SIZE;
	km->slots_base = km->table_base + KEMU_TABLE_SIZE;

	vma = _install_special_mapping(mm, km->code_base, KEMU_CODE_SIZE,
				       VM_READ | VM_EXEC | VM_MAYREAD | VM_MAYEXEC |
				       VM_PFNMAP | VM_DONTDUMP | VM_IO,
				       &kemu_code_mapping);
	if (IS_ERR(vma)) {
		ret = PTR_ERR(vma);
		goto fail;
	}
	vma = _install_special_mapping(mm, km->table_base, KEMU_TABLE_SIZE,
				       VM_READ | VM_MAYREAD |
				       VM_PFNMAP | VM_DONTDUMP | VM_IO,
				       &kemu_table_mapping);
	if (IS_ERR(vma)) {
		ret = PTR_ERR(vma);
		goto fail_unmap;
	}
	vma = _install_special_mapping(mm, km->slots_base, KEMU_SLOTS_SIZE,
				       VM_READ | VM_WRITE | VM_MAYREAD | VM_MAYWRITE |
				       VM_SHARED | VM_MAYSHARE |
				       VM_PFNMAP | VM_DONTDUMP | VM_IO,
				       &kemu_slots_mapping);
	if (IS_ERR(vma)) {
		ret = PTR_ERR(vma);
		goto fail_unmap;
	}
	addr = get_unmapped_area(NULL, 0, PAGE_SIZE, 0, 0);
	if (IS_ERR_VALUE(addr)) {
		ret = addr;
		goto fail_unmap;
	}
	vma = _install_special_mapping(mm, addr, PAGE_SIZE,
				       VM_READ | VM_EXEC | VM_MAYREAD | VM_MAYEXEC,
				       &kemu_tramp_mapping);
	if (IS_ERR(vma)) {
		ret = PTR_ERR(vma);
		goto fail_unmap;
	}
	km->vdso_base = addr;
	mm->kemu = km;
	mmap_write_unlock(mm);
	return 0;

fail_unmap:
	do_munmap(mm, km->base, KEMU_REGION_SIZE, NULL);
fail:
	mmap_write_unlock(mm);
	kemu_mm_free(km);
	return ret;
}

/* START_THREAD for AArch64 images. */
void kemu_start_thread(struct pt_regs *regs, unsigned long pc, unsigned long sp)
{
	struct kemu_mm *km = current->mm->kemu;
	struct kemu_thread *kt;
	struct kemu_cpu *cpu;
	int slot;

	if (WARN_ON_ONCE(!km) || WARN_ON_ONCE(current->kemu))
		goto fail;
	slot = kemu_slot_get(km);
	if (slot < 0)
		goto fail;
	kt = kemu_thread_new(km, slot);
	if (!kt) {
		ida_free(&km->slot_ida, slot);
		goto fail;
	}

	cpu = kt->cpu;
	memset(cpu, 0, sizeof(*cpu));
	cpu->pc = pc;
	cpu->sp = sp;
	cpu->excl_addr = ~0ULL;
	cpu->host_rsp_top = kt->rstack_top;

	static_branch_enable(&kemu_active_key);
	current->kemu = kt;

	start_thread(regs, kemu_stub_addr(km, kemu_stub_dispatch), kt->rstack_top);
	do_arch_prctl_64(current, ARCH_SET_GS, kt->cpu_uaddr);
	return;
fail:
	force_fatal_sig(SIGKILL);
}

/*
 * Called from exec_mmap() once the exec can no longer fail: the current
 * thread leaves its old mm (and its kemu slot).
 */
void kemu_exec_release(struct task_struct *tsk, struct mm_struct *old_mm)
{
	struct kemu_thread *kt = tsk->kemu;

	if (!kt)
		return;
	tsk->kemu = NULL;
	kemu_thread_free(old_mm ? old_mm->kemu : NULL, kt);
}

/* ---- fork / clone ---- */

static void kemu_zap_region(struct mm_struct *mm, struct kemu_mm *km)
{
	struct vm_area_struct *vma;

	mmap_write_lock(mm);
	vma = vma_lookup(mm, km->code_base);
	if (vma)
		zap_vma_ptes(vma, vma->vm_start, vma->vm_end - vma->vm_start);
	vma = vma_lookup(mm, km->table_base);
	if (vma)
		zap_vma_ptes(vma, vma->vm_start, vma->vm_end - vma->vm_start);
	vma = vma_lookup(mm, km->slots_base);
	if (vma)
		zap_vma_ptes(vma, vma->vm_start, vma->vm_end - vma->vm_start);
	mmap_write_unlock(mm);
}

/*
 * dup_mm() hook: give the child mm a private copy of the region contents.
 * Only the forking thread's slot is copied; other threads don't exist in
 * the child.
 */
int kemu_dup_mm(struct mm_struct *oldmm, struct mm_struct *mm)
{
	struct kemu_mm *okm = oldmm->kemu, *km;
	struct kemu_thread *kt = current->kemu;
	struct kemu_slot *os, *s;
	int i, err;

	mm->kemu = NULL;
	if (!okm)
		return 0;
	if (!kt)
		return -EINVAL;	/* only kemu threads can fork a kemu mm */

	km = kemu_mm_alloc();
	if (!km)
		return -ENOMEM;

	mutex_lock(&okm->lock);
	km->base = okm->base;
	km->code_base = okm->code_base;
	km->table_base = okm->table_base;
	km->slots_base = okm->slots_base;
	km->code_used = okm->code_used;
	km->vdso_base = okm->vdso_base;
	err = -ENOMEM;
	for (i = 0; i < KEMU_MAX_CHUNKS; i++) {
		if (!okm->chunks[i])
			continue;
		km->chunks[i] = kemu_chunk_alloc();
		if (!km->chunks[i])
			goto out_unlock;
		memcpy(km->chunks[i], okm->chunks[i], KEMU_CHUNK_SIZE);
	}
	km->table = vmalloc(KEMU_TABLE_SIZE);
	if (!km->table)
		goto out_unlock;
	memcpy(km->table, okm->table, KEMU_TABLE_SIZE);
	mutex_unlock(&okm->lock);

	/* Copy the current thread's slot to the same index. */
	os = xa_load(&okm->slots, kt->slot);
	s = kemu_slot_alloc_pages();
	if (!os || !s)
		goto out_free;
	for (i = 0; i < KEMU_SLOT_USED_PAGES; i++)
		copy_highpage(s->pages[i], os->pages[i]);
	err = ida_alloc_range(&km->slot_ida, kt->slot, kt->slot, GFP_KERNEL);
	if (err < 0)
		goto out_free_slot;
	err = xa_err(xa_store(&km->slots, kt->slot, s, GFP_KERNEL));
	if (err)
		goto out_free_slot;

	mm->kemu = km;
	kemu_zap_region(mm, km);
	return 0;

out_unlock:
	mutex_unlock(&okm->lock);
	goto out_free;
out_free_slot:
	for (i = 0; i < KEMU_SLOT_USED_PAGES; i++)
		__free_page(s->pages[i]);
	kfree(s);
out_free:
	kemu_mm_free(km);
	return err;
}

/* __mmput() hook, after exit_mmap(): no mappings reference our pages. */
void kemu_mm_release(struct mm_struct *mm)
{
	struct kemu_mm *km = mm->kemu;

	if (!km)
		return;
	mm->kemu = NULL;
	kemu_mm_free(km);
}

/*
 * copy_thread() hook. The child either shares the mm (thread/vfork: new
 * slot) or got a copy of it in kemu_dup_mm (fork: same slot index). The
 * x86 code has already applied clone's stack and TLS to the host
 * registers; for kemu those are guest values, so move them over.
 */
int kemu_copy_thread(struct task_struct *p, const struct kernel_clone_args *args)
{
	struct kemu_thread *pkt = current->kemu, *kt;
	struct pt_regs *childregs = task_pt_regs(p);
	struct kemu_mm *km;
	int slot;

	p->kemu = NULL;
	if (!pkt || (p->flags & PF_KTHREAD) || args->fn)
		return 0;
	km = p->mm ? p->mm->kemu : NULL;
	if (!km)
		return -EINVAL;

	if (args->flags & CLONE_VM) {
		slot = kemu_slot_get(km);
		if (slot < 0)
			return slot;
	} else {
		slot = pkt->slot;
	}
	kt = kemu_thread_new(km, slot);
	if (!kt) {
		if (args->flags & CLONE_VM)
			ida_free(&km->slot_ida, slot);
		return -ENOMEM;
	}
	if (args->flags & CLONE_VM)
		memcpy(kt->cpu, pkt->cpu, sizeof(*kt->cpu));

	kt->cpu->x[0] = 0;
	if (args->stack)
		kt->cpu->sp = args->stack;
	if (args->flags & CLONE_SETTLS) {
		kt->cpu->tpidr = args->tls;
		p->thread.fsbase = 0;
		p->thread.fsindex = 0;
	}
	kt->cpu->host_rsp_top = kt->rstack_top;
	kt->cpu->excl_addr = ~0ULL;

	p->thread.gsbase = kt->cpu_uaddr;
	p->thread.gsindex = 0;
	childregs->sp = kt->rstack_top;
	childregs->ip = kemu_stub_addr(km, kemu_stub_dispatch);
	childregs->cx = childregs->ip;
	childregs->r11 = childregs->flags;
	p->kemu = kt;
	return 0;
}

/* do_exit() before exit_mm(), and copy_process() failure via exit_thread(). */
void kemu_thread_exit(struct task_struct *tsk)
{
	struct kemu_thread *kt = tsk->kemu;

	if (!kt)
		return;
	tsk->kemu = NULL;
	kemu_thread_free(tsk->mm ? tsk->mm->kemu : NULL, kt);
}

unsigned long kemu_user_sp(struct task_struct *tsk)
{
	return tsk->kemu ? READ_ONCE(tsk->kemu->cpu->sp) : 0;
}

/* current_user_stack_pointer(): the guest SP for kemu tasks. */
unsigned long kemu_current_user_sp(void)
{
	if (task_is_kemu(current))
		return READ_ONCE(current->kemu->cpu->sp);
	return current_pt_regs()->sp;
}

/* ---- exit to user ---- */

void kemu_exit_to_user(struct pt_regs *regs)
{
	struct kemu_thread *kt = current->kemu;
	struct kemu_mm *km;

	if (!kt)
		return;
	kt->flags &= ~KEMU_TF_IN_SVC;
	if (!(kt->flags & KEMU_TF_REDIRECT))
		return;
	km = current->mm->kemu;
	kt->flags &= ~KEMU_TF_REDIRECT;
	regs->ip = kemu_stub_addr(km, kemu_stub_dispatch);
	regs->sp = kt->rstack_top;
	regs->cx = regs->ip;
	regs->r11 = regs->flags;
}

unsigned int kemu_hwcap(void)
{
	return kemu_rs_hwcap();
}

unsigned int kemu_hwcap2(void)
{
	return kemu_rs_hwcap2();
}

static int __init kemu_init(void)
{
	static const u32 tramp[] = { 0xd2801168, 0xd4000001 };

	kemu_thread_cache = KMEM_CACHE(kemu_thread, SLAB_PANIC | SLAB_ACCOUNT);
	kemu_tramp_pages[0] = alloc_page(GFP_KERNEL | __GFP_ZERO);
	BUG_ON(!kemu_tramp_pages[0]);
	memcpy(page_address(kemu_tramp_pages[0]), tramp, sizeof(tramp));
	BUILD_BUG_ON(KEMU_STUBS_SIZE > KEMU_CHUNK_SIZE);
	return 0;
}
core_initcall(kemu_init);
