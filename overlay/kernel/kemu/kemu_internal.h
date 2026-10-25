/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kemu internal definitions shared by the C glue.
 */
#ifndef _KEMU_INTERNAL_H
#define _KEMU_INTERNAL_H

#include <linux/kemu.h>
#include <linux/kemu_abi.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/xarray.h>
#include <linux/idr.h>
#include <linux/sched.h>
#include <linux/build_bug.h>

#include <asm/kemu.h>

#ifndef KEMU_ARCH_VECTOR_CACHE
#define KEMU_ARCH_VECTOR_CACHE 0
#endif

/* ---- Guest CPU state (mirror of rust/kemu_core/src/state.rs) ---- */

struct kemu_cpu {
	u64 x[31];
	u64 sp;
	u64 pc;
	u64 nzcv;
	u32 fpcr;
	u32 fpsr;
	u64 tpidr;
	u64 tpidrro;
	u64 excl_addr;
	u64 excl_size;
	u64 excl_val[2];
	u64 host_rsp;
	u64 host_rsp_top;
	u64 scratch[8];
	u64 exit_info;
	u64 flags_x86;
	u64 _pad0[11];
	u64 v[32][2];
};

static_assert(offsetof(struct kemu_cpu, sp) == KEMU_CPU_SP);
static_assert(offsetof(struct kemu_cpu, pc) == KEMU_CPU_PC);
static_assert(offsetof(struct kemu_cpu, nzcv) == KEMU_CPU_NZCV);
static_assert(offsetof(struct kemu_cpu, fpcr) == KEMU_CPU_FPCR);
static_assert(offsetof(struct kemu_cpu, tpidr) == KEMU_CPU_TPIDR);
static_assert(offsetof(struct kemu_cpu, excl_addr) == KEMU_CPU_EXCL_ADDR);
static_assert(offsetof(struct kemu_cpu, host_rsp) == KEMU_CPU_HOST_RSP);
static_assert(offsetof(struct kemu_cpu, exit_info) == KEMU_CPU_EXIT_INFO);
static_assert(offsetof(struct kemu_cpu, flags_x86) == KEMU_CPU_FLAGS_X86);
static_assert(offsetof(struct kemu_cpu, v) == KEMU_CPU_V(0));
static_assert(sizeof(struct kemu_cpu) == KEMU_CPU_STATE_SIZE);

/* ---- Region layout ---- */

#define KEMU_CHUNK_SHIFT	20			/* 1 MiB code chunks */
#define KEMU_CHUNK_SIZE		(1UL << KEMU_CHUNK_SHIFT)
#define KEMU_MAX_CHUNKS		64			/* 64 MiB code VA */
#define KEMU_CODE_SIZE		(KEMU_MAX_CHUNKS * KEMU_CHUNK_SIZE)
#define KEMU_STUBS_SIZE		PAGE_SIZE		/* chunk 0 holds only the stubs */
#define KEMU_BLOCK_ALIGN	16
#define KEMU_BLOCKMAP_BITS	(KEMU_CHUNK_SIZE / KEMU_BLOCK_ALIGN)

#define KEMU_TABLE_BITS		14
#define KEMU_TABLE_ENTRIES	(1UL << KEMU_TABLE_BITS)
#define KEMU_TABLE_SIZE		(KEMU_TABLE_ENTRIES * 16)

#define KEMU_MAX_THREADS	4096
#define KEMU_SLOT_SIZE		(KEMU_THREAD_SLOT_PAGES * PAGE_SIZE)
#define KEMU_SLOTS_SIZE		(KEMU_MAX_THREADS * KEMU_SLOT_SIZE)

/* Pages inside a slot: [state][guard][rstack x 16][guard...] */
#define KEMU_SLOT_STATE_PG	0
#define KEMU_SLOT_RSTACK_PG	2
#define KEMU_SLOT_RSTACK_TOP_PG	(KEMU_SLOT_RSTACK_PG + KEMU_THREAD_RSTACK_PAGES)
#define KEMU_SLOT_USED_PAGES	(1 + KEMU_THREAD_RSTACK_PAGES)

#define KEMU_REGION_SIZE	(KEMU_CODE_SIZE + KEMU_TABLE_SIZE + KEMU_SLOTS_SIZE)

struct kemu_slot {
	struct page *pages[KEMU_SLOT_USED_PAGES];	/* [0] = state, rest = rstack */
};

/* Offsets of the user-mode stubs (mirror of KemuStubs in kemu_rs.rs). */
struct kemu_stubs {
	u32 dispatch, dispatch_rax, miss, chain, helper, svc, interp_svc, step, fcmp_table, end;
	u32 nranges;
	u32 ranges[16][3];
};

#define KEMU_STUB_PAGE_STATE		0

struct kemu_mm {
	struct mutex lock;		/* translation, chunks, block map */
	struct rw_semaphore chunk_sem;	/* chunk pointers vs. fault handler */
	unsigned long base;
	unsigned long code_base;	/* stubs + code cache (R-X) */
	unsigned long table_base;	/* lookup table (R--) */
	unsigned long slots_base;	/* per-thread slots (RW) */
	void *chunks[KEMU_MAX_CHUNKS];	/* vmalloc'd code chunks (0 = stubs) */
	unsigned long *blockmap[KEMU_MAX_CHUNKS]; /* block starts, 16-byte units */
	u32 chunk_used[KEMU_MAX_CHUNKS];
	u64 chunk_retired[KEMU_MAX_CHUNKS]; /* 0 = live, else retire epoch */
	int cur_chunk;			/* chunk receiving translations, -1 none */
	struct xarray blocks;		/* guest pc >> 2 -> xa_mk_value(block offset) */
	/* Targeted invalidation (see kemu_jit_invalidate). */
	struct xarray binfo;		/* block offset / KEMU_BLOCK_ALIGN -> kemu_blkinfo */
	struct xarray pages;		/* guest page >> PAGE_SHIFT -> kemu_pgvec */
	struct kemu_pgvec *wide;	/* blocks reading too many pages to index */
	struct xarray sites;		/* chained rel32 offset -> xa_mk_value(unchained value) */
	struct xarray tbi_pcs;		/* guest pc >> 2 of blocks translated with TBI */
	u64 epoch;			/* bumped on every flush or invalidation */
	atomic_t flush_pending;		/* executable mapping went away */
	spinlock_t pend_lock;
	u64 pend_lo, pend_hi;		/* ... this guest range */
	void *scratch;			/* translator scratch (kemu_rs_scratch_size) */
	struct kemu_stubs stubs;
	spinlock_t threads_lock;
	struct list_head threads;
	void *table;			/* vmalloc'd lookup table */
	struct xarray slots;		/* slot index -> struct kemu_slot */
	struct ida slot_ida;
	void *vdso;			/* unused yet */
	unsigned long vdso_base;
	unsigned long interp_insns;	/* statistics */
	unsigned long translations;
	unsigned long chains;
	unsigned long helpers;
	unsigned long flushes;
	unsigned long invals;		/* targeted invalidations */
	unsigned long killed;		/* blocks they removed */
	unsigned long tbi_emul;		/* tagged accesses run by the interpreter */
	unsigned long lookups;		/* TRANSLATE/CHAIN ops */
	unsigned long xc_hits;		/* translations taken from the xcache */
	u64 translate_ns;		/* time spent in those ops */
};

/* A live translated block, for targeted invalidation. */
struct kemu_chain_site {
	u32 site;			/* code offset of a rel32 chained to the block */
	u32 val;			/* the value that jumps to the block */
};

struct kemu_blkinfo {
	u64 pc;
	u32 off;			/* code offset of the block */
	u32 size;
	u32 nin, cap;
	u32 tbi_faults;			/* tagged-pointer #GPs in this block */
	struct kemu_chain_site *in;
};

/* Offsets of the blocks translated from one guest page. */
struct kemu_pgvec {
	u32 n, cap;
	u32 off[];
};

/* kemu_thread.flags */
#define KEMU_TF_REDIRECT	BIT(0)	/* resume at dispatch with state from page */
#define KEMU_TF_IN_SVC		BIT(1)	/* inside a guest syscall */
#define KEMU_TF_KSTATE		BIT(2)	/* state page authoritative (in kernel) */
#define KEMU_TF_STEP		BIT(3)	/* ptrace single-step */
#define KEMU_TF_STEP_SVC	BIT(4)	/* trap after the stepped svc */

struct kemu_thread {
	struct task_struct *task;
	struct list_head node;		/* kemu_mm.threads */
	u64 epoch_seen;
	int slot;
	struct kemu_cpu *cpu;		/* kernel alias of the state page */
	unsigned long cpu_uaddr;	/* user address of the state page */
	unsigned long rstack_top;
	unsigned long flags;
	u64 orig_x0;
	/* Pending fault information for the next signal frame. */
	u64 fault_addr;
	u64 fault_esr;
	/* Interpreter instruction-fetch permission cache. */
	unsigned long fetch_start, fetch_end;
	unsigned int fetch_seq;
	bool fetch_valid;
	/* Kernel-private snapshot of the state page handed to Rust. */
	struct kemu_cpu shadow;
};

static inline struct kemu_thread *kemu_cur(void)
{
	return current->kemu;
}

static inline struct kemu_mm *kemu_cur_mm(void)
{
	return current->mm ? current->mm->kemu : NULL;
}

static inline unsigned long kemu_stub(struct kemu_mm *km, u32 off)
{
	return km->code_base + off;
}

extern bool kemu_jit_enabled;
extern int kemu_debug;

/* core.c */
int kemu_setup_mm(struct linux_binprm *bprm);
void kemu_start_thread(struct pt_regs *regs, unsigned long pc, unsigned long sp);
void kemu_redirect(struct kemu_thread *kt);
unsigned int kemu_hwcap(void);
unsigned int kemu_hwcap2(void);

/* syscall.c */
void kemu_svc(struct pt_regs *regs);
void kemu_op(struct pt_regs *regs, unsigned long op);
unsigned long kemu_interp(struct kemu_thread *kt, struct kemu_mm *km, u32 budget);

/* jit.c */
int kemu_jit_init(struct kemu_mm *km);
void kemu_jit_free(struct kemu_mm *km);
int kemu_jit_dup(struct kemu_mm *okm, struct kemu_mm *km);
unsigned long kemu_jit_op(struct pt_regs *regs, unsigned long op);
void kemu_jit_flush(struct kemu_mm *km);
void kemu_jit_invalidate(struct kemu_mm *km, u64 lo, u64 hi);
void kemu_jit_pending(struct kemu_mm *km);
void kemu_materialize(struct pt_regs *regs);
void kemu_enter_op(struct kemu_thread *kt);
void kemu_jit_exit_to_user(struct kemu_thread *kt, struct pt_regs *regs);
unsigned long kemu_op_step(struct kemu_thread *kt, struct kemu_mm *km);

/* signal.c */
void kemu_force_fault(u64 addr, int access, bool align);
long kemu_sys_rt_sigreturn(struct pt_regs *regs);

/* abi.c: arm64 syscalls with kemu-specific implementations. */
u32 kemu_oflags_to_host(u32 f);
u32 kemu_oflags_to_guest(u32 f);
long kemu_sys_openat(struct pt_regs *regs);
long kemu_sys_openat2(struct pt_regs *regs);
long kemu_sys_fcntl(struct pt_regs *regs);
long kemu_sys_pipe2(struct pt_regs *regs);
long kemu_sys_open_by_handle_at(struct pt_regs *regs);
long kemu_sys_fanotify_init(struct pt_regs *regs);
long kemu_sys_newfstatat(struct pt_regs *regs);
long kemu_sys_fstat(struct pt_regs *regs);
long kemu_sys_epoll_ctl(struct pt_regs *regs);
long kemu_sys_epoll_pwait(struct pt_regs *regs);
long kemu_sys_epoll_pwait2(struct pt_regs *regs);
long kemu_sys_uname(struct pt_regs *regs);
long kemu_sys_clone(struct pt_regs *regs);

/* env.c: host services for the Rust core. */
int kemu_c_read(u64 addr, void *buf, size_t len);
int kemu_c_write(u64 addr, const void *buf, size_t len);
int kemu_c_fetch(u64 pc, u32 *out);
int kemu_c_cmpxchg(u64 addr, u32 size, const u64 *exp, const u64 *new, u64 *old);
u64 kemu_c_cntvct(void);
u64 kemu_c_cntfrq(void);
bool kemu_c_random(u64 *out);

/* Rust entry points (kemu_rs.rs). */
struct kemu_rs_exit {
	u32 kind;
	u32 aux;
	u64 addr;
	u32 retired;
	u32 access;
};

#define KEMU_EXIT_BUDGET	0
#define KEMU_EXIT_SVC		1
#define KEMU_EXIT_BRK		2
#define KEMU_EXIT_UNDEF		3
#define KEMU_EXIT_FAULT		4
#define KEMU_EXIT_ICINV		5

#define KEMU_ACCESS_READ	0
#define KEMU_ACCESS_WRITE	1
#define KEMU_ACCESS_EXEC	2

void kemu_rs_interp(struct kemu_cpu *cpu, u32 budget, struct kemu_rs_exit *exit);

struct kemu_trans {
	u64 size;
	u32 check_off;
	u32 main_off;
	u32 ninsns;
	u32 fault_access;
	u64 fault_addr;
	u64 ic_entry;		/* filled in by jit.c, not Rust */
	u32 blk_off;		/* jit.c: code offset of the block */
};

struct kemu_host_regs {
	u64 gpr[16];
	u64 rflags;
	u64 xmm[8][2];
};

int kemu_rs_gen_stubs(u8 *out, size_t len, u64 table_base, u32 mask8,
		      struct kemu_stubs *info);
size_t kemu_rs_scratch_size(void);
int kemu_rs_translate(void *scratch, u64 pc, u8 *out, size_t len, u64 code_uaddr,
		      u64 stubs_base, const struct kemu_stubs *info,
		      struct kemu_trans *res, bool reloc, bool tbi, bool vector_cache);
long kemu_rs_xc_blob_size(void *scratch);
long kemu_rs_xc_blob(void *scratch, u64 pc, u64 blk_off, u8 *out, size_t len);
bool kemu_rs_xc_validate(const u8 *blob, size_t len, u64 pc);
bool kemu_rs_xc_apply(const u8 *blob, size_t blen, u8 *code, size_t clen, u64 pc,
		      u64 blk_off);
int kemu_rs_trans_pages(void *scratch, u64 *out, size_t max);
int kemu_rs_xc_pages(const u8 *blob, size_t blen, u64 pc, u64 *out, size_t max);
#define KEMU_MAX_PAGES	4	/* t1::MAX_PAGES */

/* Shared translation cache (xcache.c). */
struct kemu_xc_key {
	u64 sb;
	u64 ino;
	u32 gen;
	u32 pad;
	u64 off;
};
bool kemu_xc_key(u64 pc, struct kemu_xc_key *k);
size_t kemu_xc_lookup(const struct kemu_xc_key *k, u64 pc, u8 *out, size_t avail,
		      unsigned long blk_off, struct kemu_trans *res, u64 *pages, int *npages);
void kemu_xc_insert(const struct kemu_xc_key *k, void *scratch, u64 pc,
		    const u8 *code, const struct kemu_trans *res,
		    unsigned long blk_off);
void kemu_xc_stats(unsigned long *entries, unsigned long *bytes);
int kemu_xc_init(void);
extern atomic_long_t kemu_xc_hits, kemu_xc_misses, kemu_xc_stale;
bool kemu_rs_recover(const u8 *blk, size_t len, u32 host_off,
		     const struct kemu_host_regs *h, struct kemu_cpu *cpu);
void kemu_rs_recover_stub(u32 info, const struct kemu_host_regs *h, struct kemu_cpu *cpu);
size_t kemu_rs_block_info(const u8 *blk, size_t len, u64 *guest_pc, u32 *main_off);
bool kemu_rs_find_exit(const u8 *blk, size_t len, u32 site_off, u64 *target,
		       u32 *kind);

/* Block layout (rust/kemu_core/src/jit/meta.rs). */
#define KEMU_BLK_IC_OFF		32
#define KEMU_BLK_CHECK_OFF	64
#define KEMU_EXIT_KIND_IC	1
u64 kemu_rs_nzcv_from_image(u64 img);
u64 kemu_rs_image_from_nzcv(u64 nzcv);
u32 kemu_rs_mxcsr_from(u32 fpcr, u32 fpsr);
u32 kemu_rs_fpsr_merge(u32 fpsr, u32 mxcsr);
void kemu_rs_crc_table(u32 *out);
void kemu_rs_set_jit_off(u32 mask);

#define KEMU_CPU_CRC_TABLE	2048	/* offset in the state page (jit/regmap.rs) */

#define KEMU_MXCSR_SLOT	7	/* kemu_cpu.scratch[] index of the MXCSR image */
u64 kemu_rs_hwcap(void);
u64 kemu_rs_hwcap2(void);
int kemu_rs_build_ucontext(u8 *buf, size_t len, const struct kemu_cpu *cpu,
			   u64 sigmask, u64 ss_sp, u32 ss_flags, u64 ss_size,
			   u64 fault_addr, u64 esr);
int kemu_rs_restore_ucontext(const u8 *buf, size_t len, struct kemu_cpu *cpu,
			     u64 *sigmask);

/* arm64 rt_sigframe geometry (see rust sigframe.rs). */
#define KEMU_SIGINFO_SIZE	128
#define KEMU_UCONTEXT_SIZE	4560
#define KEMU_SIGFRAME_SIZE	(KEMU_SIGINFO_SIZE + KEMU_UCONTEXT_SIZE)
#define KEMU_UC_STACK_OFF	16
#define KEMU_MINSIGSTKSZ	5120
#define KEMU_AT_MINSIGSTKSZ	4720

#define KEMU_NR_restart_syscall	128
#define KEMU_NR_rt_sigreturn	139

#endif /* _KEMU_INTERNAL_H */
