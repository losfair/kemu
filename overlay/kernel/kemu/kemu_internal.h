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
	u32 dispatch, dispatch_rax, miss, chain, helper, svc, interp_svc, end;
	u32 nranges;
	u32 ranges[16][3];
};

#define KEMU_STUB_PAGE_STATE		0
#define KEMU_STUB_PINNED_LIVE		1
#define KEMU_STUB_PINNED_LIVE_PC_RAX	2

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
	u64 epoch;			/* bumped on every flush */
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
};

/* kemu_thread.flags */
#define KEMU_TF_REDIRECT	BIT(0)	/* resume at dispatch with state from page */
#define KEMU_TF_IN_SVC		BIT(1)	/* inside a guest syscall */
#define KEMU_TF_KSTATE		BIT(2)	/* state page authoritative (in kernel) */

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
void kemu_materialize(struct pt_regs *regs);
void kemu_enter_op(struct kemu_thread *kt);
void kemu_jit_exit_to_user(struct kemu_thread *kt, struct pt_regs *regs);

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
};

struct kemu_host_regs {
	u64 gpr[16];
	u64 rflags;
};

int kemu_rs_gen_stubs(u8 *out, size_t len, u64 table_base, u32 mask8,
		      struct kemu_stubs *info);
size_t kemu_rs_scratch_size(void);
int kemu_rs_translate(void *scratch, u64 pc, u8 *out, size_t len, u64 code_uaddr,
		      u64 stubs_base, const struct kemu_stubs *info,
		      struct kemu_trans *res);
bool kemu_rs_recover(const u8 *blk, size_t len, u32 host_off,
		     const struct kemu_host_regs *h, struct kemu_cpu *cpu);
void kemu_rs_pinned_from_host(const struct kemu_host_regs *h, struct kemu_cpu *cpu);
size_t kemu_rs_block_info(const u8 *blk, size_t len, u64 *guest_pc, u32 *main_off);
bool kemu_rs_find_exit(const u8 *blk, size_t len, u32 site_off, u64 *target);
u64 kemu_rs_nzcv_from_image(u64 img);
u64 kemu_rs_image_from_nzcv(u64 nzcv);
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
