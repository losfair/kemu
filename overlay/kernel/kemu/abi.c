// SPDX-License-Identifier: GPL-2.0
/*
 * kemu: arm64 syscalls whose ABI differs from x86_64.
 *
 * All handlers receive the syscall view of pt_regs (di, si, dx, r10, r8,
 * r9 = guest X0..X5) and may adjust it before calling the x86_64 entry
 * point.
 */

#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/eventpoll.h>
#include <linux/utsname.h>
#include <linux/uaccess.h>
#include <linux/highuid.h>
#include <linux/kdev_t.h>
#include <linux/openat2.h>
#include <linux/audit.h>
#include <linux/sem.h>
#include <linux/ipc.h>

#include "kemu_internal.h"

asmlinkage long __x64_sys_openat(const struct pt_regs *regs);
asmlinkage long __x64_sys_fcntl(const struct pt_regs *regs);
asmlinkage long __x64_sys_pipe2(const struct pt_regs *regs);
asmlinkage long __x64_sys_open_by_handle_at(const struct pt_regs *regs);
asmlinkage long __x64_sys_fanotify_init(const struct pt_regs *regs);
asmlinkage long __x64_sys_newuname(const struct pt_regs *regs);
asmlinkage long __x64_sys_clone(const struct pt_regs *regs);
asmlinkage long __x64_sys_semctl(const struct pt_regs *regs);
asmlinkage long __x64_sys_epoll_pwait(const struct pt_regs *regs);
asmlinkage long __x64_sys_epoll_pwait2(const struct pt_regs *regs);
int do_sys_openat2(int dfd, const char __user *filename, struct open_how *how);

/* ---- open flags ----
 *
 * arm64 overrides four O_* bits of asm-generic, which x86 uses:
 *                arm64     generic/x86
 *   O_DIRECTORY  0040000   0200000
 *   O_NOFOLLOW   0100000   0400000
 *   O_DIRECT     0200000   0040000
 *   O_LARGEFILE  0400000   0100000
 */
#define A64_O_DIRECTORY	0040000
#define A64_O_NOFOLLOW	0100000
#define A64_O_DIRECT	0200000
#define A64_O_LARGEFILE	0400000
#define A64_O_MASK	(A64_O_DIRECTORY | A64_O_NOFOLLOW | A64_O_DIRECT | A64_O_LARGEFILE)

static_assert(O_DIRECTORY == 0200000 && O_NOFOLLOW == 0400000 &&
	      O_DIRECT == 0040000 && O_LARGEFILE == 0100000);

u32 kemu_oflags_to_host(u32 f)
{
	u32 r = f & ~A64_O_MASK;

	if (f & A64_O_DIRECTORY)
		r |= O_DIRECTORY;
	if (f & A64_O_NOFOLLOW)
		r |= O_NOFOLLOW;
	if (f & A64_O_DIRECT)
		r |= O_DIRECT;
	if (f & A64_O_LARGEFILE)
		r |= O_LARGEFILE;
	return r;
}

u32 kemu_oflags_to_guest(u32 f)
{
	u32 r = f & ~A64_O_MASK;

	if (f & O_DIRECTORY)
		r |= A64_O_DIRECTORY;
	if (f & O_NOFOLLOW)
		r |= A64_O_NOFOLLOW;
	if (f & O_DIRECT)
		r |= A64_O_DIRECT;
	if (f & O_LARGEFILE)
		r |= A64_O_LARGEFILE;
	return r;
}

long kemu_sys_openat(struct pt_regs *regs)
{
	kemu_reg(regs, dx) = kemu_oflags_to_host(kemu_reg(regs, dx));
	return __x64_sys_openat(regs);
}

long kemu_sys_openat2(struct pt_regs *regs)
{
	struct open_how __user *uhow = (void __user *)kemu_reg(regs, dx);
	size_t usize = kemu_reg(regs, r10);
	struct open_how how;
	int err;

	BUILD_BUG_ON(sizeof(struct open_how) < OPEN_HOW_SIZE_VER0);
	if (unlikely(usize < OPEN_HOW_SIZE_VER0))
		return -EINVAL;
	if (unlikely(usize > PAGE_SIZE))
		return -E2BIG;
	err = copy_struct_from_user(&how, sizeof(how), uhow, usize);
	if (err)
		return err;
	/* Audit logs the guest's (arm64) flags, under AUDIT_ARCH_AARCH64. */
	audit_openat2_how(&how);
	/* Bits outside the translated set are validated by the core. */
	how.flags = (how.flags & ~(u64)U32_MAX) | kemu_oflags_to_host((u32)how.flags);
	/* O_LARGEFILE is forced on 64-bit (non-O_PATH), as in native openat2. */
	if (!(how.flags & O_PATH) && force_o_largefile())
		how.flags |= O_LARGEFILE;
	return do_sys_openat2((int)kemu_reg(regs, di), (const char __user *)kemu_reg(regs, si), &how);
}

long kemu_sys_fcntl(struct pt_regs *regs)
{
	unsigned int cmd = kemu_reg(regs, si);
	long ret;

	if (cmd == F_SETFL)
		kemu_reg(regs, dx) = kemu_oflags_to_host(kemu_reg(regs, dx));
	ret = __x64_sys_fcntl(regs);
	if (cmd == F_GETFL && ret >= 0)
		ret = kemu_oflags_to_guest(ret);
	return ret;
}

long kemu_sys_pipe2(struct pt_regs *regs)
{
	kemu_reg(regs, si) = kemu_oflags_to_host(kemu_reg(regs, si));
	return __x64_sys_pipe2(regs);
}

long kemu_sys_open_by_handle_at(struct pt_regs *regs)
{
	kemu_reg(regs, dx) = kemu_oflags_to_host(kemu_reg(regs, dx));
	return __x64_sys_open_by_handle_at(regs);
}

long kemu_sys_fanotify_init(struct pt_regs *regs)
{
	kemu_reg(regs, si) = kemu_oflags_to_host(kemu_reg(regs, si));
	return __x64_sys_fanotify_init(regs);
}

/* ---- stat ---- */

/* asm-generic struct stat, as used by arm64. */
struct kemu_stat {
	u64 st_dev;
	u64 st_ino;
	u32 st_mode;
	u32 st_nlink;
	u32 st_uid;
	u32 st_gid;
	u64 st_rdev;
	u64 __pad1;
	s64 st_size;
	s32 st_blksize;
	s32 __pad2;
	s64 st_blocks;
	s64 st_atime;
	u64 st_atime_nsec;
	s64 st_mtime;
	u64 st_mtime_nsec;
	s64 st_ctime;
	u64 st_ctime_nsec;
	u32 __unused4;
	u32 __unused5;
};
static_assert(sizeof(struct kemu_stat) == 128);

static int kemu_cp_stat(struct kstat *stat, struct kemu_stat __user *ubuf)
{
	struct kemu_stat tmp;

	memset(&tmp, 0, sizeof(tmp));
	tmp.st_dev = new_encode_dev(stat->dev);
	tmp.st_ino = stat->ino;
	tmp.st_mode = stat->mode;
	tmp.st_nlink = stat->nlink;
	if (tmp.st_nlink != stat->nlink)
		return -EOVERFLOW;
	tmp.st_uid = from_kuid_munged(current_user_ns(), stat->uid);
	tmp.st_gid = from_kgid_munged(current_user_ns(), stat->gid);
	tmp.st_rdev = new_encode_dev(stat->rdev);
	tmp.st_size = stat->size;
	tmp.st_blksize = stat->blksize;
	tmp.st_blocks = stat->blocks;
	tmp.st_atime = stat->atime.tv_sec;
	tmp.st_atime_nsec = stat->atime.tv_nsec;
	tmp.st_mtime = stat->mtime.tv_sec;
	tmp.st_mtime_nsec = stat->mtime.tv_nsec;
	tmp.st_ctime = stat->ctime.tv_sec;
	tmp.st_ctime_nsec = stat->ctime.tv_nsec;
	return copy_to_user(ubuf, &tmp, sizeof(tmp)) ? -EFAULT : 0;
}

long kemu_sys_newfstatat(struct pt_regs *regs)
{
	struct kstat stat;
	int err;

	err = vfs_fstatat((int)kemu_reg(regs, di), (const char __user *)kemu_reg(regs, si), &stat,
			  (int)kemu_reg(regs, r10));
	if (err)
		return err;
	return kemu_cp_stat(&stat, (void __user *)kemu_reg(regs, dx));
}

long kemu_sys_fstat(struct pt_regs *regs)
{
	struct kstat stat;
	int err;

	err = vfs_fstat((unsigned int)kemu_reg(regs, di), &stat);
	if (err)
		return err;
	return kemu_cp_stat(&stat, (void __user *)kemu_reg(regs, si));
}

/* ---- epoll: arm64 struct epoll_event is 16 bytes, x86_64's is packed (12) ---- */

struct kemu_epoll_event {
	u32 events;
	u32 __pad;
	u64 data;
};

long kemu_sys_epoll_ctl(struct pt_regs *regs)
{
	struct kemu_epoll_event __user *uev = (void __user *)kemu_reg(regs, r10);
	struct kemu_epoll_event gev;
	struct epoll_event ev = {};
	int op = kemu_reg(regs, si);

	if (ep_op_has_event(op)) {
		if (copy_from_user(&gev, uev, sizeof(gev)))
			return -EFAULT;
		ev.events = gev.events;
		ev.data = gev.data;
	}
	return do_epoll_ctl((int)kemu_reg(regs, di), op, (int)kemu_reg(regs, dx), &ev, false);
}

/*
 * The x86 implementation writes packed 12-byte events at the start of the
 * guest buffer (which is big enough for maxevents 16-byte events); expand
 * them in place from the end.
 */
static long kemu_epoll_expand(void __user *buf, long n)
{
	long i;

	for (i = n - 1; i >= 0; i--) {
		struct epoll_event pk;
		struct kemu_epoll_event ge = {};

		if (copy_from_user(&pk, buf + i * sizeof(pk), sizeof(pk)))
			return -EFAULT;
		ge.events = pk.events;
		ge.data = pk.data;
		if (copy_to_user(buf + i * sizeof(ge), &ge, sizeof(ge)))
			return -EFAULT;
	}
	return n;
}

long kemu_sys_epoll_pwait(struct pt_regs *regs)
{
	long n = __x64_sys_epoll_pwait(regs);

	return n > 0 ? kemu_epoll_expand((void __user *)kemu_reg(regs, si), n) : n;
}

long kemu_sys_epoll_pwait2(struct pt_regs *regs)
{
	long n = __x64_sys_epoll_pwait2(regs);

	return n > 0 ? kemu_epoll_expand((void __user *)kemu_reg(regs, si), n) : n;
}

/* ---- misc ---- */

long kemu_sys_uname(struct pt_regs *regs)
{
	struct new_utsname __user *u = (void __user *)kemu_reg(regs, di);
	static const char machine[__NEW_UTS_LEN + 1] = "aarch64";
	long ret = __x64_sys_newuname(regs);

	if (ret)
		return ret;
	if (copy_to_user(u->machine, machine, sizeof(machine)))
		return -EFAULT;
	return 0;
}

/* arm64: clone(flags, newsp, ptid, tls, ctid); x86_64: (..., ctid, tls). */
long kemu_sys_clone(struct pt_regs *regs)
{
	swap(kemu_reg(regs, r10), kemu_reg(regs, r8));
	return __x64_sys_clone(regs);
}

/* ---- semctl ----
 *
 * The x86_64 semid64_ds inserts two padding words (__unused1/__unused2)
 * that asm-generic (arm64) doesn't, so its layout is 104 bytes where the
 * guest's is 88. Only IPC_STAT/SEM_STAT/SEM_STAT_ANY (out) and IPC_SET (in)
 * carry the struct; every other command is layout-agnostic and passes
 * through. cmd never has the IPC_64 bit here (the entry fixes the version),
 * matching the native switch; anything else falls through to the native
 * handler, which rejects it exactly as arm64 would.
 */
struct kemu_ipc64_perm {
	s32 key;
	u32 uid, gid, cuid, cgid;
	u32 mode;
	u16 seq, __pad2;
	u64 __unused1, __unused2;
};

struct kemu_semid64_ds {
	struct kemu_ipc64_perm sem_perm;
	s64 sem_otime;
	s64 sem_ctime;
	u64 sem_nsems;
	u64 __unused3;
	u64 __unused4;
};
static_assert(sizeof(struct kemu_semid64_ds) == 88);
static_assert(sizeof(struct kemu_ipc64_perm) == sizeof(struct ipc64_perm));

/* Copy the shared fields between the native and guest layouts. */
static void kemu_semid_to_guest(const struct semid64_ds *k, struct kemu_semid64_ds *g)
{
	memset(g, 0, sizeof(*g));
	memcpy(&g->sem_perm, &k->sem_perm, sizeof(g->sem_perm));
	g->sem_otime = k->sem_otime;
	g->sem_ctime = k->sem_ctime;
	g->sem_nsems = k->sem_nsems;
}

static void kemu_semid_from_guest(const struct kemu_semid64_ds *g, struct semid64_ds *k)
{
	memset(k, 0, sizeof(*k));
	memcpy(&k->sem_perm, &g->sem_perm, sizeof(g->sem_perm));
	k->sem_otime = g->sem_otime;
	k->sem_ctime = g->sem_ctime;
	k->sem_nsems = g->sem_nsems;
}

long kemu_sys_semctl(struct pt_regs *regs)
{
	int semid = (int)kemu_reg(regs, di);
	int cmd = (int)kemu_reg(regs, dx);
	void __user *p = (void __user *)kemu_reg(regs, r10);
	struct kemu_semid64_ds g;
	struct semid64_ds k;
	int err;

	/* As ksys_semctl(): the stat/set helpers would mask a negative id
	 * into a valid index. */
	if (semid < 0)
		return -EINVAL;
	switch (cmd) {
	case IPC_STAT:
	case SEM_STAT:
	case SEM_STAT_ANY:
		err = kemu_semctl_stat(semid, cmd, &k);
		if (err < 0)
			return err;
		kemu_semid_to_guest(&k, &g);
		if (copy_to_user(p, &g, sizeof(g)))
			return -EFAULT;
		return err;	/* SEM_STAT* returns the semid */
	case IPC_SET:
		if (copy_from_user(&g, p, sizeof(g)))
			return -EFAULT;
		kemu_semid_from_guest(&g, &k);
		return kemu_semctl_set(semid, cmd, &k);
	default:
		return __x64_sys_semctl(regs);
	}
}
