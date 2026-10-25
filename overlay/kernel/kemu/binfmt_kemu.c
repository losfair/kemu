// SPDX-License-Identifier: GPL-2.0
/*
 * kemu: ELF loader for AArch64 images, built from fs/binfmt_elf.c with
 * arm64 overrides (the same pattern as fs/compat_binfmt_elf.c).
 */

#include <linux/elf.h>
#include <linux/kemu.h>
#include "kemu_internal.h"

static bool kemu_enabled_sysctl = true;

static inline bool kemu_elf_check_arch(const struct elf64_hdr *x)
{
	return READ_ONCE(kemu_enabled_sysctl) && x->e_machine == EM_AARCH64 &&
	       x->e_ident[EI_CLASS] == ELFCLASS64 &&
	       x->e_ident[EI_DATA] == ELFDATA2LSB;
}

#include <linux/elfcore.h>

/* arm64 NT_PRSTATUS layout: user_pt_regs is 34 u64 (x0-x30, sp, pc, pstate). */
struct kemu_elf_prstatus {
	struct elf_prstatus_common common;
	u64 pr_reg[34];
	int pr_fpvalid;
};
#define elf_prstatus	kemu_elf_prstatus

#undef	ELF_ARCH
#define	ELF_ARCH		EM_AARCH64

#undef	elf_check_arch
#define	elf_check_arch(x)	kemu_elf_check_arch(x)

#undef	ELF_PLATFORM
#define	ELF_PLATFORM		("aarch64")

#undef	ELF_HWCAP
#define	ELF_HWCAP		(kemu_hwcap())
#undef	ELF_HWCAP2
#define	ELF_HWCAP2		(kemu_hwcap2())

#undef	ARCH_DLINFO
#define	ARCH_DLINFO		NEW_AUX_ENT(AT_MINSIGSTKSZ, KEMU_AT_MINSIGSTKSZ)

#undef	SET_PERSONALITY
#define	SET_PERSONALITY(ex)	kemu_set_personality()

#undef	ELF_PLAT_INIT
#define	ELF_PLAT_INIT(regs, load_addr)	do { } while (0)

#undef	START_THREAD
#define	START_THREAD(ex, regs, ip, sp)	kemu_start_thread(regs, ip, sp)

#undef	ARCH_HAS_SETUP_ADDITIONAL_PAGES
#define	ARCH_HAS_SETUP_ADDITIONAL_PAGES	1
#undef	ARCH_SETUP_ADDITIONAL_PAGES
#define	ARCH_SETUP_ADDITIONAL_PAGES(bprm, ex, interp)	kemu_setup_mm(bprm)

#undef	elf_read_implies_exec
#define	elf_read_implies_exec(ex, stk)	0

#define elf_format		kemu_elf_format
#define init_elf_binfmt		init_kemu_elf_binfmt
#define exit_elf_binfmt		exit_kemu_elf_binfmt
#define binfmt_elf_test_cases	kemu_binfmt_elf_test_cases
#define binfmt_elf_test_suite	kemu_binfmt_elf_test_suite

#include "../../fs/binfmt_elf.c"
