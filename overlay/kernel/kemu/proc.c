// SPDX-License-Identifier: GPL-2.0
/*
 * kemu: arm64-format /proc/cpuinfo for kemu readers.
 */

#include <linux/kernel.h>
#include <linux/seq_file.h>

#include "kemu_internal.h"

static const char *const hwcap_str[] = {
	"fp", "asimd", "evtstrm", "aes", "pmull", "sha1", "sha2", "crc32",
	"atomics", "fphp", "asimdhp", "cpuid", "asimdrdm", "jscvt", "fcma", "lrcpc",
	"dcpop", "sha3", "sm3", "sm4", "asimddp", "sha512", "sve", "asimdfhm",
	"dit", "uscat", "ilrcpc", "flagm", "ssbs", "sb", "paca", "pacg",
};

static const char *const hwcap2_str[] = {
	"dcpodp", "sve2", "sveaes", "svepmull", "svebitperm", "svesha3", "svesm4",
	"flagm2", "frint", "svei8mm", "svef32mm", "svef64mm", "svebf16", "i8mm",
	"bf16", "dgh", "rng", "bti",
};

int kemu_show_cpuinfo(struct seq_file *m, unsigned int cpu)
{
	u64 hw = kemu_hwcap(), hw2 = kemu_hwcap2();
	unsigned int i;

	seq_printf(m, "processor\t: %u\n", cpu);
	seq_puts(m, "BogoMIPS\t: 100.00\nFeatures\t:");
	for (i = 0; i < ARRAY_SIZE(hwcap_str); i++)
		if (hw & BIT_ULL(i))
			seq_printf(m, " %s", hwcap_str[i]);
	for (i = 0; i < ARRAY_SIZE(hwcap2_str); i++)
		if (hw2 & BIT_ULL(i))
			seq_printf(m, " %s", hwcap2_str[i]);
	seq_puts(m, "\nCPU implementer\t: 0x00\nCPU architecture: 8\n"
		    "CPU variant\t: 0x0\nCPU part\t: 0x000\nCPU revision\t: 0\n\n");
	return 0;
}
