/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2017 Tuomas Tynkkynen
 */

#ifndef __CONFIG_H
#define __CONFIG_H

#include <linux/sizes.h>

#define CONFIG_SYS_SDRAM_SIZE		SZ_32M

/* INIT_SP_ADDR is 16-byte aligned by _main() before use. */
#define CONFIG_SYS_INIT_SP_ADDR \
	(CONFIG_SYS_SDRAM_BASE + CONFIG_SYS_SDRAM_SIZE - 1)

#define CONFIG_SYS_CBSIZE		SZ_512

#define CROSVM_PVMFW_MAX_SIZE		((size_t)SZ_2M)
#define CROSVM_FDT_MAX_SIZE		((size_t)SZ_2M)
#define CROSVM_FDT_ADDR			((uintptr_t)CONFIG_SYS_SDRAM_BASE)

#endif /* __CONFIG_H */
