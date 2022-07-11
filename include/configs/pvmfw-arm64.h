/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2017 Tuomas Tynkkynen
 */

#ifndef __CONFIG_H
#define __CONFIG_H

#include <linux/sizes.h>

#define CONFIG_SYS_INIT_SP_ADDR		(CONFIG_SYS_SDRAM_BASE + SZ_128M)

#define CONFIG_SYS_CBSIZE		SZ_512

#define CROSVM_PVMFW_MAX_SIZE		SZ_2M
#define CROSVM_FDT_MAX_SIZE		SZ_2M

#endif /* __CONFIG_H */
