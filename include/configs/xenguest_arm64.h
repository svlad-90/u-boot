/*
 * SPDX-License-Identifier: GPL-2.0+
 *
 * (C) Copyright 2020 EPAM Systemc Inc.
 */
#ifndef __XENGUEST_ARM64_H
#define __XENGUEST_ARM64_H

#ifndef __ASSEMBLY__
#include <linux/types.h>
#endif

#define CONFIG_BOARD_EARLY_INIT_F

#undef CONFIG_SYS_SDRAM_BASE

#define CONFIG_NR_DRAM_BANKS          1

/* Size of malloc() pool */
#define CONFIG_SYS_MALLOC_LEN         (32 * 1024 * 1024)

/* Monitor Command Prompt */
#define CONFIG_SYS_PROMPT_HUSH_PS2    "> "
#define CONFIG_SYS_CBSIZE             1024
#define CONFIG_SYS_MAXARGS            64
#define CONFIG_SYS_BARGSIZE           CONFIG_SYS_CBSIZE
#define CONFIG_SYS_PBSIZE             (CONFIG_SYS_CBSIZE + \
                                      sizeof(CONFIG_SYS_PROMPT) + 16)

#define CONFIG_OF_SYSTEM_SETUP

#define CONFIG_CMDLINE_TAG            1
#define CONFIG_INITRD_TAG             1

#define CONFIG_CMD_RUN

#ifndef CONFIG_EXTRA_ENV_SETTINGS
#define CONFIG_EXTRA_ENV_SETTINGS	\
	"loadimage=ext4load pvblock 0 0x90000000 /boot/Image;\0" \
	"pvblockboot=run loadimage;" \
		"booti 0x90000000 - 0x88000000;\0"
#endif

#endif /* __XENGUEST_ARM64_H */