/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2017 Tuomas Tynkkynen
 */

#ifndef __CONFIG_H
#define __CONFIG_H

#include <linux/sizes.h>

/* Physical memory map */

/* The DTB may be placed at start of RAM, stay away from there */
#define CONFIG_SYS_INIT_SP_ADDR		(CONFIG_SYS_SDRAM_BASE + SZ_2M)
#define CONFIG_SYS_LOAD_ADDR		(CONFIG_SYS_SDRAM_BASE + SZ_2M)
#define CONFIG_SYS_MALLOC_LEN		SZ_64M

#define CONFIG_SYS_BOOTM_LEN		SZ_64M

/* ARMv7/ARMv8 architected timer */
#define CONFIG_SYS_HZ                       1000

/* Environment options */
#define CONFIG_EXTRA_ENV_SETTINGS "distro_bootcmd=booti ${kernel_image_addr} - ${fdt_addr}\0"

#define CONFIG_SYS_CBSIZE 512

#define CONFIG_SYS_MONITOR_BASE		CONFIG_SYS_TEXT_BASE
#define CONFIG_SYS_MAX_FLASH_BANKS_DETECT	2
#define CONFIG_SYS_MAX_FLASH_SECT	256 /* Sector: 256K, Bank: 64M */

#endif /* __CONFIG_H */
