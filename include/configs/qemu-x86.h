/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (C) 2015, Bin Meng <bmeng.cn@gmail.com>
 */

/*
 * board/config.h - configuration options, board specific
 */

#ifndef __CONFIG_H
#define __CONFIG_H

#include <linux/sizes.h>

#ifdef CONFIG_DISTRO_DEFAULTS

#ifdef CONFIG_CMD_USB
#define BOOT_TARGET_DEVICES_USB(func) func(USB, usb, 0)
#else
#define BOOT_TARGET_DEVICES_USB(func)
#endif

#ifdef CONFIG_CMD_SCSI
#define BOOT_TARGET_DEVICES_SCSI(func) func(SCSI, scsi, 0)
#else
#define BOOT_TARGET_DEVICES_SCSI(func)
#endif

#ifdef CONFIG_CMD_VIRTIO
#define BOOT_TARGET_DEVICES_VIRTIO(func) func(VIRTIO, virtio, 0)
#else
#define BOOT_TARGET_DEVICES_VIRTIO(func)
#endif

#if defined(CONFIG_CMD_IDE)
#define BOOT_TARGET_DEVICES_IDE(func) func(IDE, ide, 0
#else
#define BOOT_TARGET_DEVICES_IDE(func)
#endif

#if defined(CONFIG_CMD_DHCP)
#define BOOT_TARGET_DEVICES_DHCP(func) func(DHCP, dhcp, na)
#else
#define BOOT_TARGET_DEVICES_DHCP(func)
#endif

#define BOOT_TARGET_DEVICES(func) \
	BOOT_TARGET_DEVICES_USB(func) \
	BOOT_TARGET_DEVICES_SCSI(func) \
	BOOT_TARGET_DEVICES_VIRTIO(func) \
	BOOT_TARGET_DEVICES_IDE(func) \
	BOOT_TARGET_DEVICES_DHCP(func)

#include <config_distro_bootcmd.h>
#endif

#include <configs/x86-common.h>

#define CONFIG_SYS_MONITOR_LEN		(1 << 20)

#define CONFIG_STD_DEVICES_SETTINGS	"stdin=serial,i8042-kbd\0" \
					"stdout=serial,vidconsole\0" \
					"stderr=serial,vidconsole\0"

/*
 * ATA/SATA support for QEMU x86 targets
 *   - Only legacy IDE controller is supported for QEMU '-M pc' target
 *   - AHCI controller is supported for QEMU '-M q35' target
 */
#define CONFIG_SYS_IDE_MAXBUS		2
#define CONFIG_SYS_IDE_MAXDEVICE	4
#define CONFIG_SYS_ATA_BASE_ADDR	0
#define CONFIG_SYS_ATA_DATA_OFFSET	0
#define CONFIG_SYS_ATA_REG_OFFSET	0
#define CONFIG_SYS_ATA_ALT_OFFSET	0
#define CONFIG_SYS_ATA_IDE0_OFFSET	0x1f0
#define CONFIG_SYS_ATA_IDE1_OFFSET	0x170
#define CONFIG_ATAPI

#define CONFIG_SPL_BOARD_LOAD_IMAGE

#endif	/* __CONFIG_H */
