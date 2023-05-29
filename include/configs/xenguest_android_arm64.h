/*
 * SPDX-License-Identifier: GPL-2.0+
 *
 * (C) Copyright 2020 EPAM Systemc Inc.
 */
#ifndef __XENGUEST_ANDROID_ARM64_H
#define __XENGUEST_ANDROID_ARM64_H

/* NOTE: In case of bootm * boot , u-boot  will set/append
 * env variable bootargs with boot_img_hdr->cmdline and further overwrite
 * /chosen node of the fdt. Since /chosen node is the main mechanism to pass cmdline
 * from Xen domain config to bootloader and Linux kernel, we will prior to all that 
 * create bootargs variable with /chosen node(using command "fdt get value bootargs /chosen bootargs").
 * So in at the end bootargs will contain /chosen node + boot_img_hdr->cmdline. */

#define CONFIG_EXTRA_ENV_SETTINGS	\
    "android_keymint_needed=N\0" \
    "blk_deivce_if=pvblock\0" \
    "blk_device_id=0\0" \
    "bootcmd=run update_fdtaddr; run update_bootargs; run bootcmd_android;\0" \
    "bootcmd_android=verified_boot_android ${blk_deivce_if} ${blk_device_id}#misc\0" \
    "bootdelay=3\0" \
    "fdtaddr=0\0" \
    "stderr=hypervisor\0" \
    "stdin=hypervisor\0" \
    "stdout=hypervisor\0" \
    "update_bootargs=fdt addr ${fdtaddr}; fdt get value bootargs /chosen bootargs;\0" \
    "update_fdtaddr=setexpr fdtaddr ${fdtcontroladdr}\0"

#endif /* __XENGUEST_ANDROID_ARM64_H */
