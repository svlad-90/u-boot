// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2017 Tuomas Tynkkynen
 * Copyright (C) 2021 Google LLC
 */

#include <common.h>
#include <cpu_func.h>
#include <dm.h>
#include <env.h>
#include <fdtdec.h>
#include <init.h>
#include <log.h>
#include <virtio_types.h>
#include <virtio.h>

#include <asm/armv8/mmu.h>

int pvmfw_boot_flow(void *fdt, void *image, size_t size);

/* Assigned in lowlevel_init.S
 * Push the variable into the .data section so that it
 * does not get cleared later.
 */
void * __section(".data") fw_dtb_pointer;
void * __section(".data") fw_kernel_image_pointer;
size_t __section(".data") fw_kernel_image_size;

static struct mm_region pvmfw_mem_map[] = {
	{
		/*
		 * Emulated I/O: 0x0000_0000-0x0001_0000
		 * PCI (virtio): 0x0001_0000-0x1110_0000
		 * GIC region  : 0x????_????-0x4000_0000
		 */
		.virt = 0x00000000UL,
		.phys = 0x00000000UL,
		.size = SZ_1G,
		.attrs = PTE_BLOCK_MEMTYPE(MT_DEVICE_NGNRNE) |
			 PTE_BLOCK_NON_SHARE |
			 PTE_BLOCK_PXN | PTE_BLOCK_UXN
	}, /* 0x4000_0000-0x7000_0000: RESERVED */ {
		/*
		 * Firmware region: 0x7000_0000-0x8000_0000
		 *      RAM region: 0x8000_0000-0x????_????
		 */
		.virt = 0x70000000,
		.phys = 0x70000000,
		.size = 255UL * SZ_1G,
		.attrs = PTE_BLOCK_MEMTYPE(MT_NORMAL) |
			 PTE_BLOCK_INNER_SHARE
	}, {
		/* List terminator */
		0,
	}
};

struct mm_region *mem_map = pvmfw_mem_map;

int board_run_command(const char *cmdline)
{
	int err;
	void (*entry)(void *fdt_addr, void *res0, void *res1, void *res2) =
		fw_kernel_image_pointer;

	err = pvmfw_boot_flow(fw_dtb_pointer,
			      fw_kernel_image_pointer,
			      fw_kernel_image_size);
	if (err) {
		panic("pvmfw boot failed: %d", err);
		__builtin_unreachable();
	}

	cleanup_before_linux();
	entry(fw_dtb_pointer, 0, 0, 0);
	__builtin_unreachable();
}

int board_init(void)
{
	/*
	 * Make sure virtio bus is enumerated so that peripherals
	 * on the virtio bus can be discovered by their drivers
	 */
	virtio_init();

	return 0;
}

int dram_init(void)
{
	if (fdtdec_setup_mem_size_base() != 0)
		return -EINVAL;

	return 0;
}

int dram_init_banksize(void)
{
	fdtdec_setup_memory_banksize();

	return 0;
}

void *board_fdt_blob_setup(int *err)
{
	*err = 0;
	return fw_dtb_pointer;
}

int misc_init_r(void)
{
	env_set_hex("fdt_addr", (u64)fw_dtb_pointer);
	env_set_hex("kernel_image_addr", (u64)fw_kernel_image_pointer);
	env_set_hex("kernel_image_size", (u64)fw_kernel_image_size);

	return 0;
}

void enable_caches(void)
{
	 icache_enable();
	 dcache_enable();
}
