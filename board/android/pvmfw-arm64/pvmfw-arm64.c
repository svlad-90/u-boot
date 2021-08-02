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

/* Assigned in lowlevel_init.S
 * Push the variable into the .data section so that it
 * does not get cleared later.
 */
void * __section(".data") fw_dtb_pointer;
void * __section(".data") fw_kernel_image_pointer;

#define CROSVM_FDT_MAX_SIZE 0x200000
#define CROSVM_EXTRA_SUBTRACT 0x10000

static struct mm_region pvmfw_mem_map[] = {
	{
		/* Map NULL
		 * TODO: figure out what's using low addresses, make it stop,
		 * and remove this mapping.
		 * Currently there are a few parts that dereference low
		 * addresses. One that consistently crashes is in
		 * pci-uclass.c:pci_generic_mmap_read_config, where
		 * `*valuep = readw(address);` dereferences 0x10000
		 */
		.virt = 0x00000000UL,
		.phys = 0x00000000UL,
		.size = 0x00020000UL,
		.attrs = PTE_BLOCK_MEMTYPE(MT_NORMAL) |
			 PTE_BLOCK_INNER_SHARE
	}, {
		/* Lowmem peripherals */
		.virt = 0x08000000UL,
		.phys = 0x08000000UL,
		.size = 0x38000000,
		.attrs = PTE_BLOCK_MEMTYPE(MT_DEVICE_NGNRNE) |
			 PTE_BLOCK_NON_SHARE |
			 PTE_BLOCK_PXN | PTE_BLOCK_UXN
	}, {
		/* RAM */
		.virt = CONFIG_SYS_SDRAM_BASE,
		.phys = CONFIG_SYS_SDRAM_BASE,
		.size = 255UL * SZ_1G,
		.attrs = PTE_BLOCK_MEMTYPE(MT_NORMAL) |
			 PTE_BLOCK_INNER_SHARE
	}, {
		/* List terminator */
		0,
	}
};

struct mm_region *mem_map = pvmfw_mem_map;

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

void *board_fdt_blob_setup(void)
{
	return fw_dtb_pointer;
}

int misc_init_r(void)
{
	env_set_hex("fdt_addr", (u64)fw_dtb_pointer);
	env_set_hex("kernel_image_addr", (u64)fw_kernel_image_pointer);
	return 0;
}

ulong board_get_usable_ram_top(ulong total_size)
{
	return gd->ram_top - CROSVM_FDT_MAX_SIZE - CROSVM_EXTRA_SUBTRACT;
}

void enable_caches(void)
{
	 icache_enable();
	 dcache_enable();
}
