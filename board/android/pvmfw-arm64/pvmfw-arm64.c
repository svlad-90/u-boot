// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2017 Tuomas Tynkkynen
 * Copyright (C) 2021 Google LLC
 */

#include <common.h>
#include <cpu_func.h>
#include <dm.h>
#include <fdtdec.h>
#include <init.h>
#include <log.h>
#include <virtio_types.h>
#include <virtio.h>

#include <asm/armv8/mmu.h>

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
	/* QEMU loads a generated DTB for us at the start of RAM. */
	return (void *)CONFIG_SYS_SDRAM_BASE;
}

void enable_caches(void)
{
	 icache_enable();
	 dcache_enable();
}
