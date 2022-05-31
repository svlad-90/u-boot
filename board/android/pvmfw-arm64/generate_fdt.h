// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2022 Google LLC
 */

#ifndef _PVMFW_GENRATE_FDT_H
#define _PVMFW_GENRATE_FDT_H

#include <linux/types.h>

/**
 * As pvmfw is responsible for providing the next stage with a DT it can trust
 * while some degree of flexibility should be allowed to the VMM (and its
 * clients in host userspace) w.r.t. the specification of the platform, we
 *
 *  - parse the input DT into a boot_config
 *  - transfer a template DT from .rodata to where the next stage expects it
 *  - update the template DT using the boot_config
 *
 * This allows the VMM (host) to configure the following parameters:
 *
 *  - number of CPUs
 *  - size of RAM (but fixed base address)
 *  - size of reserved DMA memory region
 *  - available standard IBM PC 16550 UART serial ports
 */

struct boot_config {
	size_t cpu_count;
	uint64_t memsize;
	uint64_t pci_hi_addr;
	uint64_t pci_hi_size;
	uint64_t pci_lo_addr;
	uint64_t pci_lo_size;
	size_t pci_irq_count;
	size_t serials_count;
	uint64_t serials[4];
	uint64_t kaslr_seed;
	uint64_t swiotlb_size;
	uint64_t swiotlb_align;
	uint64_t bcc_addr;
	uint64_t bcc_size;
	bool new_instance;
};

int parse_input_fdt(const void *fdt, struct boot_config *cfg);
int transfer_fdt_template(void *fdt);
int patch_output_fdt(void *fdt, const struct boot_config *cfg);

#endif
