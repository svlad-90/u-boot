// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2022 Google LLC
 */

#include <asm/global_data.h>
#include <dt-bindings/interrupt-controller/arm-gic.h>
#include <fdt_support.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <string.h>

#include "generate_fdt.h"

DECLARE_GLOBAL_DATA_PTR;

#define GIC_REDIST_SIZE_PER_CPU			0x20000

#define AARCH64_RTC_ADDR			0x2000
#define AARCH64_RTC_SIZE			0x1000
#define AARCH64_RTC_PERIPH_ID			0x41030
#define AARCH64_CLOCK_FREQ			0x2fefd8

#define AARCH64_VMWDT_ADDR			0x3000
#define AARCH64_VMWDT_SIZE			0x1000
#define AARCH64_VMWDT_INSTANCE_SIZE		0x10
#define AARCH64_VMWDT_MAX_CPU_COUNT		(AARCH64_VMWDT_SIZE /	\
						 AARCH64_VMWDT_INSTANCE_SIZE)

#define FDT_CELLS_PER_PCI_RANGE		7
#define FDT_CELLS_PER_PCI_IRQ		10
#define FDT_CELLS_PER_PCI_IRQ_MASK	4

#define PCI_DEVICE_IDX			11
#define PCI_IRQ_MASK_ADDR_HI		GENMASK(15, PCI_DEVICE_IDX)
#define PCI_IRQ_MASK_ADDR_ME		0
#define PCI_IRQ_MASK_ADDR_LO		0
#define PCI_IRQ_MASK_ANY_IRQ		0x7

#define PCI_IRQ_ADDR_ME			0
#define PCI_IRQ_ADDR_LO			0
#define PCI_IRQ_INTC			1

#define FDT_PCI_FIRST_IRQ_NUMBER	3

#define TRY(expr) \
	({ \
		int _fdt_err = (expr); \
		if (_fdt_err < 0) \
			return -EIO; \
		_fdt_err; \
	})
#define TRY_OPTIONAL(expr) \
	({ \
		int _fdt_err_opt = (expr); \
		_fdt_err_opt == -FDT_ERR_NOTFOUND ? _fdt_err_opt \
						  : TRY(_fdt_err_opt); \
	})
#define TRY_FDT_GETPROP(fdt, node, name, sizeptr) \
	({ \
		int _len; \
		const void *_ptr = fdt_getprop(fdt, node, name, &_len); \
		if (!_ptr) \
			TRY(_len); \
		*(sizeptr) = _len; \
		_ptr; \
	})

#define fdt_for_each_compatible(node, fdt, c) \
	for (node = TRY_OPTIONAL(fdt_node_offset_by_compatible(fdt, -1, c)); \
	     node >= 0; \
	     node = TRY_OPTIONAL(fdt_node_offset_by_compatible(fdt, node, c)))

#define fdt_for_each_compatible_safe(node, fdt, c, next) \
	for (node = TRY_OPTIONAL(fdt_node_offset_by_compatible(fdt, -1, c)), \
	     next = TRY_OPTIONAL(fdt_node_offset_by_compatible(fdt, node, c)); \
	     node >= 0; \
	     node = next, \
	     next = TRY_OPTIONAL(fdt_node_offset_by_compatible(fdt, node, c)))

static uint64_t fdt32_to_cpu64(fdt32_t hi, fdt32_t lo)
{
	return ((uint64_t)fdt32_to_cpu(hi) << 32) | fdt32_to_cpu(lo);
}

static void cpu64_to_fdt32(uint64_t val, fdt32_t *hi, fdt32_t *lo)
{
	*hi = cpu_to_fdt32((uint32_t)(val >> 32));
	*lo = cpu_to_fdt32((uint32_t)val);
}

static int fdt_getprop_u64(const void *fdt, int node, const char *name,
			   uint64_t *dest)
{
	int len;
	const fdt64_t *prop = TRY_FDT_GETPROP(fdt, node, name, &len);

	if (len != sizeof(*dest))
		return -FDT_ERR_TRUNCATED;

	*dest = fdt64_to_cpu(*prop);

	return 0;
}

static int fdt_getprop_u32(const void *fdt, int node, const char *name,
			   uint32_t *dest)
{
	int len;
	const fdt32_t *prop = TRY_FDT_GETPROP(fdt, node, name, &len);

	if (len != sizeof(*dest))
		return -FDT_ERR_TRUNCATED;

	*dest = fdt32_to_cpu(*prop);

	return 0;
}

static int fdt_getpair_u64(const void* fdt, int node, const char *name,
			   uint64_t *first, uint64_t *second)
{
	int len;
	const fdt64_t *prop = TRY_FDT_GETPROP(fdt, node, name, &len);

	if (len != sizeof(*first) + sizeof(*second))
		return -FDT_ERR_TRUNCATED;

	*first = fdt64_to_cpu(prop[0]);
	*second = fdt64_to_cpu(prop[1]);

	return 0;
}

static int fdt_setpair_inplace_u64(void *fdt, int node, const char *name,
				   uint64_t first, uint64_t second)
{
	const fdt64_t vals[] = {
		cpu_to_fdt64(first),
		cpu_to_fdt64(second),
	};

	return fdt_setprop_inplace(fdt, node, name, vals, sizeof(vals));
}

static int fdt_getprop_array(const void *fdt, int node, const char *name,
			     const void **prop, size_t size)
{
	int len;
	*prop = TRY_FDT_GETPROP(fdt, node, name, &len);

	if (len != size)
		return -FDT_ERR_BADVALUE;

	return 0;
}

static int fdt_trim_prop(void *fdt, int node, const char *name, void *buf,
			 size_t smaller_size)
{
	int len;
	const void *prop = TRY_FDT_GETPROP(fdt, node, name, &len);

	if (len < smaller_size)
		return -EINVAL;
	if (len == smaller_size)
		return 0;

	/* Not ideal but simple w.r.t. libfdt calls. */
	memcpy(buf, prop, len);
	TRY(fdt_delprop(fdt, node, name));
	TRY(fdt_appendprop(fdt, node, name, buf, smaller_size));

	return 0;
}

static int parse_cpu_nodes(const void *fdt, struct boot_config *cfg)
{
	int node;
	size_t count = 0;

	fdt_for_each_compatible(node, fdt, "arm,arm-v8")
		count++;

	if (count == 0)
		count = 1;

	cfg->cpu_count = count;

	return 0;
}

static int patch_cpu_nodes(void *fdt, const struct boot_config *cfg)
{
	int node, tmp;
	size_t rem = cfg->cpu_count;

	fdt_for_each_compatible_safe(node, fdt, "arm,arm-v8", tmp) {
		if (rem)
			rem--;
		else
			TRY(fdt_nop_node(fdt, node));
	}

	return rem ? -E2BIG : 0;
}

static int parse_memory_node(const void *fdt, struct boot_config *cfg)
{
	uint64_t addr, size;
	int node = TRY(fdt_path_offset(fdt, "/memory"));

	TRY(fdt_getpair_u64(fdt, node, "reg", &addr, &size));

	if (addr != CONFIG_SYS_SDRAM_BASE)
		return -EINVAL;

	if (size % PAGE_SIZE || size < gd->ram_size || size > UINT64_MAX - addr)
		return -EINVAL;

	cfg->memsize = size;

	return 0;
}

static int patch_memory_node(void *fdt, const struct boot_config *cfg)
{
	uint64_t addr = CONFIG_SYS_SDRAM_BASE;
	int node = TRY(fdt_path_offset(fdt, "/memory"));

	TRY(fdt_setpair_inplace_u64(fdt, node, "reg", addr, cfg->memsize));

	return 0;
}

static int patch_gic_node(void *fdt, const struct boot_config *cfg)
{
	const void *reg;
	fdt64_t buf[4];
	uint64_t addr, size;
	int node = TRY(fdt_node_offset_by_compatible(fdt, 0, "arm,gic-v3"));

	TRY(fdt_getprop_array(fdt, node, "reg", &reg, sizeof(buf)));

	memmove(buf, reg, sizeof(buf));

	addr = fdt64_to_cpu(buf[0]);
	size = cfg->cpu_count * GIC_REDIST_SIZE_PER_CPU;

	buf[2] = cpu_to_fdt64(addr - size);
	buf[3] = cpu_to_fdt64(size);

	TRY(fdt_setprop_inplace(fdt, node, "reg", buf, sizeof(buf)));

	return 0;
}

static int parse_pci_range(const fdt32_t *range, uint64_t *addr, uint64_t *size)
{
	if (range[0] != cpu_to_fdt32(FDT_PCI_SPACE_MEM64))
		return -FDT_ERR_BADVALUE;

	*addr = fdt32_to_cpu64(range[1], range[2]);

	/* Enforce ID bus-to-cpu mappings, as used by crosvm. */
	 if (*addr != fdt32_to_cpu64(range[3], range[4]))
		return -FDT_ERR_BADVALUE;

	*size = fdt32_to_cpu64(range[5], range[6]);

	return 0;
}

static int count_pci_irq_masks(const void *fdt, int node, size_t *count)
{
	int size;
	const fdt32_t (*masks)[FDT_CELLS_PER_PCI_IRQ_MASK];

	masks = TRY_FDT_GETPROP(fdt, node, "interrupt-map-mask", &size);
	if (size % sizeof(*masks) || !size)
		return -EINVAL;

	*count = size / sizeof(*masks);
	for (size_t i = 0; i < *count; i++)
		if (masks[i][0] != cpu_to_fdt32(PCI_IRQ_MASK_ADDR_HI) ||
		    masks[i][1] != cpu_to_fdt32(PCI_IRQ_MASK_ADDR_ME) ||
		    masks[i][2] != cpu_to_fdt32(PCI_IRQ_MASK_ADDR_LO) ||
		    masks[i][3] != cpu_to_fdt32(PCI_IRQ_MASK_ANY_IRQ))
			return -EINVAL;

	return 0;
}

static int validate_pci_irqs(const void *fdt, int node, size_t count)
{
	uint32_t addr = 0, irq_nr = FDT_PCI_FIRST_IRQ_NUMBER;
	const fdt32_t (*irqs)[FDT_CELLS_PER_PCI_IRQ];

	TRY(fdt_getprop_array(fdt, node, "interrupt-map", (const void **)&irqs,
			      sizeof(*irqs) * count));

	for (size_t i = 0; i < count; i++) {
		addr += BIT(PCI_DEVICE_IDX);
		if (irqs[i][0] != cpu_to_fdt32(addr) ||
		    irqs[i][1] != cpu_to_fdt32(PCI_IRQ_ADDR_ME) ||
		    irqs[i][2] != cpu_to_fdt32(PCI_IRQ_ADDR_LO) ||
		    irqs[i][3] != cpu_to_fdt32(PCI_IRQ_INTC) ||
		    /* Skip GIC phandle */ irqs[i][5] || irqs[i][6] ||
		    irqs[i][7] != cpu_to_fdt32(GIC_SPI) ||
		    irqs[i][8] != cpu_to_fdt32(irq_nr++) ||
		    irqs[i][9] != cpu_to_fdt32(IRQ_TYPE_LEVEL_HIGH))
			return -EINVAL;
	}

	return 0;
}

static int parse_pci_node(const void *fdt, struct boot_config *cfg)
{
	int res;
	const fdt32_t (*ranges)[FDT_CELLS_PER_PCI_RANGE];
	int node = TRY(fdt_node_offset_by_compatible(fdt, 0,
						     "pci-host-cam-generic"));

	TRY(fdt_getprop_array(fdt, node, "ranges", (const void **)&ranges,
			      sizeof(ranges[0]) * 2));

	TRY(parse_pci_range(ranges[0], &cfg->pci_lo_addr, &cfg->pci_lo_size));
	if (cfg->pci_lo_size > UINT64_MAX - cfg->pci_lo_addr)
		return -EINVAL;

	TRY(parse_pci_range(ranges[1], &cfg->pci_hi_addr, &cfg->pci_hi_size));
	if (cfg->pci_hi_size > UINT64_MAX - cfg->pci_hi_addr)
		return -EINVAL;

	res = count_pci_irq_masks(fdt, node, &cfg->pci_irq_count);
	if (res)
		return res;

	return validate_pci_irqs(fdt, node, cfg->pci_irq_count);
}

static int patch_pci_node_ranges(void *fdt, int node,
				 const struct boot_config *cfg)
{
	uint64_t addr, size;
	fdt32_t buf[2][FDT_CELLS_PER_PCI_RANGE];
	const void *ranges;

	if (cfg->pci_hi_addr < gd->ram_base + cfg->memsize)
		return -EINVAL;

	TRY(fdt_getprop_array(fdt, node, "ranges", (const void **)&ranges,
			      sizeof(buf)));
	memmove(buf, ranges, sizeof(buf));

	TRY(parse_pci_range(ranges, &addr, &size));
	if (cfg->pci_lo_addr != addr || cfg->pci_lo_size != size)
		return -EINVAL;

	cpu64_to_fdt32(cfg->pci_hi_addr, &buf[1][1], &buf[1][2]);
	cpu64_to_fdt32(cfg->pci_hi_addr, &buf[1][3], &buf[1][4]);
	cpu64_to_fdt32(cfg->pci_hi_size, &buf[1][5], &buf[1][6]);

	TRY(fdt_setprop_inplace(fdt, node, "ranges", buf, sizeof(buf)));

	return 0;
}

static int patch_pci_node(void *fdt, const struct boot_config *cfg)
{
	int res;
	fdt32_t buf[16][max(FDT_CELLS_PER_PCI_IRQ, FDT_CELLS_PER_PCI_IRQ_MASK)];
	int node = TRY(fdt_node_offset_by_compatible(fdt, 0,
						     "pci-host-cam-generic"));

	if (cfg->pci_irq_count > ARRAY_SIZE(buf))
		return -EINVAL;

	res = fdt_trim_prop(fdt, node, "interrupt-map", buf,
			    (cfg->pci_irq_count * sizeof(fdt32_t) *
			     FDT_CELLS_PER_PCI_IRQ));
	if (res)
		return res;

	res = fdt_trim_prop(fdt, node, "interrupt-map-mask", buf,
			    (cfg->pci_irq_count * sizeof(fdt32_t) *
			     FDT_CELLS_PER_PCI_IRQ_MASK));
	if (res)
		return res;

	return patch_pci_node_ranges(fdt, node, cfg);
}

static int parse_serial_nodes(const void *fdt, struct boot_config *cfg)
{
	uint64_t sz;
	int node;
	size_t i = 0;

	fdt_for_each_compatible(node, fdt, "ns16550a") {
		if (i >= ARRAY_SIZE(cfg->serials))
			return -E2BIG;
		TRY(fdt_getpair_u64(fdt, node, "reg", &cfg->serials[i++], &sz));
	}

	cfg->serials_count = i;

	return 0;
}

static bool array_contains(const uint64_t *arr, uint64_t val, size_t size)
{
	for (size_t i = 0; i < size; i++)
		if (arr[i] == val)
			return true;

	return false;
}

static int patch_serial_node(void *fdt, const struct boot_config *cfg)
{
	uint64_t addr, size;
	int node, tmp;

	fdt_for_each_compatible_safe(node, fdt, "ns16550a", tmp) {
		TRY(fdt_getpair_u64(fdt, node, "reg", &addr, &size));

		if (!array_contains(cfg->serials, addr, cfg->serials_count))
			TRY(fdt_nop_node(fdt, node));
	}

	return 0;
}

#define AS_CPU_MASK(n)		(((BIT(n) - 1) & 0xff) << 8)

static int patch_timer_node(void *fdt, const struct boot_config *cfg)
{
	fdt32_t buf[12];
	const void *irqs;
	const fdt32_t cpu_mask = cpu_to_fdt32(AS_CPU_MASK(cfg->cpu_count));
	int node = TRY(fdt_node_offset_by_compatible(fdt, -1, "arm,armv8-timer"));

	TRY(fdt_getprop_array(fdt, node, "interrupts", &irqs, sizeof(buf)));

	memmove(buf, irqs, sizeof(buf));

	for (size_t i = 2; i < ARRAY_SIZE(buf); i += 3) {
		/* Skip IRQ PPI/SPI (1 cell) */
		/* Skip IRQ number (1 cell) */
		buf[i] |= cpu_mask;
	}

	TRY(fdt_setprop_inplace(fdt, node, "interrupts", buf, sizeof(buf)));

	return 0;
}

static int parse_swiotlb_node(const void *fdt, struct boot_config *cfg)
{
	int node = TRY(fdt_node_offset_by_compatible(fdt, -1,
						     "restricted-dma-pool"));

	TRY(fdt_getprop_u64(fdt, node, "size", &cfg->swiotlb_size));
	TRY(fdt_getprop_u64(fdt, node, "alignment", &cfg->swiotlb_align));

	if (!cfg->swiotlb_size || cfg->swiotlb_size % PAGE_SIZE)
		return -EINVAL;

	/* We trust the guest to validate this size beyond these checks. */

	if (cfg->swiotlb_align % PAGE_SIZE)
		return -EINVAL;

	return 0;
}

static int patch_swiotlb_node(void *fdt, const struct boot_config *cfg)
{
	int node = TRY(fdt_node_offset_by_compatible(fdt, -1,
						     "restricted-dma-pool"));

	TRY(fdt_setprop_inplace_u64(fdt, node, "size", cfg->swiotlb_size));
	TRY(fdt_setprop_inplace_u64(fdt, node, "alignment",
				    cfg->swiotlb_align));

	return 0;
}

static int patch_chosen_node(void *fdt, const struct boot_config *cfg)
{
	int len;
	const char *path;
	int node = TRY(fdt_path_offset(fdt, "/chosen"));

	/* "stdout-path" should always be in the base DT! */
	path = TRY_FDT_GETPROP(fdt, node, "stdout-path", &len);

	/* If "stdout-path" points to a node that has been removed, NOP it. */
	if (TRY_OPTIONAL(fdt_path_offset(fdt, path)) == -FDT_ERR_NOTFOUND)
		TRY(fdt_nop_property(fdt, node, "stdout-path"));

	if (!cfg->new_instance)
		TRY(fdt_nop_property(fdt, node, "avf,new-instance"));

	/* '/chosen/avf,strict-boot' is always set (from the base DT) */

	TRY(fdt_setprop_inplace_u64(fdt, node, "kaslr-seed", cfg->kaslr_seed));

	return 0;
}

static int patch_resmem_node(void *fdt, const struct boot_config *cfg)
{
	int node = TRY(fdt_path_offset(fdt, "/reserved-memory/dice"));

	TRY(fdt_setpair_inplace_u64(fdt, node, "reg", cfg->bcc_addr,
				    cfg->bcc_size));

	return 0;
}

static int parse_clock_node(const void *fdt, struct boot_config *cfg)
{
	int node;
	uint32_t freq;

	node = TRY(fdt_node_offset_by_compatible(fdt, 0, "fixed-clock"));
	TRY(fdt_getprop_u32(fdt, node, "clock-frequency", &freq));
	TRY(fdt_getprop_u32(fdt, node, "phandle", &cfg->clk_phandle));

	if (freq != AARCH64_CLOCK_FREQ)
		return -EINVAL;

	if (!cfg->clk_phandle || cfg->clk_phandle == (uint32_t)(-1))
		return -EINVAL;

	return 0;
}

static int parse_rtc_node(const void *fdt, struct boot_config *cfg)
{
	int node;
	uint64_t addr = 0x0, size = 0;
	uint32_t rtc_periph_id, clk_phandle;

	fdt_for_each_compatible(node, fdt, "arm,primecell") {
		if (fdt_getprop_u32(fdt, node, "arm,primecell-periphid",
				    &rtc_periph_id))
			continue;

		if (rtc_periph_id != AARCH64_RTC_PERIPH_ID)
			continue;

		TRY(fdt_getpair_u64(fdt, node, "reg", &addr, &size));
		TRY(fdt_getprop_u32(fdt, node, "clocks", &clk_phandle));
		break;
	}

	if (size != AARCH64_RTC_SIZE || addr != AARCH64_RTC_ADDR ||
	    clk_phandle != cfg->clk_phandle)
		return -EINVAL;

	return 0;
}

static int parse_wdt_node(const void *fdt, struct boot_config *cfg)
{
	int node;
	uint64_t addr, size;

	node = TRY(fdt_node_offset_by_compatible(fdt, 0,
						 "qemu,vcpu-stall-detector"));
	TRY(fdt_getpair_u64(fdt, node, "reg", &addr, &size));

	/* Verify the CPU count as we don't want our device to write past
	 * the allocated size.
	 */
	if (size != AARCH64_VMWDT_SIZE || addr != AARCH64_VMWDT_ADDR ||
	    cfg->cpu_count > AARCH64_VMWDT_MAX_CPU_COUNT)
		return -EINVAL;

	return 0;
}

int parse_input_fdt(const void *fdt, struct boot_config *cfg)
{
	int err;

	if ((uintptr_t)fdt != CROSVM_FDT_ADDR)
		return -EFAULT;

	TRY(fdt_check_header(fdt));

	if (fdt_totalsize(fdt) > CROSVM_FDT_MAX_SIZE)
		return -E2BIG;

	err = parse_memory_node(fdt, cfg);
	if (err)
		return err;

	err = parse_cpu_nodes(fdt, cfg);
	if (err)
		return err;

	err = parse_pci_node(fdt, cfg);
	if (err)
		return err;

	err = parse_serial_nodes(fdt, cfg);
	if (err)
		return err;

	err = parse_swiotlb_node(fdt, cfg);
	if (err)
		return err;

	err = parse_clock_node(fdt, cfg);
	if (err)
		return err;

	err = parse_rtc_node(fdt, cfg);
	if (err)
		return err;

	err = parse_wdt_node(fdt, cfg);
	if (err)
		return err;

	return 0;
}

int patch_output_fdt(void *fdt, const struct boot_config *cfg)
{
	int err;

	err = patch_memory_node(fdt, cfg);
	if (err)
		return err;

	err = patch_cpu_nodes(fdt, cfg);
	if (err)
		return err;

	err = patch_pci_node(fdt, cfg);
	if (err)
		return err;

	err = patch_serial_node(fdt, cfg);
	if (err)
		return err;

	err = patch_gic_node(fdt, cfg);
	if (err)
		return err;

	err = patch_timer_node(fdt, cfg);
	if (err)
		return err;

	err = patch_swiotlb_node(fdt, cfg);
	if (err)
		return err;

	err = patch_resmem_node(fdt, cfg);
	if (err)
		return err;

	/* Keep patch_chosen_node() last as it relies on other nodes. */
	return patch_chosen_node(fdt, cfg);
}

int transfer_fdt_template(void *fdt)
{
	extern const char next_stage_fdt_template[];
	extern const size_t next_stage_fdt_template_size;
	size_t rem;

	if (next_stage_fdt_template_size > CROSVM_FDT_MAX_SIZE)
		return -ENOMEM;

	rem = CROSVM_FDT_MAX_SIZE - next_stage_fdt_template_size;

	memcpy(fdt, next_stage_fdt_template, next_stage_fdt_template_size);
	memset(fdt + next_stage_fdt_template_size, 0, rem);

	return 0;
}
