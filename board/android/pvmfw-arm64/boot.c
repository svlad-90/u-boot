// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2022 Google LLC
 */

#include <asm/global_data.h>

#include <android_bootloader.h>
#include <android_image.h>
#include <avb_verify.h>
#include <bcc.h>
#include <command.h>
#include <config.h>
#include <fdt_support.h>
#include <malloc.h>
#include <string.h>
#include <linux/err.h>

#include "avb_preloaded.h"

/* This assumes reserved-memory#address-cells/size-cells <= 2 */
#define DICE_NODE_SIZE			96
#define RSV_MEM_SIZE			(DICE_NODE_SIZE + 128)
#define COMPAT_DICE			"google,open-dice"

#define CHOSEN_MEM_SIZE			64

/* Taken from libavb/avb_slot_verify.c */
#define VBMETA_MAX_SIZE			SZ_64K

DECLARE_GLOBAL_DATA_PTR;

static bool is_valid_ram(const void *ptr)
{
	uintptr_t addr = (uintptr_t)ptr;

	return CONFIG_SYS_SDRAM_BASE <= addr && addr < gd->ram_top;
}

static bool is_valid_ram_region(const void *ptr, size_t size)
{
	return is_valid_ram(ptr) && (size <= gd->ram_top - (uintptr_t)ptr);
}

static int alloc_subnode(void *fdt, int parentoffset, const char *name,
			 size_t size)
{
	int offset, res;

	offset = fdt_add_subnode(fdt, parentoffset, name);
	if (offset != -FDT_ERR_NOSPACE)
		return offset;

	res = fdt_increase_size(fdt, size);
	if (res)
		return res;

	return fdt_add_subnode(fdt, parentoffset, name);
}

static int find_or_alloc_subnode(void *fdt, int parentoffset, const char *name,
				 size_t size)
{
	int offset;

	offset = fdt_subnode_offset(fdt, parentoffset, name);
	if (offset != -FDT_ERR_NOTFOUND)
		return offset;

	return alloc_subnode(fdt, parentoffset, name, size);
}

static bool pvmfw_fdt_is_valid(const void *fdt)
{
	int offset;

	/* Reject DICE-compatible DT nodes. */
	offset = fdt_node_offset_by_compatible(fdt, -1, COMPAT_DICE);
	if (offset != -FDT_ERR_NOTFOUND)
		return false;

	/* Reject "/reserved-memory/dice" nodes. */
	offset = fdt_subnode_offset(fdt, -1, "reserved-memory");
	if (offset >= 0)
		offset = fdt_subnode_offset(fdt, offset, "dice");
	if (offset != -FDT_ERR_NOTFOUND)
		return false;

	return true;
}

static int add_dice_fdt_mem_rsv(void *fdt, void *addr, size_t size)
{
	int mem, dice, err;

	mem = find_or_alloc_subnode(fdt, 0, "reserved-memory", RSV_MEM_SIZE);
	if (mem < 0)
		return mem;

	dice = alloc_subnode(fdt, mem, "dice", DICE_NODE_SIZE);
	if (dice < 0)
		return dice;

	err = fdt_appendprop_addrrange(fdt, mem, dice, "reg",
				       (uint64_t)addr, size);
	if (err)
		return err;

	err = fdt_appendprop(fdt, dice, "no-map", NULL, 0);
	if (err)
		return err;

	err = fdt_appendprop_string(fdt, dice, "compatible", COMPAT_DICE);
	if (err)
		return err;

	return dice;
}

static int add_avf_fdt_chosen_properties(void *fdt, bool new_instance)
{
	int chosen, err;

	chosen = find_or_alloc_subnode(fdt, 0, "chosen", CHOSEN_MEM_SIZE);
	if (chosen < 0)
		return chosen;

	err = fdt_increase_size(fdt, CHOSEN_MEM_SIZE);
	if (err)
		return err;

	err = fdt_appendprop(fdt, chosen, "avf,strict-boot", NULL, 0);
	if (err)
		return err;

	if (new_instance) {
		err = fdt_appendprop(fdt, chosen, "avf,new-instance", NULL, 0);
		if (err)
			return err;
	} else {
		err = fdt_delprop(fdt, chosen, "avf,new-instance");
		if (err && err != -FDT_ERR_NOTFOUND)
			return err;
	}

	return 0;
}

static struct AvbOps *alloc_avb_ops(void *image, size_t size)
{
	int error;
	AvbFooter footer;
	const void *avb_footer = image + size - AVB_FOOTER_SIZE;
	struct AvbOps *ops = avb_preloaded_alloc();

	if (!ops)
		return NULL;

	if (!avb_footer_validate_and_byteswap(avb_footer, &footer) ||
	    !is_valid_ram_region(image, footer.original_image_size) ||
	    !is_valid_ram_region(image + footer.vbmeta_offset, VBMETA_MAX_SIZE))
		goto free_ops;

	error = avb_preloaded_add_part(ops, "boot", image,
				       footer.original_image_size);
	if (error)
		goto free_ops;

	/*
	 * We can't simply use footer.vbmeta_size as avb_slot_verify() requires
	 * the partition to be VBMETA_MAX_SIZE; as the image was created through
	 * avbtool, there should always be enough 0-padding after the actual
	 * vbmeta data to safely meet that requirement.
	 */
	error = avb_preloaded_add_part(ops, "vbmeta",
				       image + footer.vbmeta_offset,
				       VBMETA_MAX_SIZE);
	if (error)
		goto free_ops;

	return ops;
free_ops:
	avb_preloaded_free(ops);
	return NULL;
}

static int verify_image(void *image, size_t size, void *fdt)
{
	const char *instance_uuid = "90d2174a-038a-4bc6-adf3-824848fc5825";
	const char *iface_str = "virtio";
	const int devnum = 1;
	int ret = 0;
	const char *parts[] = { "boot", NULL };
	AvbSlotVerifyData *data = NULL;
	struct AvbOps *ops = NULL;

	ops = alloc_avb_ops(image, size);
	if (!ops)
		return -ENOMEM;

	ret = avb_slot_verify(ops, parts, /*slot_suffix=*/"",
			      AVB_SLOT_VERIFY_FLAGS_NONE,
			      AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
			      &data);
	if (ret != AVB_SLOT_VERIFY_RESULT_OK) {
		ret = -EACCES;
		goto err;
	}

	ret = bcc_vm_instance_handover(iface_str, devnum, instance_uuid,
				       /*must_exist=*/false, "vm_entry",
				       BCC_MODE_NORMAL, data, NULL,
				       fdt, fdt_totalsize(fdt));
	if (ret < 0)
		goto err;

	ret = add_avf_fdt_chosen_properties(fdt, ret == BCC_VM_INSTANCE_CREATED);
	if (ret) {
		ret = -EIO;
		goto err;
	}

err:
	if (data)
		avb_slot_verify_data_free(data);
	if (ops)
		avb_preloaded_free(ops);

	return ret;
}

int pvmfw_boot_flow(void *fdt, void *image, size_t size, void *bcc,
		    size_t bcc_size)
{
	int ret;

	if (!size || !is_valid_ram_region(image, size) || !is_valid_ram(fdt)) {
		ret = -EPERM;
		goto err;
	}

	bcc_set_handover(bcc, bcc_size);

	if (!pvmfw_fdt_is_valid(fdt)) {
		ret = -EINVAL;
		goto err;
	}

	/*
	 * We inject the node in the DT before verifying the images
	 * to detect their potential corruption from this operation.
	 */
	ret = add_dice_fdt_mem_rsv(fdt, bcc, bcc_size);
	if (ret < 0) {
		ret = -EIO;
		goto err;
	}

	ret = verify_image(image, size, fdt);

err:
	if (ret)
		bcc_clear_memory(bcc, bcc_size);

	return ret;
}
