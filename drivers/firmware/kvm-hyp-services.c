// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Google LLC
 */

#include <common.h>
#include <dm.h>
#include <malloc.h>
#include <virtio_types.h>
#include <virtio.h>
#include <linux/arm-smccc.h>
#include <linux/compat.h>
#include <asm/io.h>

extern struct virtio_iommu_platform_ops *virtio_iommu_platform_ops;

static int kvm_hyp_mem_share(struct udevice *udev, void *addr, u32 npages)
{
	while (npages--) {
		struct arm_smccc_res res;
		phys_addr_t phys = virt_to_phys(addr);

		arm_smccc_hvc(ARM_SMCCC_VENDOR_HYP_KVM_MEM_SHARE_FUNC_ID,
			      phys, 0, 0, 0, 0, 0, 0, &res);
		if (res.a0 != SMCCC_RET_SUCCESS)
			return -EPERM;

		addr += PAGE_SIZE;
	}

	return 0;
}

static int kvm_hyp_mem_unshare(struct udevice *udev, void *addr, u32 npages)
{
	while (npages--) {
		struct arm_smccc_res res;
		phys_addr_t phys = virt_to_phys(addr);

		arm_smccc_hvc(ARM_SMCCC_VENDOR_HYP_KVM_MEM_UNSHARE_FUNC_ID,
			      phys, 0, 0, 0, 0, 0, 0, &res);
		if (res.a0 != SMCCC_RET_SUCCESS)
			return -EPERM;

		addr += PAGE_SIZE;
	}

	return 0;
}

static int kvm_hyp_memshare_init(unsigned long features)
{
	static struct virtio_iommu_platform_ops ops = {
		.map	= kvm_hyp_mem_share,
		.unmap	= kvm_hyp_mem_unshare,
	};
	struct arm_smccc_res res;

	arm_smccc_hvc(ARM_SMCCC_VENDOR_HYP_KVM_HYP_MEMINFO_FUNC_ID,
		      0, 0, 0, 0, 0, 0, 0, &res);

	if (res.a0 != PAGE_SIZE)
		return -ENXIO;

	virtio_iommu_platform_ops = &ops;
	return 0;
}

static int kvm_hyp_services_bind(struct udevice *dev)
{
	int ret = 0;
	struct arm_smccc_res res;

	arm_smccc_hvc(ARM_SMCCC_VENDOR_HYP_CALL_UID_FUNC_ID,
		      0, 0, 0, 0, 0, 0, 0, &res);
	if (res.a0 != ARM_SMCCC_VENDOR_HYP_UID_KVM_REG_0 ||
	    res.a1 != ARM_SMCCC_VENDOR_HYP_UID_KVM_REG_1 ||
	    res.a2 != ARM_SMCCC_VENDOR_HYP_UID_KVM_REG_2 ||
	    res.a3 != ARM_SMCCC_VENDOR_HYP_UID_KVM_REG_3)
		return -ENXIO;

	memset(&res, 0, sizeof(res));
	arm_smccc_hvc(ARM_SMCCC_VENDOR_HYP_KVM_FEATURES_FUNC_ID,
		      0, 0, 0, 0, 0, 0, 0, &res);

	if (res.a0 & BIT(ARM_SMCCC_KVM_FUNC_HYP_MEMINFO))
		ret = kvm_hyp_memshare_init(res.a0);

	pr_debug("Probed KVM hypervisor services: 0x%08x\n", (u32)res.a0);
	return ret;
}

U_BOOT_DRIVER(kvm_hyp_services) = {
	.name = "kvm-hyp-services",
	.id = UCLASS_FIRMWARE,
	.bind = kvm_hyp_services_bind,
};
