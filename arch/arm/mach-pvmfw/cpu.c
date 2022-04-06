// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Google LLC
 */

#include <linux/arm-smccc.h>
#include <linux/errno.h>

static int kvm_hyp_mmio_enroll(void)
{
	struct arm_smccc_res res;

	arm_smccc_hvc(ARM_SMCCC_VENDOR_HYP_KVM_MMIO_GUARD_ENROLL_FUNC_ID,
		      0, 0, 0, 0, 0, 0, 0, &res);

	return res.a0 != SMCCC_RET_SUCCESS ? -EINVAL : 0;
}

int mach_cpu_init(void)
{
	/*
	 *  Enroll into the MMIO guard pKVM feature before any MMIO takes place
	 *  (in particular, before DM and console are initialized). We may
	 *  assume that the necessary SMCCC and PSCI features are available
	 *  given that are running in a pVM.
	 */
	return kvm_hyp_mmio_enroll();
}
