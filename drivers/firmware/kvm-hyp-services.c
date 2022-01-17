// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Google LLC
 */

#include <common.h>
#include <dm.h>

static int kvm_hyp_services_bind(struct udevice *dev)
{
	return 0;
}

U_BOOT_DRIVER(kvm_hyp_services) = {
	.name = "kvm-hyp-services",
	.id = UCLASS_FIRMWARE,
	.bind = kvm_hyp_services_bind,
};
