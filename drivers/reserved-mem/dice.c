// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Google LLC
 */

#include <dm/device.h>
#include <dm/uclass.h>

static const struct udevice_id dice_match[] = {
	{ .compatible = "google,open-dice" },
	{}
};

U_BOOT_DRIVER(dice) = {
	.name		= "dice",
	.id		= UCLASS_DICE,
	.of_match	= dice_match,
};

UCLASS_DRIVER(dice) = {
	.id		= UCLASS_DICE,
	.name		= "dice",
};
