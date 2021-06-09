// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 Google LLC
 * Author: Elena Petrova <lenaptr@google.com>
 */

#include <config.h>

/*
 * Routine: save_boot_params (called after reset from start.S)
 * Description: save FDT address provided by the firmware at boot time
 */

.global save_boot_params
save_boot_params:

	adr	x8, fw_dtb_pointer
	str	x0, [x8]

	adr	x8, fw_kernel_image_pointer
	str	x1, [x8]

	/* Returns */
	b	save_boot_params_ret
