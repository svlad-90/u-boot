// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2022 Google LLC
 */

#ifndef _PVMFW_AVB_PRELOADED_H
#define _PVMFW_AVB_PRELOADED_H

#include <avb_verify.h>  // for libavb
#include <linux/kernel.h>
#include <linux/types.h>

struct AvbOps *avb_preloaded_alloc(void);
int avb_preloaded_add_part(struct AvbOps *ops, const char *name, void *addr,
			   size_t size);
void avb_preloaded_free(struct AvbOps *ops);

#endif
