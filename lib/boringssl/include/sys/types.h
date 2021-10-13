// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2021 Google LLC
 */

#ifndef __LIB_BORINGSSL_SYS_TYPES_H
#define __LIB_BORINGSSL_SYS_TYPES_H

#include <linux/const.h>
#include <linux/types.h>

#define UINT8_C(value)    _AT(uint8_t,_AC(value,U))
#define UINT32_C(value)   UL(value)
#define UINT64_C(value)   ULL(value)

#endif
