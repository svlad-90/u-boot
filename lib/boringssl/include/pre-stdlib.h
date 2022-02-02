// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2022 Google LLC
 */

#ifndef __LIB_BORINGSSL_PATCH_STLIB_H
#define __LIB_BORINGSSL_PATCH_STLIB_H

/* U-Boot does not adhere to libc API */
#include <vsprintf.h>
#define abort() panic("BoringSSL abort")

#endif
