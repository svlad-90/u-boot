// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2021 Google LLC
 */

#ifndef __LIB_BORINGSSL_PATCH_STDIO_H
#define __LIB_BORINGSSL_PATCH_STDIO_H

/* U-Boot does not adhere to libc API */
#include <vsprintf.h>	/* declares vsnprintf() */
typedef int FILE;	/* dummy type to please the compiler */

/* U-Boot's stdio.h includes <linux/compiler.h> which unconditionally
 * defines "fallthrough", but this breaks subsequent __has_attribute()
 * checks in boringssl, so include the header earlier and undefine it.
 */
#include <linux/compiler.h>
#undef fallthrough

#endif
