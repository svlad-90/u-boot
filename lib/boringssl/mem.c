// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2021 Google LLC
 */

#include <malloc.h>
#include <linux/bug.h>

void *OPENSSL_memory_alloc(size_t size)
{
	return malloc(size);
}

void OPENSSL_memory_free(void *ptr)
{
	free(ptr);
}

size_t OPENSSL_memory_get_size(void *ptr)
{
	return malloc_usable_size(ptr);
}

void sdallocx(void *ptr, size_t size, int flags)
{
	BUG();
}
