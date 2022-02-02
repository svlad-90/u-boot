// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2022 Google LLC
 */

#include <dm/uclass.h>
#include <openssl/rand.h>
#include <rng.h>

static void fill_with_entropy(uint8_t *out, size_t req)
{
	struct udevice *dev;
	int ret;

	ret = uclass_get_device(UCLASS_RNG, 0, &dev);
	if (ret)
		panic("CRYPTO_sysrand: no RNG device.\n");

	ret = dm_rng_read(dev, out, req);
	if (ret)
		panic("CRYPTO_sysrand: No RNG.\n");
}

void CRYPTO_sysrand(uint8_t *out, size_t req)
{
	fill_with_entropy(out, req);
}

void CRYPTO_sysrand_for_seed(uint8_t *out, size_t req)
{
	fill_with_entropy(out, req);
}

uint64_t CRYPTO_get_fork_generation(void)
{
	/* There's no forking to worry about in U-boot. */
	return 0;
}
