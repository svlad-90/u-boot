// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Google LLC
 */

#include <common.h>
#include <dm.h>
#include <linux/arm-smccc.h>
#include <linux/errno.h>
#include <rng.h>

#define DRIVER_NAME			"smccc-trng"

#define ARM_SMCCC_TRNG_MIN_VERSION	0x10000UL

#ifdef CONFIG_ARM64
#define ARM_SMCCC_TRNG_RND		ARM_SMCCC_TRNG_RND64
#else
#define ARM_SMCCC_TRNG_RND		ARM_SMCCC_TRNG_RND32
#endif

/* Those values are deliberately separate from the generic SMCCC definitions. */
#define TRNG_SUCCESS			0UL
#define TRNG_NOT_SUPPORTED		(-1)
#define TRNG_INVALID_PARAMETER		(-2)
#define TRNG_NO_ENTROPY			(-3)

struct smccc_trng_plat {
	void (*call)(unsigned long, unsigned long, unsigned long, unsigned long,
		     struct arm_smccc_res *);
};

static void smccc_trng_call_hvc(unsigned long fid, unsigned long arg0,
				unsigned long arg1, unsigned long arg2,
				struct arm_smccc_res *res)
{
	memset(res, 0, sizeof(*res));
	arm_smccc_hvc(fid, arg0, arg1, arg2, 0, 0, 0, 0, res);
}

static void smccc_trng_call_smc(unsigned long fid, unsigned long arg0,
				unsigned long arg1, unsigned long arg2,
				struct arm_smccc_res *res)
{
	memset(res, 0, sizeof(*res));
	arm_smccc_smc(fid, arg0, arg1, arg2, 0, 0, 0, 0, res);
}

/**
 * This driver assumes that its parent has checked that SMCCC version >= 1.1.
 */
static int smccc_trng_bind(struct udevice *dev)
{
	struct smccc_trng_plat *plat = dev_get_plat(dev);
	struct arm_smccc_res res;
	enum arm_smccc_conduit conduit;

	conduit = arm_smccc_1_1_get_conduit();
	if (conduit == SMCCC_CONDUIT_HVC)
		plat->call = &smccc_trng_call_hvc;
	else if (conduit == SMCCC_CONDUIT_SMC)
		plat->call = &smccc_trng_call_smc;
	else
		return -ENXIO;

	plat->call(ARM_SMCCC_TRNG_VERSION, 0, 0, 0, &res);
	if ((int)res.a0 < 0)
		return -ENODEV;

	if (res.a0 < ARM_SMCCC_TRNG_MIN_VERSION)
		return -EINVAL;

	return 0;
}

static ssize_t smccc_trng_rnd(struct udevice *dev, void *dest, size_t nbytes)
{
	struct smccc_trng_plat *plat = dev_get_plat(dev);
	struct arm_smccc_res res;
	size_t remains = min(nbytes, sizeof(res.a0) * 3);
	size_t nregs = DIV_ROUND_UP(remains, sizeof(res.a0));

	nbytes = remains;
	if (!nbytes)
		return 0;

	plat->call(ARM_SMCCC_TRNG_RND, sizeof(res.a0) * BITS_PER_BYTE * nregs,
		   0, 0, &res);
	if ((int)res.a0 == TRNG_NO_ENTROPY)
		return -EAGAIN;
	if ((int)res.a0 < 0)
		return -EIO;

	switch (nregs) {
	case 3:
		memcpy(dest, &res.a1, sizeof(res.a1));
		dest += sizeof(res.a1);
		remains -= sizeof(res.a1);
		fallthrough;
	case 2:
		memcpy(dest, &res.a2, sizeof(res.a2));
		dest += sizeof(res.a2);
		remains -= sizeof(res.a2);
		fallthrough;
	case 1:
		memcpy(dest, &res.a3, remains);
	}

	return nbytes;
}

static int smccc_trng_read(struct udevice *dev, void *dest, size_t len)
{
	while (len) {
		ssize_t chunk = smccc_trng_rnd(dev, dest, len);

		if (chunk == -EAGAIN)
			continue;
		if (chunk < 0)
			return chunk;
		dest += chunk;
		len -= chunk;
	}

	return 0;
}

static const struct dm_rng_ops smccc_trng_ops = {
	.read = smccc_trng_read,
};

U_BOOT_DRIVER(smccc_trng) = {
	.name = DRIVER_NAME,
	.id = UCLASS_RNG,
	.ops = &smccc_trng_ops,
	.bind = smccc_trng_bind,
	.plat_auto = sizeof(struct smccc_trng_plat),
};
