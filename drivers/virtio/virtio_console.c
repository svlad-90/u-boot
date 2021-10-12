// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2018, Tuomas Tynkkynen <tuomas.tynkkynen@iki.fi>
 * Copyright (C) 2018, Bin Meng <bmeng.cn@gmail.com>
 * Copyright (C) 2021, Google LLC, schuffelen@google.com (A. Cody Schuffelen)
 */

#include <common.h>
#include <blk.h>
#include <dm.h>
#include <part.h>
#include <serial.h>
#include <virtio_types.h>
#include <virtio.h>
#include <virtio_ring.h>
#include "virtio_blk.h"

struct virtio_console_priv {
};

static int virtio_console_bind(struct udevice *dev)
{
	struct virtio_dev_priv *uc_priv = dev_get_uclass_priv(dev->parent);

	/* Indicate what driver features we support */
	virtio_driver_features_init(uc_priv, NULL, 0, NULL, 0);

	return 0;
}

static int virtio_console_probe(struct udevice *dev)
{
	return 0;
}

static int virtio_console_serial_setbrg(struct udevice *dev, int baudrate)
{
	return 0;
}

static int virtio_console_serial_getc(struct udevice *dev)
{
	return -EAGAIN;
}

static int virtio_console_serial_pending(struct udevice *dev, bool input)
{
	return 0;
}

static int virtio_console_serial_putc(struct udevice *dev, const char ch)
{
	return 0;
}

static const struct dm_serial_ops virtio_console_serial_ops = {
	.putc = virtio_console_serial_putc,
	.pending = virtio_console_serial_pending,
	.getc = virtio_console_serial_getc,
	.setbrg = virtio_console_serial_setbrg,
};

U_BOOT_DRIVER(virtio_console) = {
	.name	= VIRTIO_CONSOLE_DRV_NAME,
	.id	= UCLASS_SERIAL,
	.ops	= &virtio_console_serial_ops,
	.bind	= virtio_console_bind,
	.probe	= virtio_console_probe,
	.remove	= virtio_reset,
	.priv_auto	= sizeof(struct virtio_console_priv),
	.flags	= DM_FLAG_ACTIVE_DMA,
};
