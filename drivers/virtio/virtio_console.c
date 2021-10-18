// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2018, Tuomas Tynkkynen <tuomas.tynkkynen@iki.fi>
 * Copyright (C) 2018, Bin Meng <bmeng.cn@gmail.com>
 * Copyright (C) 2006, 2007, 2009 Rusty Russell, IBM Corporation
 * Copyright (C) 2009, 2010, 2011 Red Hat, Inc.
 * Copyright (C) 2009, 2010, 2011 Amit Shah <amit.shah@redhat.com>
 * Copyright (C) 2021 Ahmad Fatoum
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
	struct virtqueue *receiveq_port0;
	struct virtqueue *transmitq_port0;
	unsigned char inbuf[1] __aligned(4);
};

static int virtio_console_bind(struct udevice *dev)
{
	struct virtio_dev_priv *uc_priv = dev_get_uclass_priv(dev->parent);

	/* Indicate what driver features we support */
	virtio_driver_features_init(uc_priv, NULL, 0, NULL, 0);

	return 0;
}

/*
 * Create a scatter-gather list representing our input buffer and put
 * it in the queue.
 */
static void add_inbuf(struct virtio_console_priv *priv)
{
	struct virtio_sg sg;
	struct virtio_sg *sgs[1];

	sgs[0] = &sg;
	sg.addr = priv->inbuf;
	sg.length = sizeof(priv->inbuf);

	/* We should always be able to add one buffer to an empty queue. */
	if (virtqueue_add(priv->receiveq_port0, sgs, 0, 1) < 0) {
		debug("%s: virtqueue_add failed\n", __func__);
		BUG();
	}
	virtqueue_kick(priv->receiveq_port0);
}

static int virtio_console_probe(struct udevice *dev)
{
	struct virtio_console_priv *priv = dev_get_priv(dev);
	int ret;

	struct virtqueue *virtqueues[2];

	ret = virtio_find_vqs(dev, 2, virtqueues);
	if (ret < 0) {
		debug("%s: virtio_find_vqs failed\n", __func__);
		return ret;
	}

	priv->receiveq_port0 = virtqueues[0];
	priv->transmitq_port0 = virtqueues[1];

	/* Register the input buffer the first time. */
	add_inbuf(priv);

	return 0;
}

static int virtio_console_serial_setbrg(struct udevice *dev, int baudrate)
{
	return 0;
}

static int virtio_console_serial_pending(struct udevice *dev, bool input)
{
	struct virtio_console_priv *priv = dev_get_priv(dev);
	return virtqueue_poll(priv->receiveq_port0,
			      priv->receiveq_port0->last_used_idx);
}

static int virtio_console_serial_getc(struct udevice *dev)
{
	struct virtio_console_priv *priv = dev_get_priv(dev);
	unsigned char *in;
	int ch;
	unsigned int len = 0;

	in = virtqueue_get_buf(priv->receiveq_port0, &len);
	if (!in) {
		return -EAGAIN;
	} else if (len != 1) {
		debug("%s: too much data: %d\n", __func__, len);
		BUG();
	}

	ch = *in;

	add_inbuf(priv);

	return ch;
}

static int virtio_console_serial_putc(struct udevice *dev, const char ch)
{
	struct virtio_console_priv *priv = dev_get_priv(dev);
	struct virtio_sg sg;
	struct virtio_sg *sgs[1];
	unsigned char buf[1] __aligned(4);
	int ret = 0;

	sg.addr = buf;
	sg.length = sizeof(buf);
	sgs[0] = &sg;
	buf[0] = ch;

	ret = virtqueue_add(priv->transmitq_port0, sgs, 1, 0);
	if (ret) {
		debug("%s: virtqueue_add failed\n", __func__);
		return ret;
	}

	virtqueue_kick(priv->transmitq_port0);

	while (!virtqueue_get_buf(priv->transmitq_port0, NULL)) {
	}

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
