// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Google LLC
 */

#include <vm_instance.h>
#include <dm/uclass.h>
#include <linux/bug.h>
#include <linux/err.h>
#include <log.h>
#include <openssl/aead.h>
#include <rng.h>

#define VM_INSTANCE_BLOCK_SIZE		512
#define VM_INSTANCE_MAX_BLOCK		(S64_MAX / VM_INSTANCE_BLOCK_SIZE)

#define DISK_HEADER_MAX_VERSION		1

static const char vm_instance_hdr_magic[] = {
	'A', 'n', 'd', 'r', 'o', 'i', 'd', '-', 'V', 'M', '-',
	'i', 'n', 's', 't', 'a', 'n', 'c', 'e' };

struct vm_instance_hdr {
	uint8_t magic[sizeof(vm_instance_hdr_magic)];
	uint16_t version;
} __packed;

struct vm_instance_part_hdr {
	struct uuid uuid;
	uint64_t part_size;
} __packed;

static int read_bytes(struct AvbOps *ops, size_t block_num,
		      void *buf, size_t size)
{
	AvbIOResult res;
	size_t bytes_read;
	int64_t offset;

	if (block_num > VM_INSTANCE_MAX_BLOCK)
		return -EINVAL;

	offset = block_num * VM_INSTANCE_BLOCK_SIZE;
	res = ops->read_from_partition(ops, CONFIG_VM_INSTANCE_PARTITION_NAME,
				       offset, size, buf, &bytes_read);
	if (res != AVB_IO_RESULT_OK)
		return -EIO;

	if (bytes_read != size)
		return -ENOENT;

	return 0;
}

static int write_bytes(struct AvbOps *ops, size_t block_num,
		       const void *buf, size_t size)
{
	AvbIOResult res;
	int64_t offset;

	if (block_num > VM_INSTANCE_MAX_BLOCK)
		return -EINVAL;

	offset = block_num * VM_INSTANCE_BLOCK_SIZE;
	res = ops->write_to_partition(ops, CONFIG_VM_INSTANCE_PARTITION_NAME,
				      offset, size, buf);
	if (res != AVB_IO_RESULT_OK)
		return -EIO;

	return 0;
}

static int read_and_verify_img_hdr_block(struct AvbOps *ops, size_t block_num)
{
	struct vm_instance_hdr hdr;
	int ret;

	ret = read_bytes(ops, block_num, &hdr, sizeof(hdr));
	if (ret)
		return ret;

	hdr.version = le16_to_cpu(hdr.version);

	if (memcmp(hdr.magic, vm_instance_hdr_magic, sizeof(hdr.magic)))
		return -EINVAL;

	if (!hdr.version || hdr.version > DISK_HEADER_MAX_VERSION)
		return -EINVAL;

	return 0;
}

/**
 * Search the partitions for one with the given UUID.
 *
 * If the partition is found, returns 0 and end_block_num is set to the first
 * block of the partition contents. If the partition is not found, returns
 * -ENOENT and end_block_num is set to the block where the next partition header
 *  is expected. Otherwise, returns an error code and end_block_num is not
 *  valid;
 */
static int find_partition(struct AvbOps *ops, size_t block_num,
			  const struct uuid *uuid,
			  struct vm_instance_part_hdr *hdr,
			  size_t *end_block_num)
{
	const struct vm_instance_part_hdr zero_hdr = {};
	size_t blocks;
	int ret;

	while (true) {
		ret = read_bytes(ops, block_num, hdr, sizeof(*hdr));
		if (ret == -ENOENT)
			break;
		else if (ret)
			return ret;

		/* An empty partition means the end of the file. */
		if (memcmp(hdr, &zero_hdr, sizeof(zero_hdr)) == 0) {
			ret = -ENOENT;
			break;
		}

		/* The parition is valid, so check if it's the right one. */
		block_num += 1;
		if (memcmp(&hdr->uuid, uuid, sizeof(*uuid)) == 0) {
			ret = 0;
			break;
		}

		/* Skip payload. */
		blocks = DIV_ROUND_UP(hdr->part_size, VM_INSTANCE_BLOCK_SIZE);
		if (blocks > VM_INSTANCE_MAX_BLOCK - block_num)
			return -EINVAL;
		block_num += blocks;
	}

	*end_block_num = block_num;
	return ret;
}

int vm_instance_load_entry(struct AvbOps *ops, const struct uuid *uuid,
			   const uint8_t *sealing_key, size_t sealing_key_size,
			   void *data, size_t data_size)
{
	const EVP_AEAD *aead = EVP_aead_aes_256_gcm_randnonce();
	EVP_AEAD_CTX ctx;
	size_t block_num;
	struct vm_instance_part_hdr hdr;
	size_t max_sealed_size, sealed_size, opened_size;
	uint8_t *sealed;
	int ret;

	sealed = NULL;
	max_sealed_size = data_size + EVP_AEAD_max_overhead(aead);

	if (!uuid)
		return -EINVAL;

	if (!EVP_AEAD_CTX_init(&ctx, aead, sealing_key, sealing_key_size,
			       EVP_AEAD_DEFAULT_TAG_LENGTH, /*engine=*/NULL))
		return -EINVAL;

	block_num = 0;
	ret = read_and_verify_img_hdr_block(ops, block_num);
	if (ret < 0)
		goto out;
	block_num = 1;

	ret = find_partition(ops, block_num, uuid, &hdr, &block_num);
	if (ret)
		goto out;

	sealed_size = hdr.part_size;
	if (sealed_size > max_sealed_size) {
		ret = -EINVAL;
		goto out;
	}

	sealed = kmalloc(max_sealed_size, GFP_KERNEL);
	if (!sealed) {
		ret = -ENOMEM;
		goto out;
	}

	ret = read_bytes(ops, block_num, sealed, sealed_size);
	if (ret)
		goto out;

	if (!EVP_AEAD_CTX_open(&ctx, data, &opened_size, data_size,
			       /*nonce=*/NULL, /*nonce_len=*/0,
			       sealed, sealed_size,
			       /*ad=*/NULL, /*ad_len=*/0)) {
		ret = -EINVAL;
		goto out;
	}

	if (opened_size != data_size) {
		ret = -EINVAL;
		goto out;
	}

out:
	EVP_AEAD_CTX_cleanup(&ctx);
	kfree(sealed);
	return ret;
}

int vm_instance_save_entry(struct AvbOps *ops, const struct uuid *uuid,
			   const uint8_t *sealing_key, size_t sealing_key_size,
			   const void *data, size_t data_size)
{
	const EVP_AEAD *aead = EVP_aead_aes_256_gcm_randnonce();
	EVP_AEAD_CTX ctx;
	size_t block_num;
	struct vm_instance_part_hdr hdr;
	int ret;
	size_t sealed_size, max_sealed_size;
	uint8_t *sealed;

	sealed = NULL;
	max_sealed_size = data_size + EVP_AEAD_max_overhead(aead);

	if (!uuid)
		return -EINVAL;

	if (!EVP_AEAD_CTX_init(&ctx, aead, sealing_key, sealing_key_size,
			       EVP_AEAD_DEFAULT_TAG_LENGTH, /*engine=*/NULL))
		return -EINVAL;

	sealed = kmalloc(max_sealed_size, GFP_KERNEL);
	if (!sealed) {
		ret = -ENOMEM;
		goto out;
	}

	if (!EVP_AEAD_CTX_seal(&ctx, sealed, &sealed_size, max_sealed_size,
			       /*nonce=*/NULL, /*nonce_len=*/0,
			       data, data_size,
			       /*ad=*/NULL, /*ad_len=*/0)) {
		ret = -EINVAL;
		goto out;
	}

	block_num = 0;
	ret = read_and_verify_img_hdr_block(ops, block_num);
	if (ret)
		goto out;
	block_num = 1;

	ret = find_partition(ops, block_num, uuid, &hdr, &block_num);
	if (ret == -ENOENT) {
		hdr = (struct vm_instance_part_hdr){ .part_size = sealed_size };
		memcpy(&hdr.uuid, uuid, sizeof(*uuid));
		ret = write_bytes(ops, block_num, &hdr, sizeof(hdr));
		block_num += 1;
	}
	if (ret)
		goto out;

	/* Check the payload size is still the same. */
	if (hdr.part_size != sealed_size) {
		ret = -EINVAL;
		goto out;
	}

	ret = write_bytes(ops, block_num, sealed, sealed_size);

out:
	EVP_AEAD_CTX_cleanup(&ctx);
	kfree(sealed);
	return ret;
}

int vm_instance_new_salt(uint8_t salt[VM_INSTANCE_SALT_SIZE])
{
	struct udevice *dev;
	int ret;

	ret = uclass_get_device(UCLASS_RNG, 0, &dev);
	if (ret) {
		log_err("No RNG device.\n");
		return ret;
	}

	ret = dm_rng_read(dev, salt, VM_INSTANCE_SALT_SIZE);
	if (ret) {
		log_err("No RNG.\n");
		return ret;
	}

	return 0;
}
