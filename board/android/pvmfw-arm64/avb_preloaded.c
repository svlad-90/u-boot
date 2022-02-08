// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2022 Google LLC
 */

#include <avb_verify.h>
#include <errno.h>
#include <linux/bug.h>
#include <malloc.h>
#include <part.h>

#include "avb_preloaded.h"

struct avb_preloaded_part {
	char name[PART_NAME_LEN];
	uint8_t *buffer;
	size_t size;
};

struct avb_preloaded {
	struct AvbOps ops;
	size_t part_count;
	struct avb_preloaded_part parts[3];
};

#define avb_preloaded_from_ops(ops) container_of(ops, struct avb_preloaded, ops)

static struct avb_preloaded_part*
avb_preloaded_find_part(struct AvbOps *ops, const char *name)
{
	struct avb_preloaded *preloaded = avb_preloaded_from_ops(ops);

	if (name) {
		for (size_t i = 0; i < preloaded->part_count; i++) {
			if (!strcmp(preloaded->parts[i].name, name))
				return &preloaded->parts[i];
		}
	}
	return NULL;
}

int avb_preloaded_add_part(struct AvbOps *ops, const char *name, void *addr,
			   size_t size)
{
	struct avb_preloaded *preloaded = avb_preloaded_from_ops(ops);
	struct avb_preloaded_part *part;

	if (preloaded->part_count >= ARRAY_SIZE(preloaded->parts))
		return -ENOMEM;

	if (avb_preloaded_find_part(ops, name))
		return -EEXIST;

	part = &preloaded->parts[preloaded->part_count++];
	part->size = size;
	part->buffer = addr;
	strlcpy(part->name, name, ARRAY_SIZE(part->name));

	return 0;
}

static bool safe_offset(int64_t offset, size_t size, size_t *result)
{
	if (offset >= 0) {
		if (offset > size)
			return false;
		*result = (size_t)offset;
	} else if (size >= (size_t)(-offset)) {
		*result = size - (size_t)(-offset);
	} else {
		return false;
	}

	return true;
}

static AvbIOResult read_from_partition(AvbOps *ops, const char *name,
				       int64_t signed_offset, size_t count,
				       void *buffer, size_t *out_num_read)
{
	struct avb_preloaded_part *part;
	size_t offset;

	part = avb_preloaded_find_part(ops, name);
	if (!part)
		return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;

	if (!safe_offset(signed_offset, part->size, &offset) ||
	    count > part->size - offset)
		return AVB_IO_RESULT_ERROR_RANGE_OUTSIDE_PARTITION;

	memcpy(buffer, &part->buffer[offset], count);
	if (out_num_read)
		*out_num_read = count;

	return AVB_IO_RESULT_OK;
}

static AvbIOResult get_preloaded_partition(AvbOps *ops, const char *name,
					   size_t capacity, uint8_t **addr,
					   size_t *size)
{
	BUG_ON(!addr || !size);

	struct avb_preloaded_part *part;

	*addr = NULL;
	*size = 0;

	part = avb_preloaded_find_part(ops, name);
	if (!part)
		return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;

	*addr = part->buffer;
	/* If they ask for less, they'll get less: */
	*size = min(part->size, capacity);

	return AVB_IO_RESULT_OK;
}

static AvbIOResult get_size_of_partition(AvbOps *ops,
					 const char *name,
					 u64 *size)
{
	struct avb_preloaded_part *part;

	if (!size)
		return AVB_IO_RESULT_ERROR_INSUFFICIENT_SPACE;

	part = avb_preloaded_find_part(ops, name);
	if (!part)
		return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;

	*size = part->size;
	return AVB_IO_RESULT_OK;
}

static AvbIOResult validate_vbmeta_public_key(AvbOps *ops, const uint8_t *key,
					      size_t key_length,
					      const uint8_t *metadata,
					      size_t metadata_length,
					      bool *trusted)
{
	if (!key_length || !key)
		return AVB_IO_RESULT_ERROR_IO;

	*trusted = avb_pubkey_is_trusted(key, key_length) == CMD_RET_SUCCESS;
	return AVB_IO_RESULT_OK;
}

static AvbIOResult read_rollback_index(AvbOps *ops,
				       size_t rollback_index_location,
				       uint64_t *out_rollback_index)
{
	/* Required by load_and_verify_vbmeta */
	if (!out_rollback_index)
		return AVB_IO_RESULT_ERROR_INSUFFICIENT_SPACE;

	*out_rollback_index = 0;

	return AVB_IO_RESULT_OK;
}

static AvbIOResult read_is_device_unlocked(AvbOps *ops, bool *unlocked)
{
	*unlocked = false;
	return AVB_IO_RESULT_OK;
}

static AvbIOResult get_unique_guid_for_partition(AvbOps *ops,
						 const char *name,
						 char *guid,
						 size_t guid_size)
{
	struct avb_preloaded_part *part;

	part = avb_preloaded_find_part(ops, name);
	if (!part)
		return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;

	/* Required by avb_sub_cmdline but we don't have a GUID. */
	memset(guid, 0, guid_size);
	return AVB_IO_RESULT_OK;
}

struct AvbOps *avb_preloaded_alloc(void)
{
	struct AvbOps *ops;
	struct avb_preloaded *ops_data;

	ops_data = avb_calloc(sizeof(*ops_data));
	if (!ops_data)
		return NULL;

	ops = &ops_data->ops;

	ops->user_data = ops_data;
	ops->read_from_partition = read_from_partition;
	ops->get_preloaded_partition = get_preloaded_partition;
	ops->validate_vbmeta_public_key =
			validate_vbmeta_public_key;
	ops->read_rollback_index = read_rollback_index;
	ops->read_is_device_unlocked = read_is_device_unlocked;
	ops->get_unique_guid_for_partition =
			get_unique_guid_for_partition;
	ops->get_size_of_partition = get_size_of_partition;

	return ops;
}

void avb_preloaded_free(struct AvbOps *ops)
{
	if (ops)
		avb_free(avb_preloaded_from_ops(ops));
}
