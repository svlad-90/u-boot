// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Google LLC
 */

#include <bcc.h>
#include <malloc.h>
#include <u-boot/sha256.h>

#include <dice/android/bcc.h>
#include <dice/ops.h>

#define BCC_CONFIG_DESC_SIZE	64

static const DiceMode bcc_to_dice_mode[] = {
	[BCC_MODE_NORMAL] = kDiceModeNormal,
	[BCC_MODE_MAINTENANCE] = kDiceModeMaintenance,
	[BCC_MODE_DEBUG] = kDiceModeDebug,
};

struct bcc_context {
	sha256_context auth_hash, code_hash, hidden_hash;
};

void bcc_clear_memory(void *data, size_t size)
{
	DiceClearMemory(NULL, size, data);
}

struct bcc_context *bcc_context_alloc(void)
{
	struct bcc_context *ctx;

	ctx = calloc(1, sizeof(*ctx));
	if (ctx) {
		sha256_starts(&ctx->hidden_hash);
		sha256_starts(&ctx->code_hash);
		sha256_starts(&ctx->auth_hash);
	}

	return ctx;
}

static int bcc_update_hash(sha256_context *ctx, const uint8_t *input, size_t size)
{
	sha256_update(ctx, input, size);
	return 0;
}

static int bcc_finish_hash(sha256_context *ctx, void *digest, size_t size)
{
	memset(digest, 0, size);
	sha256_finish(ctx, digest);
	return 0;
}

int bcc_update_hidden_hash(struct bcc_context *ctx,
			   const uint8_t *input, size_t size)
{
	return bcc_update_hash(&ctx->hidden_hash, input, size);
}

int bcc_update_authority_hash(struct bcc_context *ctx,
			      const uint8_t *input, size_t size)
{
	return bcc_update_hash(&ctx->auth_hash, input, size);
}

int bcc_update_code_hash(struct bcc_context *ctx,
			 const uint8_t *input, size_t size)
{
	return bcc_update_hash(&ctx->code_hash, input, size);
}

int bcc_handover(struct bcc_context *ctx, const char *component_name,
		 uint32_t component_version, enum bcc_mode mode,
		 uint8_t *in_handover, size_t in_handover_size,
		 size_t buffer_size, uint8_t *buffer, size_t *out_size)
{
	uint8_t cfg_desc[BCC_CONFIG_DESC_SIZE];
	size_t cfg_desc_size;
	BccConfigValues cfg_vals;
	DiceInputValues input_vals;
	DiceResult res;

	cfg_vals = (BccConfigValues){
		.inputs = BCC_INPUT_COMPONENT_NAME |
			  BCC_INPUT_COMPONENT_VERSION,
		.component_name = component_name,
		.component_version = component_version,
	};

	res = BccFormatConfigDescriptor(&cfg_vals, BCC_CONFIG_DESC_SIZE,
					cfg_desc, &cfg_desc_size);
	if (res != kDiceResultOk)
		return -EINVAL;

	input_vals = (DiceInputValues){
		.config_type = kDiceConfigTypeDescriptor,
		.config_descriptor = cfg_desc,
		.config_descriptor_size = cfg_desc_size,
		.mode = bcc_to_dice_mode[mode],
	};

	bcc_finish_hash(&ctx->auth_hash, input_vals.authority_hash, DICE_HASH_SIZE);
	bcc_finish_hash(&ctx->code_hash, input_vals.code_hash, DICE_HASH_SIZE);
	bcc_finish_hash(&ctx->hidden_hash, input_vals.hidden, DICE_HIDDEN_SIZE);

	res = BccHandoverMainFlow(/*context=*/NULL, in_handover,
				  in_handover_size, &input_vals,
				  buffer_size, buffer, out_size);
	return (res == kDiceResultOk) ? 0 : -EINVAL;
}
