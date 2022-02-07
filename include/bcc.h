// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Google LLC
 */

#ifndef _BCC_H
#define _BCC_H

#include <avb_verify.h>

struct bcc_context;

enum bcc_mode {
	BCC_MODE_NORMAL,
	BCC_MODE_DEBUG,
	BCC_MODE_MAINTENANCE,
};

int bcc_init(void);

struct bcc_context *bcc_context_alloc(void);

int bcc_update_hidden_hash(struct bcc_context *ctx, const uint8_t *buffer, size_t size);
int bcc_update_code_hash(struct bcc_context *ctx, const uint8_t *buffer, size_t size);
int bcc_update_authority_hash(struct bcc_context *ctx, const uint8_t *buffer, size_t size);

/**
 * Perform a Boot Certificate Chain handover
 *
 * Takes the input BCC handover and measurement of all inputs loaded at this
 * boot stage, and generates the outgoing BCC handover for the next stage.
 * Returns zero if successful, a negative error code otherwise.
 */
int bcc_handover(struct bcc_context *ctx, const char *component_name, enum bcc_mode mode);

/**
 * Get a sealing key derived from the sealing CDI.
 *
 * The sealing CDI should not be used directly as a key but should have keys
 * derived from it. This functions deterministically derives keys from the
 * sealing CDI based on the info parameter. Returns zero if successful, a
 * negative error code otherwise.
 */
int bcc_get_sealing_key(const uint8_t *info, size_t info_size,
			uint8_t *out_key, size_t out_key_size);

/**
 * Zero given memory buffer and flush dcache
 */
void bcc_clear_memory(void *data, size_t size);

#endif /* _BCC_H */
