/**
 * @file digital_locker.c
 * @brief Implementation of the generic digital locker interface.
 */

#include "crypto/digital_locker.h"

#include "common/secure_memory.h"
#include "crypto/random.h"

#include <stdlib.h>
#include <string.h>

const char *digital_locker_status_string(digital_locker_status_t status) {
    switch (status) {
    case DIGITAL_LOCKER_OK:                  return "success";

    case DIGITAL_LOCKER_ERR_NULL_ARG:        return "null argument";

    case DIGITAL_LOCKER_ERR_INVALID_ARG:     return "invalid argument";

    case DIGITAL_LOCKER_ERR_BACKEND_FAIL:    return "backend failure";

    case DIGITAL_LOCKER_ERR_INVALID_PADDING: return "invalid padding";

    case DIGITAL_LOCKER_ERR_OOM:             return "memory allocation failed";

    default:                                 return "unknown status";
    }
}

static digital_locker_status_t digital_locker_lock(const digital_locker_context_t *ctx,
                                                   digital_locker_workspace_t     *workspace,
                                                   const uint8_t *key, size_t key_len_bytes,
                                                   const uint8_t *value, size_t value_len_bytes,
                                                   uint8_t *locker) {
    if (ctx == NULL || workspace == NULL || workspace->buf == NULL || locker == NULL) {
        return DIGITAL_LOCKER_ERR_NULL_ARG;
    }

    if (key == NULL && key_len_bytes != 0u) {
        return DIGITAL_LOCKER_ERR_INVALID_ARG;
    }

    if (value == NULL && value_len_bytes != 0u) {
        return DIGITAL_LOCKER_ERR_INVALID_ARG;
    }

    const size_t hash_len_bytes = hash_digest_len_bytes(ctx->hash_alg);
    if (hash_len_bytes == 0u) {
        return DIGITAL_LOCKER_ERR_BACKEND_FAIL;
    }

    if (ctx->tag_len_bytes == 0u || ctx->tag_len_bytes > hash_len_bytes) {
        return DIGITAL_LOCKER_ERR_INVALID_PADDING;
    }

    if (value_len_bytes > hash_len_bytes - ctx->tag_len_bytes) {
        return DIGITAL_LOCKER_ERR_INVALID_PADDING;
    }

    const size_t required_len_bytes = digital_locker_workspace_size(ctx, key_len_bytes);
    if (workspace->buf_len_bytes < required_len_bytes) {
        return DIGITAL_LOCKER_ERR_INVALID_ARG;
    }

    uint8_t     *nonce             = locker;
    uint8_t     *mask              = locker + ctx->nonce_len_bytes;

    uint8_t     *padded            = workspace->buf;
    uint8_t     *hash              = workspace->buf + hash_len_bytes;
    uint8_t     *input             = hash + hash_len_bytes;

    const size_t padding_len_bytes = hash_len_bytes - value_len_bytes;

    rng_status_t rng_status        = random_bytes(nonce, ctx->nonce_len_bytes);
    if (rng_status != RNG_OK) {
        return DIGITAL_LOCKER_ERR_BACKEND_FAIL;
    }

    memcpy(padded, value, value_len_bytes);
    memset(padded + value_len_bytes, 0, padding_len_bytes);

    memcpy(input, nonce, ctx->nonce_len_bytes);
    memcpy(input + ctx->nonce_len_bytes, key, key_len_bytes);

    hash_status_t hash_status = hash_digest(
        ctx->hash_alg, input, ctx->nonce_len_bytes + key_len_bytes, hash, hash_len_bytes);

    if (hash_status != HASH_OK) {
        return DIGITAL_LOCKER_ERR_BACKEND_FAIL;
    }

    for (size_t i = 0u; i < hash_len_bytes; i++) {
        mask[i] = (uint8_t)(hash[i] ^ padded[i]);
    }

    return DIGITAL_LOCKER_OK;
}

static digital_locker_status_t digital_locker_unlock(const digital_locker_context_t *ctx,
                                                     digital_locker_workspace_t     *workspace,
                                                     const uint8_t *key, size_t key_len_bytes,
                                                     uint8_t *value, size_t value_len_bytes,
                                                     const uint8_t *locker) {
    if (ctx == NULL || workspace == NULL || workspace->buf == NULL || locker == NULL) {
        return DIGITAL_LOCKER_ERR_NULL_ARG;
    }

    if (key == NULL && key_len_bytes != 0u) {
        return DIGITAL_LOCKER_ERR_INVALID_ARG;
    }

    if (value == NULL && value_len_bytes != 0u) {
        return DIGITAL_LOCKER_ERR_INVALID_ARG;
    }

    const size_t hash_len_bytes = hash_digest_len_bytes(ctx->hash_alg);
    if (hash_len_bytes == 0u) {
        return DIGITAL_LOCKER_ERR_BACKEND_FAIL;
    }

    if (ctx->tag_len_bytes == 0u || ctx->tag_len_bytes > hash_len_bytes) {
        return DIGITAL_LOCKER_ERR_INVALID_PADDING;
    }

    if (value_len_bytes > hash_len_bytes - ctx->tag_len_bytes) {
        return DIGITAL_LOCKER_ERR_INVALID_PADDING;
    }

    const size_t required_len_bytes = digital_locker_workspace_size(ctx, key_len_bytes);
    if (workspace->buf_len_bytes < required_len_bytes) {
        return DIGITAL_LOCKER_ERR_INVALID_ARG;
    }

    const uint8_t *nonce  = locker;
    const uint8_t *mask   = locker + ctx->nonce_len_bytes;

    uint8_t       *padded = workspace->buf;
    uint8_t       *hash   = workspace->buf + hash_len_bytes;
    uint8_t       *input  = hash + hash_len_bytes;

    memcpy(input, nonce, ctx->nonce_len_bytes);
    memcpy(input + ctx->nonce_len_bytes, key, key_len_bytes);

    hash_status_t hash_status = hash_digest(
        ctx->hash_alg, input, ctx->nonce_len_bytes + key_len_bytes, hash, hash_len_bytes);

    if (hash_status != HASH_OK) {
        return DIGITAL_LOCKER_ERR_BACKEND_FAIL;
    }

    for (size_t i = 0u; i < hash_len_bytes; i++) {
        padded[i] = (uint8_t)(hash[i] ^ mask[i]);
    }

    uint8_t bad_padding = 0u;

    for (size_t i = value_len_bytes; i < hash_len_bytes; i++) {
        bad_padding = (uint8_t)(bad_padding | padded[i]);
    }

    if (bad_padding != 0u) {
        return DIGITAL_LOCKER_ERR_INVALID_PADDING;
    }

    memcpy(value, padded, value_len_bytes);

    return DIGITAL_LOCKER_OK;
}

digital_locker_workspace_t *digital_locker_workspace_create(const digital_locker_context_t *ctx,
                                                            size_t key_len_bytes) {
    const size_t workspace_len_bytes = digital_locker_workspace_size(ctx, key_len_bytes);
    if (workspace_len_bytes == 0u) {
        return NULL;
    }

    digital_locker_workspace_t *workspace = calloc(1u, sizeof(*workspace));
    if (workspace == NULL) {
        return NULL;
    }

    workspace->buf = calloc(1u, workspace_len_bytes);
    if (workspace->buf == NULL) {
        free(workspace);
        return NULL;
    }

    workspace->buf_len_bytes = workspace_len_bytes;

    return workspace;
}

void digital_locker_workspace_clear(const digital_locker_context_t *ctx,
                                    digital_locker_workspace_t *workspace, size_t key_len_bytes) {
    if (ctx == NULL || workspace == NULL || workspace->buf == NULL) {
        return;
    }

    const size_t workspace_len_bytes = digital_locker_workspace_size(ctx, key_len_bytes);
    if (workspace_len_bytes == 0u) {
        return;
    }

    const size_t clear_len_bytes = workspace->buf_len_bytes < workspace_len_bytes
                                       ? workspace->buf_len_bytes
                                       : workspace_len_bytes;

    secure_bzero(workspace->buf, clear_len_bytes);
}

void digital_locker_workspace_destroy(const digital_locker_context_t *ctx,
                                      digital_locker_workspace_t *workspace, size_t key_len_bytes) {
    if (workspace == NULL) {
        return;
    }

    if (workspace->buf != NULL) {
        digital_locker_workspace_clear(ctx, workspace, key_len_bytes);
        free(workspace->buf);
    }

    free(workspace);
}

void digital_locker_init(digital_locker_t *dl, size_t nonce_len_bytes, size_t tag_len_bytes,
                         const hash_alg_t *hash_alg) {
    if (dl == NULL) {
        return;
    }

    *dl = (digital_locker_t){
        .ctx.nonce_len_bytes = nonce_len_bytes,
        .ctx.tag_len_bytes   = tag_len_bytes,
        .ctx.hash_alg        = hash_alg,
        .lock                = digital_locker_lock,
        .unlock              = digital_locker_unlock,
    };
}
