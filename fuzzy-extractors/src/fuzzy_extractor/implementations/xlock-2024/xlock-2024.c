/**
 * @file xlock-2024.c
 * @brief Original X-Lock fuzzy extractor implementation (2024).
 */

#include "fuzzy_extractor/implementations/xlock-2024.h"

#include "common/bits.h"
#include "common/secure_memory.h"
#include "crypto/random.h"
#include "crypto/sample.h"
#include "fuzzy_extractor/core/fuzzy_extractor_internal.h"
#include "fuzzy_extractor/core/workspace_internal.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    size_t            w_len_bytes;
    size_t            w_len_bits;
    prng_t            prng;

    size_t            pool_len_bytes;
    size_t            pool_len_bits;
    size_t            key_pre_len_bytes;
    size_t            key_pre_len_bits;
    size_t            key_len_bytes;

    size_t            xor_n;
    size_t            locks_n;
    size_t            nonce_len_bytes;
    const hmac_alg_t *hmac_alg;

    size_t            indices_n;
    size_t            hmac_len_bytes;
    size_t            used_w_len_bytes;
    size_t            used_pool_len_bytes;
    size_t            votes_len_bytes;
} xlock_context_t;

typedef struct {
    uint8_t *pool;
    uint8_t *key_pre;
    uint8_t *full_key;
    uint8_t *token;
    uint8_t *used_w;
    uint8_t *used_pool;
    size_t  *votes;
} xlock_workspace_t;

static inline bool xlock_vault_is_set(const fuzzy_extractor_xlock_2024_vault_t *vault) {
    return vault != NULL && vault->is_set;
}

static void xlock_workspace_clear(const xlock_context_t *ctx, xlock_workspace_t *workspace) {
    if (ctx == NULL || workspace == NULL) {
        return;
    }

    if (workspace->pool != NULL) {
        secure_bzero(workspace->pool, ctx->pool_len_bytes);
    }

    if (workspace->key_pre != NULL) {
        secure_bzero(workspace->key_pre, ctx->key_pre_len_bytes);
    }

    if (workspace->full_key != NULL) {
        secure_bzero(workspace->full_key, ctx->hmac_len_bytes);
    }

    if (workspace->token != NULL) {
        secure_bzero(workspace->token, ctx->hmac_len_bytes);
    }

    if (workspace->used_w != NULL) {
        secure_bzero(workspace->used_w, ctx->used_w_len_bytes);
    }

    if (workspace->used_pool != NULL) {
        secure_bzero(workspace->used_pool, ctx->used_pool_len_bytes);
    }

    if (workspace->votes != NULL) {
        secure_bzero(workspace->votes, ctx->votes_len_bytes);
    }
}

static void *xlock_workspace_create(const void *ctx_ptr) {
    const xlock_context_t *ctx = (const xlock_context_t *)ctx_ptr;
    if (ctx == NULL) {
        return NULL;
    }

    if (ctx->hmac_len_bytes == 0u || ctx->used_w_len_bytes == 0u ||
        ctx->used_pool_len_bytes == 0u) {
        return NULL;
    }

    const size_t workspace_len_bytes = ctx->pool_len_bytes + ctx->key_pre_len_bytes +
                                       ctx->hmac_len_bytes + ctx->hmac_len_bytes +
                                       ctx->used_w_len_bytes + ctx->used_pool_len_bytes +
                                       ctx->votes_len_bytes + sizeof(size_t) - 1u;

    xlock_workspace_t *workspace = calloc(1u, sizeof(*workspace) + workspace_len_bytes);

    if (workspace == NULL) {
        return NULL;
    }

    uint8_t *cursor      = (uint8_t *)(workspace + 1);

    workspace->pool      = workspace_alloc_slice(&cursor, ctx->pool_len_bytes);

    workspace->key_pre   = workspace_alloc_slice(&cursor, ctx->key_pre_len_bytes);

    workspace->full_key  = workspace_alloc_slice(&cursor, ctx->hmac_len_bytes);

    workspace->token     = workspace_alloc_slice(&cursor, ctx->hmac_len_bytes);

    workspace->used_w    = workspace_alloc_slice(&cursor, ctx->used_w_len_bytes);

    workspace->used_pool = workspace_alloc_slice(&cursor, ctx->used_pool_len_bytes);

    cursor               = workspace_align_cursor(cursor, sizeof(size_t));

    workspace->votes     = (size_t *)workspace_alloc_slice(&cursor, ctx->votes_len_bytes);

    return workspace;
}

static void xlock_workspace_destroy(const void *ctx_ptr, void *workspace_ptr) {
    const xlock_context_t *ctx       = (const xlock_context_t *)ctx_ptr;
    xlock_workspace_t     *workspace = (xlock_workspace_t *)workspace_ptr;

    if (ctx == NULL || workspace == NULL) {
        return;
    }

    xlock_workspace_clear(ctx, workspace);
    free(workspace);
}

static fuzzy_extractor_status_t xlock_derive_pre_key(uint8_t *key_pre, const xlock_context_t *ctx,
                                                     const uint8_t *pool, uint8_t *used_pool,
                                                     size_t            used_pool_len_bytes,
                                                     const rng_seed_t *seed) {
    if (key_pre == NULL || ctx == NULL || pool == NULL || used_pool == NULL || seed == NULL) {
        return FUZZY_EXTRACTOR_ERR_NULL_ARG;
    }

    if (ctx->key_pre_len_bits > ctx->pool_len_bits) {
        secure_bzero(key_pre, ctx->key_pre_len_bytes);
        return FUZZY_EXTRACTOR_ERR_BUFFER_TOO_SMALL;
    }

    secure_bzero(key_pre, ctx->key_pre_len_bytes);

    sample_stream_t stream;

    rng_status_t    rng_status = sample_stream_init(
        &stream, ctx->prng, SAMPLE_MODE_WITHOUT_REPLACEMENT, ctx->key_pre_len_bits, 0u,
        ctx->pool_len_bits, seed, used_pool, used_pool_len_bytes);

    if (rng_status != RNG_OK) {
        return fuzzy_extractor_status_from_rng(rng_status);
    }

    for (size_t bit = 0u; bit < ctx->key_pre_len_bits; bit++) {
        size_t index = 0u;

        rng_status   = sample_stream_next(&stream, &index);
        if (rng_status != RNG_OK) {
            secure_bzero(key_pre, ctx->key_pre_len_bytes);
            return fuzzy_extractor_status_from_rng(rng_status);
        }

        bits_set(key_pre, bit, bits_get(pool, index));
    }

    return FUZZY_EXTRACTOR_OK;
}

static fuzzy_extractor_status_t xlock_vault_encrypt(fuzzy_extractor_xlock_2024_vault_t *vault,
                                                    const xlock_context_t *ctx, const uint8_t *w,
                                                    xlock_workspace_t *workspace) {
    if (vault == NULL || ctx == NULL || w == NULL || workspace == NULL || workspace->pool == NULL ||
        workspace->used_w == NULL) {
        return FUZZY_EXTRACTOR_ERR_NULL_ARG;
    }

    uint8_t *pool = workspace->pool;

    if (ctx->indices_n > ctx->w_len_bits) {
        secure_bzero(pool, ctx->pool_len_bytes);
        return FUZZY_EXTRACTOR_ERR_BUFFER_TOO_SMALL;
    }

    rng_status_t rng_status = random_bytes(pool, ctx->pool_len_bytes);

    if (rng_status != RNG_OK) {
        return fuzzy_extractor_status_from_rng(rng_status);
    }

    rng_status = random_seed_u32(&vault->vault_seed);
    if (rng_status != RNG_OK) {
        secure_bzero(pool, ctx->pool_len_bytes);
        return fuzzy_extractor_status_from_rng(rng_status);
    }

    vault->is_set = 0;

    sample_stream_t stream;

    rng_status = sample_stream_init(&stream, ctx->prng, SAMPLE_MODE_WITHOUT_REPLACEMENT,
                                    ctx->indices_n, 0u, ctx->w_len_bits, &vault->vault_seed,
                                    workspace->used_w, ctx->used_w_len_bytes);

    if (rng_status != RNG_OK) {
        secure_bzero(pool, ctx->pool_len_bytes);
        return fuzzy_extractor_status_from_rng(rng_status);
    }

    for (size_t i = 0u; i < ctx->locks_n; i++) {
        uint8_t *lock_bits = vault->lock_bits + i * ctx->pool_len_bytes;

        for (size_t byte_index = 0u; byte_index < ctx->pool_len_bytes; byte_index++) {
            uint8_t      out       = 0u;

            const size_t first_bit = byte_index * 8u;
            const size_t last_bit =
                first_bit + 8u < ctx->pool_len_bits ? first_bit + 8u : ctx->pool_len_bits;

            for (size_t bit = first_bit; bit < last_bit; bit++) {
                uint8_t x = bits_get(pool, bit);

                for (size_t j = 0u; j < ctx->xor_n; j++) {
                    size_t index = 0u;

                    rng_status   = sample_stream_next(&stream, &index);
                    if (rng_status != RNG_OK) {
                        secure_bzero(pool, ctx->pool_len_bytes);
                        return fuzzy_extractor_status_from_rng(rng_status);
                    }

                    x = (uint8_t)(x ^ bits_get(w, index));
                }

                if (x != 0u) {
                    out = (uint8_t)(out | (uint8_t)(1u << (bit & 7u)));
                }
            }

            lock_bits[byte_index] = out;
        }
    }

    vault->is_set = 1;

    return FUZZY_EXTRACTOR_OK;
}

static fuzzy_extractor_status_t xlock_vault_decrypt(const fuzzy_extractor_xlock_2024_vault_t *vault,
                                                    const xlock_context_t *ctx, const uint8_t *w,
                                                    xlock_workspace_t *workspace) {
    if (vault == NULL || ctx == NULL || w == NULL || workspace == NULL || workspace->pool == NULL ||
        workspace->used_w == NULL || workspace->votes == NULL) {
        return FUZZY_EXTRACTOR_ERR_NULL_ARG;
    }

    uint8_t *pool  = workspace->pool;
    size_t  *votes = workspace->votes;

    secure_bzero(pool, ctx->pool_len_bytes);
    secure_bzero(votes, ctx->votes_len_bytes);

    if (ctx->indices_n > ctx->w_len_bits) {
        return FUZZY_EXTRACTOR_ERR_BUFFER_TOO_SMALL;
    }

    rng_seed_t      vault_seed = vault->vault_seed;
    sample_stream_t stream;

    rng_status_t    rng_status =
        sample_stream_init(&stream, ctx->prng, SAMPLE_MODE_WITHOUT_REPLACEMENT, ctx->indices_n, 0u,
                           ctx->w_len_bits, &vault_seed, workspace->used_w, ctx->used_w_len_bytes);

    if (rng_status != RNG_OK) {
        return fuzzy_extractor_status_from_rng(rng_status);
    }

    const size_t half = ctx->locks_n / 2u;

    for (size_t i = 0u; i < ctx->locks_n; i++) {
        const uint8_t *lock_bits = vault->lock_bits + i * ctx->pool_len_bytes;

        for (size_t byte_index = 0u; byte_index < ctx->pool_len_bytes; byte_index++) {
            const size_t first_bit = byte_index * 8u;
            const size_t last_bit =
                first_bit + 8u < ctx->pool_len_bits ? first_bit + 8u : ctx->pool_len_bits;

            for (size_t bit = first_bit; bit < last_bit; bit++) {
                uint8_t x = bits_get(lock_bits, bit);

                for (size_t j = 0u; j < ctx->xor_n; j++) {
                    size_t index = 0u;

                    rng_status   = sample_stream_next(&stream, &index);
                    if (rng_status != RNG_OK) {
                        secure_bzero(pool, ctx->pool_len_bytes);
                        return fuzzy_extractor_status_from_rng(rng_status);
                    }

                    x = (uint8_t)(x ^ bits_get(w, index));
                }

                votes[bit] += x;
            }
        }
    }

    for (size_t bit = 0u; bit < ctx->pool_len_bits; bit++) {
        bits_set(pool, bit, votes[bit] > half ? 1u : 0u);
    }

    return FUZZY_EXTRACTOR_OK;
}

static fuzzy_extractor_status_t xlock_derive_key(const xlock_context_t *ctx,
                                                 xlock_workspace_t     *workspace,
                                                 const fuzzy_extractor_xlock_2024_helper_data_t *hd,
                                                 fuzzy_extractor_key_t *key, uint8_t *token_out) {
    if (ctx == NULL || workspace == NULL || hd == NULL || key == NULL || key->data == NULL ||
        token_out == NULL) {
        return FUZZY_EXTRACTOR_ERR_NULL_ARG;
    }

    if (ctx->hmac_len_bytes == 0u) {
        return FUZZY_EXTRACTOR_ERR_INVALID_ARG;
    }

    fuzzy_extractor_status_t status =
        xlock_derive_pre_key(workspace->key_pre, ctx, workspace->pool, workspace->used_pool,
                             ctx->used_pool_len_bytes, &hd->key_pre_seed);

    if (status != FUZZY_EXTRACTOR_OK) {
        return status;
    }

    hmac_status_t hmac_status =
        hmac_digest(ctx->hmac_alg, hd->nonce, ctx->nonce_len_bytes, workspace->key_pre,
                    ctx->key_pre_len_bytes, workspace->full_key, ctx->hmac_len_bytes);

    if (hmac_status != HMAC_OK) {
        return fuzzy_extractor_status_from_hmac(hmac_status);
    }

    memcpy(key->data, workspace->full_key, key->len_bytes);

    hmac_status =
        hmac_digest(ctx->hmac_alg, &hd->key_pre_seed, sizeof(hd->key_pre_seed), workspace->full_key,
                    ctx->hmac_len_bytes, token_out, ctx->hmac_len_bytes);

    return fuzzy_extractor_status_from_hmac(hmac_status);
}

static fuzzy_extractor_status_t
xlock_validate_common(const xlock_context_t                          *ctx,
                      const fuzzy_extractor_xlock_2024_helper_data_t *hd, const uint8_t *w,
                      size_t w_len_bytes, const fuzzy_extractor_key_t *key) {
    if (ctx == NULL || hd == NULL || w == NULL || key == NULL || key->data == NULL) {
        return FUZZY_EXTRACTOR_ERR_NULL_ARG;
    }

    if (hd->vault == NULL || hd->nonce == NULL || hd->token == NULL) {
        return FUZZY_EXTRACTOR_ERR_NULL_ARG;
    }

    if (ctx->hmac_len_bytes == 0u) {
        return FUZZY_EXTRACTOR_ERR_INVALID_ARG;
    }

    if (w_len_bytes != ctx->w_len_bytes) {
        return FUZZY_EXTRACTOR_ERR_INVALID_ARG;
    }

    if (key->len_bytes != ctx->key_len_bytes) {
        return FUZZY_EXTRACTOR_ERR_INVALID_ARG;
    }

    return FUZZY_EXTRACTOR_OK;
}

static fuzzy_extractor_status_t xlock_generate(const void *ctx_ptr, void *workspace_ptr,
                                               const uint8_t *w, size_t w_len_bytes, void *hd_ptr,
                                               fuzzy_extractor_key_t *key) {
    const xlock_context_t                    *ctx = (const xlock_context_t *)ctx_ptr;
    fuzzy_extractor_xlock_2024_helper_data_t *hd =
        (fuzzy_extractor_xlock_2024_helper_data_t *)hd_ptr;
    xlock_workspace_t       *workspace = (xlock_workspace_t *)workspace_ptr;

    fuzzy_extractor_status_t status    = xlock_validate_common(ctx, hd, w, w_len_bytes, key);

    if (status != FUZZY_EXTRACTOR_OK) {
        return status;
    }

    if (workspace == NULL) {
        return FUZZY_EXTRACTOR_ERR_NULL_ARG;
    }

    /*
     * If the vault has not been built yet, construct it from w (first call).
     * If the vault already exists, decrypt it to reconstruct the pool from w:
     * this supports multi-key generation, where the same vault is reused to
     * derive independent keys without rebuilding the error-correction structure.
     */
    if (!xlock_vault_is_set(hd->vault)) {
        status = xlock_vault_encrypt(hd->vault, ctx, w, workspace);
    } else {
        status = xlock_vault_decrypt(hd->vault, ctx, w, workspace);
    }

    if (status != FUZZY_EXTRACTOR_OK) {
        goto cleanup;
    }

    rng_status_t rng_status = random_seed_u32(&hd->key_pre_seed);

    if (rng_status != RNG_OK) {
        status = fuzzy_extractor_status_from_rng(rng_status);
        goto cleanup;
    }

    rng_status = random_bytes(hd->nonce, ctx->nonce_len_bytes);

    if (rng_status != RNG_OK) {
        status = fuzzy_extractor_status_from_rng(rng_status);
        goto cleanup;
    }

    status = xlock_derive_key(ctx, workspace, hd, key, hd->token);

cleanup:
    if (status != FUZZY_EXTRACTOR_OK && key != NULL && key->data != NULL) {
        secure_bzero(key->data, key->len_bytes);
    }

    xlock_workspace_clear(ctx, workspace);

    return status;
}

static fuzzy_extractor_status_t xlock_reproduce(const void *ctx_ptr, void *workspace_ptr,
                                                const uint8_t *w, size_t w_len_bytes,
                                                const void *hd_ptr, fuzzy_extractor_key_t *key) {
    const xlock_context_t                          *ctx = (const xlock_context_t *)ctx_ptr;
    const fuzzy_extractor_xlock_2024_helper_data_t *hd =
        (const fuzzy_extractor_xlock_2024_helper_data_t *)hd_ptr;
    xlock_workspace_t       *workspace = (xlock_workspace_t *)workspace_ptr;

    fuzzy_extractor_status_t status    = xlock_validate_common(ctx, hd, w, w_len_bytes, key);

    if (status != FUZZY_EXTRACTOR_OK) {
        return status;
    }

    if (!xlock_vault_is_set(hd->vault)) {
        return FUZZY_EXTRACTOR_ERR_NULL_ARG;
    }

    if (workspace == NULL) {
        return FUZZY_EXTRACTOR_ERR_NULL_ARG;
    }

    status = xlock_vault_decrypt(hd->vault, ctx, w, workspace);
    if (status != FUZZY_EXTRACTOR_OK) {
        goto cleanup;
    }

    status = xlock_derive_key(ctx, workspace, hd, key, workspace->token);
    if (status != FUZZY_EXTRACTOR_OK) {
        goto cleanup;
    }

    if (secure_memcmp(workspace->token, hd->token, ctx->hmac_len_bytes) != 0) {
        status = FUZZY_EXTRACTOR_ERR_REPRODUCE_FAILED;
    }

cleanup:
    if (status != FUZZY_EXTRACTOR_OK && key != NULL && key->data != NULL) {
        secure_bzero(key->data, key->len_bytes);
    }

    xlock_workspace_clear(ctx, workspace);

    return status;
}

static void xlock_vault_destroy(const xlock_context_t              *ctx,
                                fuzzy_extractor_xlock_2024_vault_t *vault) {
    if (ctx == NULL || vault == NULL) {
        return;
    }

    secure_free(vault->lock_bits, ctx->locks_n * ctx->pool_len_bytes);
    free(vault);
}

static void *xlock_vault_create(const xlock_context_t *ctx) {
    if (ctx == NULL) {
        return NULL;
    }

    fuzzy_extractor_xlock_2024_vault_t *vault = calloc(1u, sizeof(*vault));
    if (vault == NULL) {
        return NULL;
    }

    vault->lock_bits = calloc(ctx->locks_n, ctx->pool_len_bytes);
    if (vault->lock_bits == NULL) {
        free(vault);
        return NULL;
    }

    return vault;
}

static void *xlock_helper_data_create(const void *ctx_ptr) {
    const xlock_context_t *ctx = (const xlock_context_t *)ctx_ptr;
    if (ctx == NULL) {
        return NULL;
    }

    fuzzy_extractor_xlock_2024_helper_data_t *hd = calloc(1u, sizeof(*hd));
    if (hd == NULL) {
        return NULL;
    }

    hd->vault = (fuzzy_extractor_xlock_2024_vault_t *)xlock_vault_create(ctx);
    if (hd->vault == NULL) {
        goto fail;
    }

    hd->nonce = calloc(1u, ctx->nonce_len_bytes);
    if (hd->nonce == NULL) {
        goto fail;
    }

    hd->token = calloc(1u, ctx->hmac_len_bytes);
    if (hd->token == NULL) {
        goto fail;
    }

    return hd;

fail:
    xlock_vault_destroy(ctx, hd->vault);
    free(hd->nonce);
    free(hd->token);
    free(hd);
    return NULL;
}

static void xlock_helper_data_destroy(const void *ctx_ptr, void *hd_ptr) {
    const xlock_context_t                    *ctx = (const xlock_context_t *)ctx_ptr;
    fuzzy_extractor_xlock_2024_helper_data_t *hd =
        (fuzzy_extractor_xlock_2024_helper_data_t *)hd_ptr;

    if (ctx == NULL || hd == NULL) {
        return;
    }

    secure_free(hd->nonce, ctx->nonce_len_bytes);
    secure_free(hd->token, ctx->hmac_len_bytes);
    xlock_vault_destroy(ctx, hd->vault);
    free(hd);
}

static void xlock_context_destroy(void *ctx_ptr) {
    xlock_context_t *ctx = (xlock_context_t *)ctx_ptr;

    if (ctx == NULL) {
        return;
    }

    free(ctx);
}

static const fuzzy_extractor_vtable_t xlock_vtable = {
    .gen               = xlock_generate,
    .rep               = xlock_reproduce,
    .hd_init           = xlock_helper_data_create,
    .hd_free           = xlock_helper_data_destroy,
    .workspace_create  = xlock_workspace_create,
    .workspace_destroy = xlock_workspace_destroy,
    .ctx_free          = xlock_context_destroy,
};

fuzzy_extractor_status_t
fuzzy_extractor_xlock_2024_init(fuzzy_extractor_t                         *fe,
                                const fuzzy_extractor_xlock_2024_params_t *params) {
    if (fe == NULL || params == NULL) {
        return FUZZY_EXTRACTOR_ERR_NULL_ARG;
    }

    memset(fe, 0, sizeof(*fe));

    if (params->common.impl != FUZZY_EXTRACTOR_IMPL_XLOCK_2024) {
        return FUZZY_EXTRACTOR_ERR_INVALID_ARG;
    }

    if (params->hmac_alg == NULL) {
        return FUZZY_EXTRACTOR_ERR_NULL_ARG;
    }

    const size_t hmac_len_bytes = hmac_digest_len_bytes(params->hmac_alg);

    if (hmac_len_bytes == 0u) {
        return FUZZY_EXTRACTOR_ERR_INVALID_ARG;
    }

    if (params->common.w_len_bytes == 0u || params->pool_len_bytes == 0u ||
        params->key_pre_len_bytes == 0u || params->key_len_bytes == 0u || params->xor_n == 0u ||
        params->locks_n == 0u || params->nonce_len_bytes == 0u) {
        return FUZZY_EXTRACTOR_ERR_INVALID_ARG;
    }

    if (params->key_len_bytes > hmac_len_bytes) {
        return FUZZY_EXTRACTOR_ERR_INVALID_ARG;
    }

    const size_t key_pre_len_bits = bits_from_bytes(params->key_pre_len_bytes);

    const size_t pool_len_bits    = bits_from_bytes(params->pool_len_bytes);

    if (key_pre_len_bits > pool_len_bits) {
        return FUZZY_EXTRACTOR_ERR_INVALID_ARG;
    }

    const size_t indices_n  = pool_len_bits * params->locks_n * params->xor_n;

    const size_t w_len_bits = bits_from_bytes(params->common.w_len_bytes);

    if (indices_n > w_len_bits) {
        return FUZZY_EXTRACTOR_ERR_INVALID_ARG;
    }

    xlock_context_t *ctx = malloc(sizeof(*ctx));
    if (ctx == NULL) {
        return FUZZY_EXTRACTOR_ERR_OOM;
    }

    *ctx = (xlock_context_t){
        .w_len_bytes         = params->common.w_len_bytes,
        .w_len_bits          = w_len_bits,
        .prng                = params->common.prng,

        .pool_len_bytes      = params->pool_len_bytes,
        .pool_len_bits       = pool_len_bits,
        .key_pre_len_bytes   = params->key_pre_len_bytes,
        .key_pre_len_bits    = key_pre_len_bits,
        .key_len_bytes       = params->key_len_bytes,

        .xor_n               = params->xor_n,
        .locks_n             = params->locks_n,
        .nonce_len_bytes     = params->nonce_len_bytes,
        .hmac_alg            = params->hmac_alg,

        .indices_n           = indices_n,
        .hmac_len_bytes      = hmac_len_bytes,
        .used_w_len_bytes    = sample_used_len_bytes(0u, w_len_bits),
        .used_pool_len_bytes = sample_used_len_bytes(0u, pool_len_bits),
        .votes_len_bytes     = pool_len_bits * sizeof(size_t),
    };

    *fe = (fuzzy_extractor_t){
        .ctx = ctx,
        .vt  = &xlock_vtable,
    };

    return FUZZY_EXTRACTOR_OK;
}
