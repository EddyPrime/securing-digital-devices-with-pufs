/**
 * @file stl.c
 * @brief Implementation of the STL fuzzy extractor.
 */

#include "fuzzy_extractor/implementations/stl.h"

#include "common/bits.h"
#include "common/secure_memory.h"
#include "crypto/digital_locker.h"
#include "crypto/random.h"
#include "crypto/sample.h"
#include "fuzzy_extractor/core/fuzzy_extractor_internal.h"
#include "fuzzy_extractor/core/workspace_internal.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    size_t           w_len_bytes;
    size_t           w_len_bits;
    prng_t           prng;

    size_t           digital_locker_nonce_len_bytes;
    size_t           digital_locker_key_len_bytes;
    size_t           dl_key_len_bits;
    size_t           locks_n;
    size_t           key_len_bytes;

    size_t           used_len_bytes;
    size_t           locker_len_bytes;

    digital_locker_t dl;
} stl_context_t;

typedef struct {
    digital_locker_workspace_t *locker_workspace;
    uint8_t                    *v;
    uint8_t                    *candidate;
    uint8_t                    *used;
} stl_workspace_t;

static void stl_workspace_clear(const stl_context_t *ctx, stl_workspace_t *workspace) {
    if (ctx == NULL || workspace == NULL) {
        return;
    }

    if (workspace->v != NULL) {
        secure_bzero(workspace->v, ctx->digital_locker_key_len_bytes);
    }

    if (workspace->candidate != NULL) {
        secure_bzero(workspace->candidate, ctx->key_len_bytes);
    }

    if (workspace->locker_workspace != NULL) {
        digital_locker_workspace_clear(&ctx->dl.ctx, workspace->locker_workspace,
                                       ctx->digital_locker_key_len_bytes);
    }

    if (workspace->used != NULL) {
        secure_bzero(workspace->used, ctx->used_len_bytes);
    }
}

static void *stl_workspace_create(const void *ctx_ptr) {
    const stl_context_t *ctx = (const stl_context_t *)ctx_ptr;
    if (ctx == NULL) {
        return NULL;
    }

    const size_t locker_workspace_buffer_len_bytes =
        digital_locker_workspace_size(&ctx->dl.ctx, ctx->digital_locker_key_len_bytes);

    if (ctx->digital_locker_key_len_bytes == 0u || ctx->key_len_bytes == 0u ||
        ctx->used_len_bytes == 0u || locker_workspace_buffer_len_bytes == 0u) {
        return NULL;
    }

    const size_t locker_workspace_alignment = _Alignof(digital_locker_workspace_t);

    const size_t workspace_len_bytes =
        sizeof(digital_locker_workspace_t) + locker_workspace_alignment - 1u +
        locker_workspace_buffer_len_bytes + ctx->digital_locker_key_len_bytes + ctx->key_len_bytes +
        ctx->used_len_bytes;

    stl_workspace_t *workspace = calloc(1u, sizeof(*workspace) + workspace_len_bytes);

    if (workspace == NULL) {
        return NULL;
    }

    uint8_t *cursor             = (uint8_t *)(workspace + 1);
    cursor                      = workspace_align_cursor(cursor, locker_workspace_alignment);

    workspace->locker_workspace = (digital_locker_workspace_t *)workspace_alloc_slice(
        &cursor, sizeof(*workspace->locker_workspace));

    workspace->locker_workspace->buf =
        workspace_alloc_slice(&cursor, locker_workspace_buffer_len_bytes);

    workspace->locker_workspace->buf_len_bytes = locker_workspace_buffer_len_bytes;

    workspace->v         = workspace_alloc_slice(&cursor, ctx->digital_locker_key_len_bytes);

    workspace->candidate = workspace_alloc_slice(&cursor, ctx->key_len_bytes);

    workspace->used      = workspace_alloc_slice(&cursor, ctx->used_len_bytes);

    return workspace;
}

static void stl_workspace_destroy(const void *ctx_ptr, void *workspace_ptr) {
    const stl_context_t *ctx       = (const stl_context_t *)ctx_ptr;
    stl_workspace_t     *workspace = (stl_workspace_t *)workspace_ptr;

    if (ctx == NULL || workspace == NULL) {
        return;
    }

    stl_workspace_clear(ctx, workspace);
    free(workspace);
}

static fuzzy_extractor_status_t stl_generate(const void *ctx_ptr, void *workspace_ptr,
                                             const uint8_t *w, size_t w_len_bytes, void *hd_ptr,
                                             fuzzy_extractor_key_t *key) {
    const stl_context_t               *ctx       = (const stl_context_t *)ctx_ptr;
    stl_workspace_t                   *workspace = (stl_workspace_t *)workspace_ptr;
    fuzzy_extractor_stl_helper_data_t *hd        = (fuzzy_extractor_stl_helper_data_t *)hd_ptr;

    fuzzy_extractor_status_t           ret       = FUZZY_EXTRACTOR_OK;

    if (ctx == NULL || workspace == NULL || w == NULL || hd == NULL || key == NULL ||
        key->data == NULL) {
        return FUZZY_EXTRACTOR_ERR_NULL_ARG;
    }

    if (hd->seeds == NULL || hd->lockers == NULL) {
        return FUZZY_EXTRACTOR_ERR_NULL_ARG;
    }

    if (w_len_bytes != ctx->w_len_bytes) {
        return FUZZY_EXTRACTOR_ERR_INVALID_ARG;
    }

    if (key->len_bytes != ctx->key_len_bytes) {
        return FUZZY_EXTRACTOR_ERR_INVALID_ARG;
    }

    secure_bzero(key->data, ctx->key_len_bytes);

    rng_status_t rng_status = random_bytes(key->data, ctx->key_len_bytes);

    if (rng_status != RNG_OK) {
        return fuzzy_extractor_status_from_rng(rng_status);
    }

    for (size_t i = 0u; i < ctx->locks_n; i++) {
        rng_status = random_seed_u32(&hd->seeds[i]);
        if (rng_status != RNG_OK) {
            ret = fuzzy_extractor_status_from_rng(rng_status);
            goto cleanup;
        }
    }

    uint8_t                    *v                = workspace->v;
    digital_locker_workspace_t *locker_workspace = workspace->locker_workspace;
    uint8_t                    *used             = workspace->used;
    const size_t                used_len_bytes   = ctx->used_len_bytes;

    for (size_t i = 0u; i < ctx->locks_n; i++) {
        uint8_t        *locker = hd->lockers + i * ctx->locker_len_bytes;
        rng_seed_t      seed   = hd->seeds[i];
        sample_stream_t stream;

        secure_bzero(v, ctx->digital_locker_key_len_bytes);

        rng_status = sample_stream_init(&stream, ctx->prng, SAMPLE_MODE_WITHOUT_REPLACEMENT,
                                        ctx->dl_key_len_bits, 0u, ctx->w_len_bits, &seed, used,
                                        used_len_bytes);

        if (rng_status != RNG_OK) {
            ret = fuzzy_extractor_status_from_rng(rng_status);
            goto cleanup;
        }

        for (size_t j = 0u; j < ctx->dl_key_len_bits; j++) {
            size_t index = 0u;

            rng_status   = sample_stream_next(&stream, &index);
            if (rng_status != RNG_OK) {
                ret = fuzzy_extractor_status_from_rng(rng_status);
                goto cleanup;
            }

            bits_set(v, j, bits_get(w, index));
        }

        digital_locker_status_t dl_status =
            ctx->dl.lock(&ctx->dl.ctx, locker_workspace, v, ctx->digital_locker_key_len_bytes,
                         key->data, ctx->key_len_bytes, locker);

        if (dl_status != DIGITAL_LOCKER_OK) {
            ret = fuzzy_extractor_status_from_digital_locker(dl_status);
            goto cleanup;
        }
    }

cleanup:
    stl_workspace_clear(ctx, workspace);

    if (ret != FUZZY_EXTRACTOR_OK && key != NULL && key->data != NULL) {
        secure_bzero(key->data, ctx->key_len_bytes);
    }

    return ret;
}

static fuzzy_extractor_status_t stl_reproduce(const void *ctx_ptr, void *workspace_ptr,
                                              const uint8_t *w, size_t w_len_bytes,
                                              const void *hd_ptr, fuzzy_extractor_key_t *key) {
    const stl_context_t                     *ctx       = (const stl_context_t *)ctx_ptr;
    stl_workspace_t                         *workspace = (stl_workspace_t *)workspace_ptr;
    const fuzzy_extractor_stl_helper_data_t *hd = (const fuzzy_extractor_stl_helper_data_t *)hd_ptr;

    fuzzy_extractor_status_t                 ret = FUZZY_EXTRACTOR_ERR_REPRODUCE_FAILED;

    if (ctx == NULL || workspace == NULL || w == NULL || hd == NULL || key == NULL ||
        key->data == NULL) {
        return FUZZY_EXTRACTOR_ERR_NULL_ARG;
    }

    if (hd->seeds == NULL || hd->lockers == NULL) {
        return FUZZY_EXTRACTOR_ERR_NULL_ARG;
    }

    if (w_len_bytes != ctx->w_len_bytes) {
        return FUZZY_EXTRACTOR_ERR_INVALID_ARG;
    }

    if (key->len_bytes != ctx->key_len_bytes) {
        return FUZZY_EXTRACTOR_ERR_INVALID_ARG;
    }

    secure_bzero(key->data, ctx->key_len_bytes);

    uint8_t                    *v                = workspace->v;
    uint8_t                    *candidate        = workspace->candidate;
    digital_locker_workspace_t *locker_workspace = workspace->locker_workspace;
    uint8_t                    *used             = workspace->used;
    const size_t                used_len_bytes   = ctx->used_len_bytes;

    for (size_t i = 0u; i < ctx->locks_n; i++) {
        const uint8_t  *locker = hd->lockers + i * ctx->locker_len_bytes;
        rng_seed_t      seed   = hd->seeds[i];
        sample_stream_t stream;

        secure_bzero(v, ctx->digital_locker_key_len_bytes);
        secure_bzero(candidate, ctx->key_len_bytes);

        rng_status_t rng_status = sample_stream_init(
            &stream, ctx->prng, SAMPLE_MODE_WITHOUT_REPLACEMENT, ctx->dl_key_len_bits, 0u,
            ctx->w_len_bits, &seed, used, used_len_bytes);

        if (rng_status != RNG_OK) {
            ret = fuzzy_extractor_status_from_rng(rng_status);
            goto cleanup;
        }

        for (size_t j = 0u; j < ctx->dl_key_len_bits; j++) {
            size_t index = 0u;

            rng_status   = sample_stream_next(&stream, &index);
            if (rng_status != RNG_OK) {
                ret = fuzzy_extractor_status_from_rng(rng_status);
                goto cleanup;
            }

            bits_set(v, j, bits_get(w, index));
        }

        digital_locker_status_t dl_status =
            ctx->dl.unlock(&ctx->dl.ctx, locker_workspace, v, ctx->digital_locker_key_len_bytes,
                           candidate, ctx->key_len_bytes, locker);

        if (dl_status == DIGITAL_LOCKER_OK) {
            memcpy(key->data, candidate, ctx->key_len_bytes);
            ret = FUZZY_EXTRACTOR_OK;
            goto cleanup;
        }
    }

cleanup:
    stl_workspace_clear(ctx, workspace);

    if (ret != FUZZY_EXTRACTOR_OK && key != NULL && key->data != NULL) {
        secure_bzero(key->data, ctx->key_len_bytes);
    }

    return ret;
}

static void *stl_helper_data_create(const void *ctx_ptr) {
    const stl_context_t *ctx = (const stl_context_t *)ctx_ptr;
    if (ctx == NULL) {
        return NULL;
    }

    fuzzy_extractor_stl_helper_data_t *hd = calloc(1u, sizeof(*hd));
    if (hd == NULL) {
        return NULL;
    }

    hd->seeds   = calloc(ctx->locks_n, sizeof(*hd->seeds));
    hd->lockers = calloc(ctx->locks_n, ctx->locker_len_bytes);

    if (hd->seeds == NULL || hd->lockers == NULL) {
        free(hd->seeds);
        free(hd->lockers);
        free(hd);
        return NULL;
    }

    return hd;
}

static void stl_helper_data_destroy(const void *ctx_ptr, void *hd_ptr) {
    const stl_context_t               *ctx = (const stl_context_t *)ctx_ptr;
    fuzzy_extractor_stl_helper_data_t *hd  = (fuzzy_extractor_stl_helper_data_t *)hd_ptr;

    if (ctx == NULL || hd == NULL) {
        return;
    }

    secure_free(hd->seeds, ctx->locks_n * sizeof(*hd->seeds));
    secure_free(hd->lockers, ctx->locks_n * ctx->locker_len_bytes);
    free(hd);
}

static void stl_context_destroy(void *ctx_ptr) {
    stl_context_t *ctx = (stl_context_t *)ctx_ptr;

    if (ctx == NULL) {
        return;
    }

    free(ctx);
}

static const fuzzy_extractor_vtable_t stl_vtable = {
    .gen               = stl_generate,
    .rep               = stl_reproduce,
    .hd_init           = stl_helper_data_create,
    .hd_free           = stl_helper_data_destroy,
    .workspace_create  = stl_workspace_create,
    .workspace_destroy = stl_workspace_destroy,
    .ctx_free          = stl_context_destroy,
};

fuzzy_extractor_status_t fuzzy_extractor_stl_init(fuzzy_extractor_t                  *fe,
                                                  const fuzzy_extractor_stl_params_t *params) {
    if (fe == NULL || params == NULL) {
        return FUZZY_EXTRACTOR_ERR_NULL_ARG;
    }

    memset(fe, 0, sizeof(*fe));

    if (params->common.impl != FUZZY_EXTRACTOR_IMPL_STL) {
        return FUZZY_EXTRACTOR_ERR_INVALID_ARG;
    }

    if (params->hash_alg == NULL) {
        return FUZZY_EXTRACTOR_ERR_NULL_ARG;
    }

    const size_t hash_len_bytes = hash_digest_len_bytes(params->hash_alg);

    if (hash_len_bytes == 0u) {
        return FUZZY_EXTRACTOR_ERR_INVALID_ARG;
    }

    if (params->common.w_len_bytes == 0u || params->digital_locker_nonce_len_bytes == 0u ||
        params->digital_locker_tag_len_bytes == 0u || params->digital_locker_key_len_bytes == 0u ||
        params->locks_n == 0u || params->key_len_bytes == 0u) {
        return FUZZY_EXTRACTOR_ERR_INVALID_ARG;
    }

    if (params->key_len_bytes > hash_len_bytes) {
        return FUZZY_EXTRACTOR_ERR_INVALID_ARG;
    }

    const size_t dl_key_len_bits = bits_from_bytes(params->digital_locker_key_len_bytes);

    const size_t w_len_bits      = bits_from_bytes(params->common.w_len_bytes);

    if (dl_key_len_bits > w_len_bits) {
        return FUZZY_EXTRACTOR_ERR_INVALID_ARG;
    }

    stl_context_t *ctx = malloc(sizeof(*ctx));
    if (ctx == NULL) {
        return FUZZY_EXTRACTOR_ERR_OOM;
    }

    *ctx = (stl_context_t){
        .w_len_bytes                    = params->common.w_len_bytes,
        .w_len_bits                     = w_len_bits,
        .prng                           = params->common.prng,

        .digital_locker_nonce_len_bytes = params->digital_locker_nonce_len_bytes,
        .digital_locker_key_len_bytes   = params->digital_locker_key_len_bytes,
        .dl_key_len_bits                = dl_key_len_bits,
        .locks_n                        = params->locks_n,
        .key_len_bytes                  = params->key_len_bytes,

        .used_len_bytes                 = sample_used_len_bytes(0u, w_len_bits),
    };

    digital_locker_init(&ctx->dl, params->digital_locker_nonce_len_bytes,
                        params->digital_locker_tag_len_bytes, params->hash_alg);

    ctx->locker_len_bytes = digital_locker_size_bytes(&ctx->dl);
    if (ctx->locker_len_bytes == 0u) {
        free(ctx);
        return FUZZY_EXTRACTOR_ERR_INVALID_ARG;
    }

    *fe = (fuzzy_extractor_t){
        .ctx = ctx,
        .vt  = &stl_vtable,
    };

    return FUZZY_EXTRACTOR_OK;
}
