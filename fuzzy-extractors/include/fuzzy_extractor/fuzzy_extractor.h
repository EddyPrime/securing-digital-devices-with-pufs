/**
 * @file fuzzy_extractor.h
 * @brief Provides a generic interface for fuzzy extractor implementations.
 *
 * This header defines the common types and operations used to derive a stable
 * key from noisy input data and subsequently reproduce the same key from a
 * sufficiently similar input.
 *
 * A fuzzy extractor provides two primary operations:
 * - generation, which derives a key from a noisy input and produces the
 *   corresponding helper data;
 * - reproduction, which uses a similar noisy input and the helper data to
 *   recover the generated key.
 *
 * The concrete implementation is selected through
 * fuzzy_extractor_params_t and accessed through a fuzzy_extractor_t instance.
 */

#ifndef FUZZY_EXTRACTOR_H
#define FUZZY_EXTRACTOR_H

#include "crypto/prng.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Fuzzy extractor operation status codes.
 */
typedef enum {
    FUZZY_EXTRACTOR_OK                   = 0,  /**< Operation completed successfully. */
    FUZZY_EXTRACTOR_ERR_NULL_ARG         = -1, /**< A required pointer argument is @c NULL. */
    FUZZY_EXTRACTOR_ERR_INVALID_ARG      = -2, /**< One or more arguments are invalid. */
    FUZZY_EXTRACTOR_ERR_BUFFER_TOO_SMALL = -3, /**< An output buffer is too small. */
    FUZZY_EXTRACTOR_ERR_OOM              = -4, /**< A memory allocation operation failed. */
    FUZZY_EXTRACTOR_ERR_RNG_FAILED       = -5, /**< A random number generation operation failed. */
    FUZZY_EXTRACTOR_ERR_CRYPTO_BACKEND   = -6, /**< A cryptographic backend operation failed. */
    FUZZY_EXTRACTOR_ERR_HASH_FAILED      = -7, /**< A hash operation failed. */
    FUZZY_EXTRACTOR_ERR_HMAC_FAILED      = -8, /**< An HMAC operation failed. */
    FUZZY_EXTRACTOR_ERR_REPRODUCE_FAILED = -9  /**< Key reproduction failed. */
} fuzzy_extractor_status_t;

/**
 * @brief Returns a textual description of a fuzzy extractor status code.
 *
 * @param[in] status Status code to describe.
 *
 * @return A pointer to a statically allocated, null-terminated string.
 *
 * @note The returned pointer is never @c NULL and must not be released or
 *       modified by the caller.
 */
const char *fuzzy_extractor_status_string(fuzzy_extractor_status_t status);

typedef enum {
    FUZZY_EXTRACTOR_IMPL_XLOCK_2024 = 0, /**< Original X-Lock (2024). */
    FUZZY_EXTRACTOR_IMPL_STL,            /**< STL fuzzy extractor. */
    FUZZY_EXTRACTOR_IMPL_XLOCK_2026,     /**< Revised X-Lock (2026). */
    FUZZY_EXTRACTOR_COUNT                /**< Number of supported implementations. */
} fuzzy_extractor_implementation_t;

/**
 * @brief Stores the common fuzzy extractor initialization parameters.
 *
 * Each implementation-specific parameter structure must place this structure
 * as its first member. This layout allows fuzzy_extractor_init() to inspect the
 * common prefix and dispatch initialization to the selected implementation.
 */
typedef struct {
    fuzzy_extractor_implementation_t impl;        /**< Fuzzy extractor implementation to use. */
    size_t                           w_len_bytes; /**< Length of the noisy input word in bytes. */
    prng_t                           prng; /**< PRNG used by implementations that require one. */
} fuzzy_extractor_params_t;

/**
 * @brief Stores a key produced by a fuzzy extractor.
 *
 * The key buffer may contain sensitive material and should be securely erased
 * before being released.
 */
typedef struct {
    uint8_t *data;      /**< Buffer containing the key. */
    size_t   len_bytes; /**< Length of the key in bytes. */
} fuzzy_extractor_key_t;

/**
 * @brief Defines the operations provided by a fuzzy extractor implementation.
 *
 * This structure contains the implementation-specific functions used by the
 * generic fuzzy extractor interface.
 */
typedef struct fuzzy_extractor_vtable {
    /**
     * @brief Generates helper data and a key from a noisy input.
     *
     * @param[in]     ctx         Implementation-specific context.
     * @param[in,out] workspace   Implementation-specific workspace.
     * @param[in]     w           Noisy input word.
     * @param[in]     w_len_bytes Length of @p w in bytes.
     * @param[out]    hd          Helper data object receiving the generated
     *                            helper data.
     * @param[out]    key         Output receiving the generated key.
     *
     * @return #FUZZY_EXTRACTOR_OK if generation succeeds.
     * @return A fuzzy extractor error code otherwise.
     */
    fuzzy_extractor_status_t (*gen)(const void *ctx, void *workspace, const uint8_t *w,
                                    size_t w_len_bytes, void *hd, fuzzy_extractor_key_t *key);

    /**
     * @brief Reproduces a key from a noisy input and helper data.
     *
     * @param[in]     ctx         Implementation-specific context.
     * @param[in,out] workspace   Implementation-specific workspace.
     * @param[in]     w           Noisy input word.
     * @param[in]     w_len_bytes Length of @p w in bytes.
     * @param[in]     hd          Helper data used for reproduction.
     * @param[out]    key         Output receiving the reproduced key.
     *
     * @return #FUZZY_EXTRACTOR_OK if reproduction succeeds.
     * @return A fuzzy extractor error code otherwise.
     */
    fuzzy_extractor_status_t (*rep)(const void *ctx, void *workspace, const uint8_t *w,
                                    size_t w_len_bytes, const void *hd, fuzzy_extractor_key_t *key);

    /**
     * @brief Allocates and initializes implementation-specific helper data.
     *
     * @param[in] ctx Implementation-specific context.
     *
     * @return A pointer to the initialised helper data object.
     * @return @c NULL if allocation or initialization fails.
     */
    void *(*hd_init)(const void *ctx);

    /**
     * @brief Securely clears and releases implementation-specific helper data.
     *
     * @param[in]     ctx Implementation-specific context.
     * @param[in,out] hd  Helper data object to clear and release.
     */
    void (*hd_free)(const void *ctx, void *hd);

    /**
     * @brief Allocates and initializes an implementation-specific workspace.
     *
     * @param[in] ctx Implementation-specific context.
     *
     * @return A pointer to the initialised workspace.
     * @return @c NULL if allocation or initialization fails.
     */
    void *(*workspace_create)(const void *ctx);

    /**
     * @brief Securely clears and releases an implementation-specific workspace.
     *
     * @param[in]     ctx       Implementation-specific context.
     * @param[in,out] workspace Workspace to clear and release.
     */
    void (*workspace_destroy)(const void *ctx, void *workspace);

    /**
     * @brief Securely clears and releases an implementation-specific context.
     *
     * @param[in,out] ctx Implementation-specific context to clear and release.
     */
    void (*ctx_free)(void *ctx);
} fuzzy_extractor_vtable_t;

/**
 * @brief Represents a fuzzy extractor instance.
 *
 * The instance stores an implementation-specific context and the corresponding
 * operation table.
 */
typedef struct {
    void                           *ctx; /**< Implementation-specific context. */
    const fuzzy_extractor_vtable_t *vt;  /**< Implementation-specific operation table. */
} fuzzy_extractor_t;

/**
 * @brief Initializes a fuzzy extractor instance.
 *
 * The initialised instance must be released using fuzzy_extractor_destroy().
 *
 * @param[out] fe     Fuzzy extractor instance to initialize.
 * @param[in]  params Initialization parameters for the selected implementation.
 *
 * @return #FUZZY_EXTRACTOR_OK if initialization succeeds.
 * @return A fuzzy extractor error code otherwise.
 */
fuzzy_extractor_status_t fuzzy_extractor_init(fuzzy_extractor_t              *fe,
                                              const fuzzy_extractor_params_t *params);

/**
 * @brief Generates helper data and a key from a noisy input.
 *
 * @param[in]     fe          initialised fuzzy extractor instance.
 * @param[in,out] workspace   Workspace returned by
 *                            fuzzy_extractor_workspace_create().
 * @param[in]     w           Noisy input word.
 * @param[in]     w_len_bytes Length of @p w in bytes.
 * @param[out]    hd          Helper data object returned by
 *                            fuzzy_extractor_helper_data_create().
 * @param[out]    key         Output receiving the generated key.
 *
 * @return #FUZZY_EXTRACTOR_OK if generation succeeds.
 * @return #FUZZY_EXTRACTOR_ERR_NULL_ARG if a required argument or
 *         implementation field is @c NULL.
 * @return A fuzzy extractor error code otherwise.
 */
static inline fuzzy_extractor_status_t fuzzy_extractor_generate(const fuzzy_extractor_t *fe,
                                                                void *workspace, const uint8_t *w,
                                                                size_t w_len_bytes, void *hd,
                                                                fuzzy_extractor_key_t *key) {
    if (fe == NULL || fe->ctx == NULL || fe->vt == NULL || fe->vt->gen == NULL ||
        workspace == NULL || w == NULL || hd == NULL || key == NULL) {
        return FUZZY_EXTRACTOR_ERR_NULL_ARG;
    }

    return fe->vt->gen(fe->ctx, workspace, w, w_len_bytes, hd, key);
}

/**
 * @brief Reproduces a key from a noisy input and helper data.
 *
 * @param[in]     fe          initialised fuzzy extractor instance.
 * @param[in,out] workspace   Workspace returned by
 *                            fuzzy_extractor_workspace_create().
 * @param[in]     w           Noisy input word.
 * @param[in]     w_len_bytes Length of @p w in bytes.
 * @param[in]     hd          Helper data used for reproduction.
 * @param[out]    key         Output receiving the reproduced key.
 *
 * @return #FUZZY_EXTRACTOR_OK if reproduction succeeds.
 * @return #FUZZY_EXTRACTOR_ERR_NULL_ARG if a required argument or
 *         implementation field is @c NULL.
 * @return A fuzzy extractor error code otherwise.
 */
static inline fuzzy_extractor_status_t fuzzy_extractor_reproduce(const fuzzy_extractor_t *fe,
                                                                 void *workspace, const uint8_t *w,
                                                                 size_t w_len_bytes, const void *hd,
                                                                 fuzzy_extractor_key_t *key) {
    if (fe == NULL || fe->ctx == NULL || fe->vt == NULL || fe->vt->rep == NULL ||
        workspace == NULL || w == NULL || hd == NULL || key == NULL) {
        return FUZZY_EXTRACTOR_ERR_NULL_ARG;
    }

    return fe->vt->rep(fe->ctx, workspace, w, w_len_bytes, hd, key);
}

/**
 * @brief Allocates and initializes helper data for a fuzzy extractor instance.
 *
 * The returned object must be released using
 * fuzzy_extractor_helper_data_destroy().
 *
 * @param[in] fe initialised fuzzy extractor instance.
 *
 * @return A pointer to the initialised helper data object.
 * @return @c NULL if the instance is invalid or initialization fails.
 */
static inline void *fuzzy_extractor_helper_data_create(const fuzzy_extractor_t *fe) {
    if (fe == NULL || fe->ctx == NULL || fe->vt == NULL || fe->vt->hd_init == NULL) {
        return NULL;
    }

    return fe->vt->hd_init(fe->ctx);
}

/**
 * @brief Securely clears and releases helper data.
 *
 * The function has no effect if the fuzzy extractor instance, the helper data
 * object, or the required implementation operation is invalid.
 *
 * @param[in]     fe initialised fuzzy extractor instance.
 * @param[in,out] hd Helper data object to clear and release.
 */
static inline void fuzzy_extractor_helper_data_destroy(const fuzzy_extractor_t *fe, void *hd) {
    if (fe == NULL || fe->ctx == NULL || fe->vt == NULL || fe->vt->hd_free == NULL || hd == NULL) {
        return;
    }

    fe->vt->hd_free(fe->ctx, hd);
}

/**
 * @brief Allocates and initializes a workspace for a fuzzy extractor instance.
 *
 * The returned workspace must be released using
 * fuzzy_extractor_workspace_destroy().
 *
 * @param[in] fe initialised fuzzy extractor instance.
 *
 * @return A pointer to the initialised workspace.
 * @return @c NULL if the instance is invalid or initialization fails.
 */
static inline void *fuzzy_extractor_workspace_create(const fuzzy_extractor_t *fe) {
    if (fe == NULL || fe->ctx == NULL || fe->vt == NULL || fe->vt->workspace_create == NULL) {
        return NULL;
    }

    return fe->vt->workspace_create(fe->ctx);
}

/**
 * @brief Securely clears and releases a fuzzy extractor workspace.
 *
 * The function has no effect if the fuzzy extractor instance, the workspace,
 * or the required implementation operation is invalid.
 *
 * @param[in]     fe        initialised fuzzy extractor instance.
 * @param[in,out] workspace Workspace to clear and release.
 */
static inline void fuzzy_extractor_workspace_destroy(const fuzzy_extractor_t *fe, void *workspace) {
    if (fe == NULL || fe->ctx == NULL || fe->vt == NULL || fe->vt->workspace_destroy == NULL ||
        workspace == NULL) {
        return;
    }

    fe->vt->workspace_destroy(fe->ctx, workspace);
}

/**
 * @brief Securely clears and releases a fuzzy extractor instance.
 *
 * After the implementation-specific context is released, the instance is
 * reset to an empty state by setting its context and operation table pointers
 * to @c NULL.
 *
 * The function has no effect if @p fe is @c NULL.
 *
 * @param[in,out] fe Fuzzy extractor instance to clear and release.
 */
static inline void fuzzy_extractor_destroy(fuzzy_extractor_t *fe) {
    if (fe == NULL) {
        return;
    }

    if (fe->ctx != NULL && fe->vt != NULL && fe->vt->ctx_free != NULL) {
        fe->vt->ctx_free(fe->ctx);
    }

    fe->ctx = NULL;
    fe->vt  = NULL;
}

#ifdef __cplusplus
}
#endif

#endif /* FUZZY_EXTRACTOR_H */
