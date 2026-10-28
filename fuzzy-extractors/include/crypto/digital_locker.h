/**
 * @file digital_locker.h
 * @brief Provides a generic interface for digital locker constructions.
 *
 * This header defines the common types and operations used to bind a value to
 * a key and subsequently recover it using the same key.
 *
 * The locking operation produces a locker containing the data required by the
 * selected implementation. The exact locker format and cryptographic
 * construction are implementation-dependent.
 *
 * @note The caller must provide valid input and output buffers of the required
 *       sizes.
 */

#ifndef DIGITAL_LOCKER_H
#define DIGITAL_LOCKER_H

#include "crypto/hash.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Digital locker operation status codes.
 */
typedef enum {
    DIGITAL_LOCKER_OK                  = 0,  /**< Operation completed successfully. */
    DIGITAL_LOCKER_ERR_NULL_ARG        = -1, /**< A required pointer argument is @c NULL. */
    DIGITAL_LOCKER_ERR_INVALID_ARG     = -2, /**< One or more arguments are invalid. */
    DIGITAL_LOCKER_ERR_BACKEND_FAIL    = -3, /**< The underlying cryptographic backend failed. */
    DIGITAL_LOCKER_ERR_INVALID_PADDING = -4, /**< The locker contains invalid padding. */
    DIGITAL_LOCKER_ERR_OOM             = -5  /**< A memory allocation operation failed. */
} digital_locker_status_t;

/**
 * @brief Returns a textual description of a digital locker status code.
 *
 * @param[in] status Status code to describe.
 *
 * @return A pointer to a statically allocated, null-terminated string.
 *
 * @note The returned pointer is never @c NULL and must not be released or
 *       modified by the caller.
 */
const char *digital_locker_status_string(digital_locker_status_t status);

/**
 * @brief Stores the parameters of a digital locker construction.
 */
typedef struct {
    size_t            nonce_len_bytes; /**< Length of the nonce in bytes. */
    size_t            tag_len_bytes;   /**< Length of the authentication tag in bytes. */
    const hash_alg_t *hash_alg;        /**< Hash algorithm used by the construction. */
} digital_locker_context_t;

/**
 * @brief Stores temporary memory used by digital locker operations.
 *
 * The workspace may contain sensitive intermediate values and should be
 * securely erased before being released.
 */
typedef struct {
    uint8_t *buf;           /**< Temporary workspace buffer. */
    size_t   buf_len_bytes; /**< Length of the workspace buffer in bytes. */
} digital_locker_workspace_t;

/**
 * @brief Represents a digital locker implementation.
 *
 * A digital locker instance contains its configuration and the implementation
 * functions used to lock and unlock values.
 */
typedef struct {
    digital_locker_context_t ctx; /**< Digital locker context. */

    /**
     * @brief Locks a value using a key.
     *
     * The caller must provide an output buffer large enough to contain
     * digital_locker_size_bytes() bytes.
     *
     * @param[in]     ctx             Digital locker context.
     * @param[in,out] workspace       Workspace used by the operation.
     * @param[in]     key             Key used to lock the value.
     * @param[in]     key_len_bytes   Length of @p key in bytes.
     * @param[in]     value           Value to lock.
     * @param[in]     value_len_bytes Length of @p value in bytes.
     * @param[out]    locker          Output buffer receiving the locker.
     *
     * @return #DIGITAL_LOCKER_OK if the operation succeeds.
     * @return A digital locker error code otherwise.
     */
    digital_locker_status_t (*lock)(const digital_locker_context_t *ctx,
                                    digital_locker_workspace_t *workspace, const uint8_t *key,
                                    size_t key_len_bytes, const uint8_t *value,
                                    size_t value_len_bytes, uint8_t *locker);

    /**
     * @brief Recovers a value from a locker using a key.
     *
     * The caller must provide an output buffer large enough to contain
     * @p value_len_bytes bytes.
     *
     * @param[in]     ctx             Digital locker context.
     * @param[in,out] workspace       Workspace used by the operation.
     * @param[in]     key             Key used to unlock the value.
     * @param[in]     key_len_bytes   Length of @p key in bytes.
     * @param[out]    value           Output buffer receiving the recovered
     *                                value.
     * @param[in]     value_len_bytes Length of the value to recover in bytes.
     * @param[in]     locker          Locker containing the protected value.
     *
     * @return #DIGITAL_LOCKER_OK if the operation succeeds.
     * @return A digital locker error code otherwise.
     */
    digital_locker_status_t (*unlock)(const digital_locker_context_t *ctx,
                                      digital_locker_workspace_t *workspace, const uint8_t *key,
                                      size_t key_len_bytes, uint8_t *value, size_t value_len_bytes,
                                      const uint8_t *locker);
} digital_locker_t;

/**
 * @brief Initializes a digital locker instance.
 *
 * @param[out] dl              Digital locker instance to initialize.
 * @param[in]  nonce_len_bytes Length of the nonce in bytes.
 * @param[in]  tag_len_bytes   Length of the authentication tag in bytes.
 * @param[in]  hash_alg        Hash algorithm used by the digital locker.
 */
void digital_locker_init(digital_locker_t *dl, size_t nonce_len_bytes, size_t tag_len_bytes,
                         const hash_alg_t *hash_alg);

/**
 * @brief Returns the required locker size.
 *
 * @param[in] dl Digital locker instance.
 *
 * @return The required locker size in bytes.
 * @return @c 0 if @p dl is @c NULL or its configuration is invalid.
 */
static inline size_t digital_locker_size_bytes(const digital_locker_t *dl) {
    if (dl == NULL) {
        return 0;
    }

    const size_t hash_len = hash_digest_len_bytes(dl->ctx.hash_alg);
    if (hash_len == 0u) {
        return 0;
    }

    return dl->ctx.nonce_len_bytes + hash_len;
}

/**
 * @brief Returns the required workspace buffer size.
 *
 * @param[in] ctx           Digital locker context.
 * @param[in] key_len_bytes Length of the key in bytes.
 *
 * @return The required workspace buffer size in bytes.
 * @return @c 0 if @p ctx is @c NULL or its configuration is invalid.
 */
static inline size_t digital_locker_workspace_size(const digital_locker_context_t *ctx,
                                                   size_t                          key_len_bytes) {
    if (ctx == NULL) {
        return 0;
    }

    const size_t hash_len = hash_digest_len_bytes(ctx->hash_alg);
    if (hash_len == 0u) {
        return 0;
    }

    return hash_len + hash_len + ctx->nonce_len_bytes + key_len_bytes;
}

/**
 * @brief Allocates and initializes a digital locker workspace.
 *
 * The workspace must be released using digital_locker_workspace_destroy().
 *
 * @param[in] ctx           Digital locker context.
 * @param[in] key_len_bytes Length of the key in bytes.
 *
 * @return A pointer to the initialised workspace.
 * @return @c NULL if the arguments are invalid or memory allocation fails.
 */
digital_locker_workspace_t *digital_locker_workspace_create(const digital_locker_context_t *ctx,
                                                            size_t key_len_bytes);

/**
 * @brief Securely erases the contents of a digital locker workspace.
 *
 * This function erases the workspace buffer without releasing the workspace
 * structure or its buffer.
 *
 * @param[in]     ctx           Digital locker context.
 * @param[in,out] workspace     Workspace to erase.
 * @param[in]     key_len_bytes Length of the key used to size the workspace,
 *                              in bytes.
 */
void digital_locker_workspace_clear(const digital_locker_context_t *ctx,
                                    digital_locker_workspace_t *workspace, size_t key_len_bytes);

/**
 * @brief Securely erases and releases a digital locker workspace.
 *
 * @param[in]     ctx           Digital locker context.
 * @param[in,out] workspace     Workspace to erase and release.
 * @param[in]     key_len_bytes Length of the key used to size the workspace,
 *                              in bytes.
 */
void digital_locker_workspace_destroy(const digital_locker_context_t *ctx,
                                      digital_locker_workspace_t *workspace, size_t key_len_bytes);

#ifdef __cplusplus
}
#endif

#endif /* DIGITAL_LOCKER_H */
