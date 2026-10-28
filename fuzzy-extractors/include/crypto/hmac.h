/**
 * @file hmac.h
 * @brief Provides a generic interface for HMAC algorithms.
 *
 * This header defines an algorithm-independent interface for computing HMAC
 * authentication codes. Each supported HMAC algorithm is represented by an
 * opaque descriptor that specifies the corresponding implementation and
 * digest length.
 */

#ifndef HMAC_H
#define HMAC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief HMAC operation status codes.
 */
typedef enum {
    HMAC_OK                = 0,  /**< Operation completed successfully. */
    HMAC_ERR_NULL_ARG      = -1, /**< A required pointer argument is @c NULL. */
    HMAC_ERR_OUT_TOO_SMALL = -2, /**< The output buffer is too small. */
    HMAC_ERR_KEY_TOO_LARGE = -3, /**< The key is too large for the backend. */
    HMAC_ERR_BACKEND_FAIL  = -4  /**< The underlying HMAC backend failed. */
} hmac_status_t;

/**
 * @brief Opaque descriptor of an HMAC algorithm.
 */
typedef struct hmac_alg hmac_alg_t;

/**
 * @brief Returns a textual description of an HMAC status code.
 *
 * @param[in] status Status code to describe.
 *
 * @return A pointer to a statically allocated, null-terminated string.
 *
 * @note The returned pointer is never @c NULL and must not be released or
 *       modified by the caller.
 */
const char *hmac_status_string(hmac_status_t status);

/**
 * @brief Returns the digest length of an HMAC algorithm.
 *
 * @param[in] alg HMAC algorithm descriptor.
 *
 * @return The HMAC digest length in bytes.
 * @return @c 0 if @p alg is @c NULL.
 */
size_t hmac_digest_len_bytes(const hmac_alg_t *alg);

/**
 * @brief Computes the HMAC digest of an input buffer.
 *
 * The output buffer must contain at least the number of bytes returned by
 * hmac_digest_len_bytes() for the selected algorithm.
 *
 * @param[in]  alg              HMAC algorithm descriptor.
 * @param[in]  key              Secret key.
 * @param[in]  key_len_bytes    Length of @p key in bytes.
 * @param[in]  data             Input data.
 * @param[in]  data_len_bytes   Length of @p data in bytes.
 * @param[out] digest           Output buffer receiving the computed HMAC
 *                              digest.
 * @param[in]  digest_len_bytes Length of @p digest in bytes.
 *
 * @return #HMAC_OK if the digest is computed successfully.
 * @return An HMAC error code otherwise.
 */
hmac_status_t hmac_digest(const hmac_alg_t *alg, const void *key, size_t key_len_bytes,
                          const void *data, size_t data_len_bytes, uint8_t *digest,
                          size_t digest_len_bytes);

/**
 * @brief Represents a portion of an HMAC input message.
 */
typedef struct {
    const void *data;
    size_t      len_bytes;
} hmac_part_t;

/**
 * @brief Computes HMAC over the concatenation of multiple
 * input buffers without allocating an intermediate buffer.
 */
hmac_status_t hmac_digest_parts(const hmac_alg_t *alg, const void *key, size_t key_len_bytes,
                                const hmac_part_t *parts, size_t parts_n, uint8_t *digest,
                                size_t digest_len_bytes);

/**
 * @brief HMAC-SHA-256 algorithm descriptor.
 */
extern const hmac_alg_t hmac_alg_sha_256;

/**
 * @brief HMAC-SHA-512 algorithm descriptor.
 */
extern const hmac_alg_t hmac_alg_sha_512;

#ifdef __cplusplus
}
#endif

#endif /* HMAC_H */
