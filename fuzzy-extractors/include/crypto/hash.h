/**
 * @file hash.h
 * @brief Provides a generic interface for hash algorithms.
 *
 * This header defines an algorithm-independent interface for computing hash
 * digests. Each supported hash algorithm is represented by an opaque
 * descriptor that specifies the corresponding implementation and digest size.
 */

#ifndef HASH_H
#define HASH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Hash operation status codes.
 */
typedef enum {
    HASH_OK                = 0,  /**< Operation completed successfully. */
    HASH_ERR_NULL_ARG      = -1, /**< A required pointer argument is @c NULL. */
    HASH_ERR_OUT_TOO_SMALL = -2, /**< The output buffer is too small. */
    HASH_ERR_BACKEND_FAIL  = -3  /**< The underlying hash backend failed. */
} hash_status_t;

/**
 * @brief Opaque descriptor of a hash algorithm.
 */
typedef struct hash_alg hash_alg_t;

/**
 * @brief Returns a textual description of a hash status code.
 *
 * @param[in] status Status code to describe.
 *
 * @return A pointer to a statically allocated, null-terminated string.
 *
 * @note The returned pointer is never @c NULL and must not be released or
 *       modified by the caller.
 */
const char *hash_status_string(hash_status_t status);

/**
 * @brief Returns the digest length of a hash algorithm.
 *
 * @param[in] alg Hash algorithm descriptor.
 *
 * @return The digest length in bytes.
 * @return @c 0 if @p alg is @c NULL.
 */
size_t hash_digest_len_bytes(const hash_alg_t *alg);

/**
 * @brief Computes the hash digest of an input buffer.
 *
 * The output buffer must contain at least the number of bytes returned by
 * hash_digest_len_bytes() for the selected algorithm.
 *
 * @param[in]  alg               Hash algorithm descriptor.
 * @param[in]  data              Input data.
 * @param[in]  data_len_bytes    Length of @p data in bytes.
 * @param[out] digest            Output buffer receiving the computed digest.
 * @param[in]  digest_len_bytes  Length of @p digest in bytes.
 *
 * @return #HASH_OK if the digest is computed successfully.
 * @return A hash error code otherwise.
 */
hash_status_t hash_digest(const hash_alg_t *alg, const void *data, size_t data_len_bytes,
                          uint8_t *digest, size_t digest_len_bytes);

/**
 * @brief SHA-256 hash algorithm descriptor.
 */
extern const hash_alg_t hash_alg_sha_256;

/**
 * @brief SHA-512 hash algorithm descriptor.
 */
extern const hash_alg_t hash_alg_sha_512;

/**
 * @brief 32-bit FNV-1a hash algorithm descriptor.
 *
 * @warning FNV-1a is not a cryptographic hash function and must not be used
 *          for security-critical purposes.
 */
extern const hash_alg_t hash_alg_fnv1a_32;

#ifdef __cplusplus
}
#endif

#endif /* HASH_H */
