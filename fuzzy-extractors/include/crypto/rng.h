/**
 * @file rng.h
 * @brief Provides common types for random generation and sampling.
 *
 * This header defines the status codes and seed type shared by the secure
 * random generation, pseudo-random generation, and random sampling modules.
 */

#ifndef RNG_H
#define RNG_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Random generation and sampling operation status codes.
 */
typedef enum {
    RNG_OK                  = 0,  /**< Operation completed successfully. */
    RNG_ERR_INVALID_ARG     = -1, /**< One or more arguments are invalid. */
    RNG_ERR_BACKEND_FAIL    = -2, /**< The underlying random generation backend failed. */
    RNG_ERR_RANGE           = -3, /**< The specified range is invalid. */
    RNG_ERR_RANGE_TOO_SMALL = -4, /**< The specified range is too small for the request. */
    RNG_ERR_UNSUPPORTED     = -5, /**< The requested operation is not supported. */
    RNG_ERR_OOM             = -6  /**< A memory allocation operation failed. */
} rng_status_t;

/**
 * @brief Returns a textual description of an RNG status code.
 *
 * @param[in] status Status code to describe.
 *
 * @return A pointer to a statically allocated, null-terminated string.
 *
 * @note The returned pointer is never @c NULL and must not be released or
 *       modified by the caller.
 */
const char *rng_status_string(rng_status_t status);

/**
 * @brief Seed type used by pseudo-random number generators.
 */
typedef uint32_t rng_seed_t;

#ifdef __cplusplus
}
#endif

#endif /* RNG_H */
