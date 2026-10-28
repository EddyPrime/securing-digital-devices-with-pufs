/**
 * @file prng_internal.h
 * @brief Provides internal pseudo-random number generation utilities.
 *
 * This header defines internal helpers shared by pseudo-random number
 * generator implementations. These functions assume that their arguments have
 * already been validated by the public interface.
 *
 * @warning This header is intended for internal use only.
 */

#ifndef PRNG_INTERNAL_H
#define PRNG_INTERNAL_H

#include "crypto/prng.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Fallback seed used by generators that require a non-zero state.
 */
#define PRNG_NONZERO_SEED_FALLBACK 0xDEADBEEFu

/**
 * @brief Generates a pseudo-random integer within a half-open range without
 *        validating the arguments.
 *
 * The function advances the generator state and returns a value in the range
 * [@p low, @p high). Rejection sampling is used to avoid modulo bias.
 *
 * Use prng_uniform_range() when argument validation and error reporting are
 * required.
 *
 * @param[in]     prng  Supported pseudo-random number generator algorithm.
 * @param[in,out] state Generator state to update.
 * @param[in]     low   Inclusive lower bound.
 * @param[in]     high  Exclusive upper bound.
 *
 * @return A pseudo-random value in the range [@p low, @p high).
 *
 * @pre @p state must not be @c NULL.
 * @pre @p low must be strictly less than @p high.
 * @pre @p prng must identify a supported generator.
 * @pre The size of the requested range must be representable by the
 *      implementation.
 */
size_t prng_uniform_range_unchecked(prng_t prng, rng_seed_t *state, size_t low, size_t high);

#ifdef __cplusplus
}
#endif

#endif /* PRNG_INTERNAL_H */
