/**
 * @file prng.h
 * @brief Provides deterministic pseudo-random number generators.
 *
 * This header defines the supported deterministic pseudo-random number
 * generators and the operations used to generate values from their internal
 * state.
 */

#ifndef PRNG_H
#define PRNG_H

#include "crypto/rng.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Supported pseudo-random number generator algorithms.
 */
typedef enum {
    PRNG_XORSHIFT32 = 0, /**< 32-bit xorshift generator. */
    PRNG_LFSR32,         /**< 32-bit linear-feedback shift register generator. */
    PRNG_CONSTANT,       /**< Constant deterministic generator. */
    PRNG_MARKOV,         /**< Constrained random-walk generator. */
    PRNG_BUCKET,         /**< Bucket-based generator. */
    PRNG_COUNT           /**< Number of supported generator algorithms. */
} prng_t;

/**
 * @brief Generates the next 32-bit pseudo-random value.
 *
 * The function advances the generator state and returns the resulting value.
 *
 * @param[in]     prng  Pseudo-random number generator algorithm.
 * @param[in,out] state Generator state to update.
 *
 * @return The next 32-bit pseudo-random value.
 */
uint32_t prng_next_u32(prng_t prng, rng_seed_t *state);

/**
 * @brief Generates a pseudo-random integer within a half-open range.
 *
 * The generated value belongs to the range [@p low, @p high).
 *
 * @param[in]     prng  Pseudo-random number generator algorithm.
 * @param[in,out] state Generator state to update.
 * @param[in]     low   Inclusive lower bound.
 * @param[in]     high  Exclusive upper bound.
 * @param[out]    out   Output receiving the generated value.
 *
 * @return #RNG_OK if the value is generated successfully.
 * @return An RNG error code otherwise.
 */
rng_status_t prng_uniform_range(prng_t prng, rng_seed_t *state, size_t low, size_t high,
                                size_t *out);

/**
 * @brief Checks whether a pseudo-random number generator is constant.
 *
 * @param[in] prng Pseudo-random number generator algorithm.
 *
 * @return @c true if @p prng is #PRNG_CONSTANT.
 * @return @c false otherwise.
 */
static inline bool prng_is_constant(prng_t prng) { return prng == PRNG_CONSTANT; }

#ifdef __cplusplus
}
#endif

#endif /* PRNG_H */
