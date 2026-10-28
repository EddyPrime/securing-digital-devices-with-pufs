/**
 * @file sample.h
 * @brief Provides pseudo-random sampling utilities.
 *
 * This header defines functions for sampling integer values and bit positions
 * using the supported pseudo-random number generators. Sampling may be
 * performed either with or without replacement.
 */

#ifndef SAMPLE_H
#define SAMPLE_H

#include "crypto/prng.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Supported sampling modes.
 */
typedef enum {
    SAMPLE_MODE_WITH_REPLACEMENT = 0, /**< Allows the same value to be sampled multiple times. */
    SAMPLE_MODE_WITHOUT_REPLACEMENT,  /**< Ensures that each sampled value is unique. */
    SAMPLE_MODE_COUNT                 /**< Number of supported sample modes. */
} sample_mode_t;

/**
 * @brief Stores the state of an incremental sampling operation.
 *
 * A sampling stream produces values incrementally from the half-open range
 * [@p low, @p high). Depending on the selected mode, values may be sampled
 * either with or without replacement.
 *
 * When sampling without replacement, @p used must reference a caller-provided
 * bitmap containing at least sample_used_len_bytes() bytes.
 */
typedef struct {
    prng_t        prng;           /**< Pseudo-random number generator algorithm. */
    sample_mode_t mode;           /**< Sampling mode. */
    size_t        samples_n;      /**< Total number of samples to produce. */
    size_t        sampled;        /**< Number of samples already produced. */
    size_t        low;            /**< Inclusive lower bound of the sampling range. */
    size_t        high;           /**< Exclusive upper bound of the sampling range. */
    size_t        range;          /**< Size of the sampling range, equal to @p high - @p low. */
    rng_seed_t    state;          /**< Current pseudo-random number generator state. */
    uint8_t      *used;           /**< Bitmap tracking values sampled without replacement. */
    size_t        used_len_bytes; /**< Length of @p used in bytes. */
} sample_stream_t;

/**
 * @brief Returns the bitmap size required for sampling without replacement.
 *
 * The returned size is sufficient to track every value in the half-open range
 * [@p low, @p high).
 *
 * @param[in] low  Inclusive lower bound.
 * @param[in] high Exclusive upper bound.
 *
 * @return The required bitmap size in bytes.
 * @return @c 0 if the specified range is empty or invalid.
 */
size_t sample_used_len_bytes(size_t low, size_t high);

/**
 * @brief Initializes a sampling stream.
 *
 * The initialised stream produces @p samples_n values from the half-open range
 * [@p low, @p high). When @p seed is @c NULL, the implementation may generate
 * an initial seed internally.
 *
 * For #SAMPLE_MODE_WITHOUT_REPLACEMENT, @p used must reference a bitmap
 * containing at least sample_used_len_bytes() bytes. For
 * #SAMPLE_MODE_WITH_REPLACEMENT, @p used may be @c NULL and
 * @p used_len_bytes may be zero.
 *
 * @param[out] stream         Sampling stream to initialize.
 * @param[in]  prng           Pseudo-random number generator algorithm.
 * @param[in]  mode           Sampling mode.
 * @param[in]  samples_n      Number of samples to produce.
 * @param[in]  low            Inclusive lower bound.
 * @param[in]  high           Exclusive upper bound.
 * @param[in]  seed           Optional initial seed, or @c NULL to generate one
 *                            internally.
 * @param[in,out] used        Optional bitmap used for sampling without
 *                            replacement.
 * @param[in]  used_len_bytes Length of @p used in bytes.
 *
 * @return #RNG_OK if the stream is initialised successfully.
 * @return An RNG error code otherwise.
 */
rng_status_t sample_stream_init(sample_stream_t *stream, prng_t prng, sample_mode_t mode,
                                size_t samples_n, size_t low, size_t high, const rng_seed_t *seed,
                                uint8_t *used, size_t used_len_bytes);

/**
 * @brief Produces the next value from a sampling stream.
 *
 * @param[in,out] stream initialised sampling stream to advance.
 * @param[out]    out    Output receiving the sampled value.
 *
 * @return #RNG_OK if a value is produced successfully.
 * @return An RNG error code otherwise.
 */
rng_status_t sample_stream_next(sample_stream_t *stream, size_t *out);

/**
 * @brief Samples integer values from a half-open range.
 *
 * The function samples @p samples_n values from the range [@p low, @p high)
 * and stores them in @p values. Depending on @p mode, sampling is performed
 * either with or without replacement.
 *
 * For #SAMPLE_MODE_WITHOUT_REPLACEMENT, @p used must reference a bitmap
 * containing at least sample_used_len_bytes() bytes. For
 * #SAMPLE_MODE_WITH_REPLACEMENT, @p used may be @c NULL and
 * @p used_len_bytes may be zero.
 *
 * @param[in]     prng           Pseudo-random number generator algorithm.
 * @param[in]     mode           Sampling mode.
 * @param[in]     samples_n      Number of values to sample.
 * @param[in]     low            Inclusive lower bound.
 * @param[in]     high           Exclusive upper bound.
 * @param[out]    values         Output array receiving the sampled values.
 * @param[in]     seed           Optional initial seed, or @c NULL to generate
 *                               one internally.
 * @param[in,out] used           Optional bitmap used for sampling without
 *                               replacement.
 * @param[in]     used_len_bytes Length of @p used in bytes.
 *
 * @return #RNG_OK if the values are sampled successfully.
 * @return An RNG error code otherwise.
 */
rng_status_t sample_values(prng_t prng, sample_mode_t mode, size_t samples_n, size_t low,
                           size_t high, size_t *values, const rng_seed_t *seed, uint8_t *used,
                           size_t used_len_bytes);

/**
 * @brief Flips pseudo-randomly selected bits in a byte array.
 *
 * The function performs @p bit_flips_n bit-flip operations on @p data. Bit
 * positions are sampled from the range covered by the first @p len_bytes
 * bytes. Depending on @p mode, the same bit position may be selected more than
 * once.
 *
 * @param[in]     prng        Pseudo-random number generator algorithm.
 * @param[in]     mode        Sampling mode.
 * @param[in,out] data        Byte array whose bits are modified.
 * @param[in]     len_bytes   Length of @p data in bytes.
 * @param[in]     bit_flips_n Number of bit-flip operations to perform.
 * @param[in]     seed        Optional initial seed, or @c NULL to generate one
 *                            internally.
 *
 * @return #RNG_OK if the bits are flipped successfully.
 * @return An RNG error code otherwise.
 */
rng_status_t sample_flip_bits(prng_t prng, sample_mode_t mode, uint8_t *data, size_t len_bytes,
                              size_t bit_flips_n, const rng_seed_t *seed);

#ifdef __cplusplus
}
#endif

#endif /* SAMPLE_H */
