/**
 * @file stl.h
 * @brief Provides the Sample-then-Lock fuzzy extractor implementation.
 *
 * This header defines the public initialization parameters and helper data used
 * by the Sample-then-Lock fuzzy extractor implementation.
 *
 * The implementation is exposed through the generic fuzzy_extractor_t
 * interface. Instances are initialised using fuzzy_extractor_stl_init() and
 * subsequently managed through the generic fuzzy extractor operations.
 */

#ifndef FUZZY_EXTRACTOR_STL_H
#define FUZZY_EXTRACTOR_STL_H

#include "crypto/hash.h"
#include "crypto/rng.h"
#include "fuzzy_extractor/fuzzy_extractor.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Stores the initialization parameters of an STL fuzzy extractor.
 *
 * The common parameters structure must remain the first member to preserve
 * compatibility with the generic fuzzy extractor initialization interface.
 */
typedef struct {
    fuzzy_extractor_params_t common;       /**< Common fuzzy extractor parameters. */

    size_t digital_locker_nonce_len_bytes; /**< Length of each digital locker nonce in bytes. */
    size_t digital_locker_tag_len_bytes;   /**< Length of each digital locker tag in bytes. */
    size_t digital_locker_key_len_bytes;   /**< Length of each digital locker key in bytes. */
    size_t locks_n;                        /**< Number of digital lockers. */
    size_t key_len_bytes;                  /**< Length of the extracted key in bytes. */
    const hash_alg_t *hash_alg;            /**< Hash algorithm used by the implementation. */
} fuzzy_extractor_stl_params_t;

/**
 * @brief Stores the helper data produced by an STL fuzzy extractor.
 *
 * The helper data contains the pseudo-random number generator seeds and
 * serialized digital lockers required to reproduce the extracted key from a
 * sufficiently similar noisy input.
 */
typedef struct {
    rng_seed_t *seeds;   /**< Array of PRNG seeds associated with the digital lockers. */
    uint8_t    *lockers; /**< Buffer containing the serialized digital lockers. */
} fuzzy_extractor_stl_helper_data_t;

/**
 * @brief Initializes an STL fuzzy extractor instance.
 *
 * The initialised instance must be released using fuzzy_extractor_destroy().
 *
 * @param[out] fe     Fuzzy extractor instance to initialize.
 * @param[in]  params STL fuzzy extractor initialization parameters.
 *
 * @return #FUZZY_EXTRACTOR_OK if initialization succeeds.
 * @return A fuzzy extractor error code otherwise.
 */
fuzzy_extractor_status_t fuzzy_extractor_stl_init(fuzzy_extractor_t                  *fe,
                                                  const fuzzy_extractor_stl_params_t *params);

#ifdef __cplusplus
}
#endif

#endif /* FUZZY_EXTRACTOR_STL_H */
