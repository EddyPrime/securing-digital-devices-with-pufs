/**
 * @file xlock-2026.h
 * @brief Revised X-Lock fuzzy extractor implementation (2026).
 *
 * This header defines the public initialization parameters and helper data
 * structures used by the X-Lock fuzzy extractor implementation.
 *
 * The implementation is exposed through the generic fuzzy_extractor_t
 * interface. Instances are initialised using fuzzy_extractor_xlock_2026_init() and
 * subsequently managed through the generic fuzzy extractor operations.
 *
 * @par Multi-key generation
 * An X-Lock vault encodes the error-correction structure associated with a
 * noisy input and may be reused across multiple fuzzy_extractor_generate()
 * operations performed on the same helper data object.
 *
 * During the first generation operation, the vault is constructed from the
 * supplied noisy input. During subsequent operations, the existing vault is
 * used to reconstruct the internal pool from the supplied noisy input, while a
 * new nonce and pre-key seed are generated to derive an independent output key.
 *
 * This mechanism allows multiple independent keys to be derived from a single
 * vault without rebuilding it, provided that every noisy input supplied to
 * fuzzy_extractor_generate() remains within the error-correction capacity of
 * the construction.
 */

#ifndef FUZZY_EXTRACTOR_XLOCK_2026_H
#define FUZZY_EXTRACTOR_XLOCK_2026_H

#include "crypto/hmac.h"
#include "crypto/rng.h"
#include "fuzzy_extractor/fuzzy_extractor.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Stores the initialization parameters of an X-Lock fuzzy extractor.
 *
 * The common parameters structure must remain the first member to preserve
 * compatibility with the generic fuzzy extractor initialization interface.
 */
typedef struct {
    fuzzy_extractor_params_t common;            /**< Common fuzzy extractor parameters. */

    size_t                   pool_len_bytes;    /**< Length of the internal pool in bytes. */
    size_t                   key_pre_len_bytes; /**< Length of the pre-key in bytes. */
    size_t                   key_len_bytes;     /**< Length of the extracted key in bytes. */
    size_t                   xor_n;   /**< Number of XOR operations performed per lock bit. */
    size_t                   locks_n; /**< Number of locks. */
    size_t                   nonce_len_bytes; /**< Length of the nonce in bytes. */
    const hmac_alg_t        *hmac_alg;        /**< HMAC algorithm used by the implementation. */
} fuzzy_extractor_xlock_2026_params_t;

/**
 * @brief Stores the vault data used by an X-Lock fuzzy extractor.
 *
 * The vault contains the pseudo-random number generator seed and serialized
 * lock bits required to reconstruct the pre-key during key reproduction.
 */
typedef struct {
    rng_seed_t vault_seed; /**< PRNG seed used to derive the vault structure. */
    bool       is_set;     /**< Indicates whether the vault has been initialised. */
    uint8_t   *lock_bits;  /**< Buffer containing the serialized lock bits. */
} fuzzy_extractor_xlock_2026_vault_t;

/**
 * @brief Stores the helper data produced by an X-Lock fuzzy extractor.
 *
 * The helper data contains the vault, nonce, pre-key seed, and authentication
 * token required to reproduce and verify the extracted key.
 */
typedef struct {
    fuzzy_extractor_xlock_2026_vault_t *vault;        /**< X-Lock vault. */
    uint8_t                            *nonce;        /**< Nonce used during key derivation. */
    rng_seed_t                          key_pre_seed; /**< PRNG seed used to derive the pre-key. */
    uint8_t                            *token;        /**< Authentication token. */
} fuzzy_extractor_xlock_2026_helper_data_t;

/**
 * @brief Initializes an X-Lock fuzzy extractor instance.
 *
 * The initialised instance must be released using fuzzy_extractor_destroy().
 *
 * @param[out] fe     Fuzzy extractor instance to initialize.
 * @param[in]  params X-Lock fuzzy extractor initialization parameters.
 *
 * @return #FUZZY_EXTRACTOR_OK if initialization succeeds.
 * @return A fuzzy extractor error code otherwise.
 */
fuzzy_extractor_status_t
fuzzy_extractor_xlock_2026_init(fuzzy_extractor_t                         *fe,
                                const fuzzy_extractor_xlock_2026_params_t *params);

#ifdef __cplusplus
}
#endif

#endif /* FUZZY_EXTRACTOR_XLOCK_2026_H */
