/**
 * @file fuzzy_extractor_internal.h
 * @brief Provides internal fuzzy extractor utilities.
 *
 * This header defines internal helper functions shared by fuzzy extractor
 * implementations, including conversions from subsystem-specific status codes
 * to the corresponding fuzzy extractor status codes.
 *
 * @warning This header is intended for internal use only.
 */

#ifndef FUZZY_EXTRACTOR_INTERNAL_H
#define FUZZY_EXTRACTOR_INTERNAL_H

#include "crypto/digital_locker.h"
#include "crypto/hmac.h"
#include "crypto/prng.h"
#include "fuzzy_extractor/fuzzy_extractor.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Converts an RNG status code to a fuzzy extractor status code.
 *
 * @param[in] status RNG status code to convert.
 *
 * @return The corresponding fuzzy extractor status code.
 */
static inline fuzzy_extractor_status_t fuzzy_extractor_status_from_rng(rng_status_t status) {
    switch (status) {
    case RNG_OK:                  return FUZZY_EXTRACTOR_OK;

    case RNG_ERR_BACKEND_FAIL:    return FUZZY_EXTRACTOR_ERR_RNG_FAILED;

    case RNG_ERR_OOM:             return FUZZY_EXTRACTOR_ERR_OOM;

    case RNG_ERR_INVALID_ARG:
    case RNG_ERR_RANGE:
    case RNG_ERR_RANGE_TOO_SMALL:
    case RNG_ERR_UNSUPPORTED:
    default:                      return FUZZY_EXTRACTOR_ERR_INVALID_ARG;
    }
}

/**
 * @brief Converts an HMAC status code to a fuzzy extractor status code.
 *
 * @param[in] status HMAC status code to convert.
 *
 * @return The corresponding fuzzy extractor status code.
 */
static inline fuzzy_extractor_status_t fuzzy_extractor_status_from_hmac(hmac_status_t status) {
    switch (status) {
    case HMAC_OK:                return FUZZY_EXTRACTOR_OK;

    case HMAC_ERR_NULL_ARG:      return FUZZY_EXTRACTOR_ERR_NULL_ARG;

    case HMAC_ERR_OUT_TOO_SMALL: return FUZZY_EXTRACTOR_ERR_BUFFER_TOO_SMALL;

    case HMAC_ERR_BACKEND_FAIL:  return FUZZY_EXTRACTOR_ERR_CRYPTO_BACKEND;

    case HMAC_ERR_KEY_TOO_LARGE:
    default:                     return FUZZY_EXTRACTOR_ERR_INVALID_ARG;
    }
}

/**
 * @brief Converts a digital locker status code to a fuzzy extractor status
 *        code.
 *
 * @param[in] status Digital locker status code to convert.
 *
 * @return The corresponding fuzzy extractor status code.
 */
static inline fuzzy_extractor_status_t
fuzzy_extractor_status_from_digital_locker(digital_locker_status_t status) {
    switch (status) {
    case DIGITAL_LOCKER_OK:                  return FUZZY_EXTRACTOR_OK;

    case DIGITAL_LOCKER_ERR_NULL_ARG:        return FUZZY_EXTRACTOR_ERR_NULL_ARG;

    case DIGITAL_LOCKER_ERR_INVALID_ARG:     return FUZZY_EXTRACTOR_ERR_INVALID_ARG;

    case DIGITAL_LOCKER_ERR_BACKEND_FAIL:    return FUZZY_EXTRACTOR_ERR_CRYPTO_BACKEND;

    case DIGITAL_LOCKER_ERR_INVALID_PADDING: return FUZZY_EXTRACTOR_ERR_REPRODUCE_FAILED;

    case DIGITAL_LOCKER_ERR_OOM:             return FUZZY_EXTRACTOR_ERR_OOM;

    default:                                 return FUZZY_EXTRACTOR_ERR_INVALID_ARG;
    }
}

#ifdef __cplusplus
}
#endif

#endif /* FUZZY_EXTRACTOR_INTERNAL_H */
