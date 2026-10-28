/**
 * @file fuzzy_extractor.c
 * @brief Implementation of the generic fuzzy extractor dispatcher.
 */

#include "fuzzy_extractor/fuzzy_extractor.h"

#include "fuzzy_extractor/implementations/stl.h"
#include "fuzzy_extractor/implementations/xlock-2024.h"
#include "fuzzy_extractor/implementations/xlock-2026.h"

const char *fuzzy_extractor_status_string(fuzzy_extractor_status_t status) {
    switch (status) {
    case FUZZY_EXTRACTOR_OK:                   return "success";

    case FUZZY_EXTRACTOR_ERR_NULL_ARG:         return "null argument";

    case FUZZY_EXTRACTOR_ERR_INVALID_ARG:      return "invalid argument";

    case FUZZY_EXTRACTOR_ERR_BUFFER_TOO_SMALL: return "output buffer too small";

    case FUZZY_EXTRACTOR_ERR_OOM:              return "memory allocation failed";

    case FUZZY_EXTRACTOR_ERR_RNG_FAILED:       return "random number generation failed";

    case FUZZY_EXTRACTOR_ERR_CRYPTO_BACKEND:   return "cryptographic backend failure";

    case FUZZY_EXTRACTOR_ERR_HASH_FAILED:      return "hash operation failed";

    case FUZZY_EXTRACTOR_ERR_HMAC_FAILED:      return "HMAC operation failed";

    case FUZZY_EXTRACTOR_ERR_REPRODUCE_FAILED: return "key reproduction failed";

    default:                                   return "unknown status";
    }
}

fuzzy_extractor_status_t fuzzy_extractor_init(fuzzy_extractor_t              *fe,
                                              const fuzzy_extractor_params_t *params) {
    if (fe == NULL || params == NULL) {
        return FUZZY_EXTRACTOR_ERR_NULL_ARG;
    }

    if (params->impl < 0 || params->impl >= FUZZY_EXTRACTOR_COUNT) {
        return FUZZY_EXTRACTOR_ERR_INVALID_ARG;
    }

    switch (params->impl) {
    case FUZZY_EXTRACTOR_IMPL_STL:
        return fuzzy_extractor_stl_init(fe, (const fuzzy_extractor_stl_params_t *)params);

    case FUZZY_EXTRACTOR_IMPL_XLOCK_2024:
        return fuzzy_extractor_xlock_2024_init(fe,
                                               (const fuzzy_extractor_xlock_2024_params_t *)params);

    case FUZZY_EXTRACTOR_IMPL_XLOCK_2026:
        return fuzzy_extractor_xlock_2026_init(fe,
                                               (const fuzzy_extractor_xlock_2026_params_t *)params);

    default: return FUZZY_EXTRACTOR_ERR_INVALID_ARG;
    }
}
