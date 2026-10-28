/**
 * @file rng.c
 * @brief Common utilities for random generation and sampling.
 */

#include "crypto/rng.h"

const char *rng_status_string(rng_status_t status) {
    switch (status) {
    case RNG_OK:                  return "success";

    case RNG_ERR_INVALID_ARG:     return "invalid argument";

    case RNG_ERR_BACKEND_FAIL:    return "backend failure";

    case RNG_ERR_RANGE:           return "invalid range";

    case RNG_ERR_RANGE_TOO_SMALL: return "range too small";

    case RNG_ERR_UNSUPPORTED:     return "unsupported operation";

    case RNG_ERR_OOM:             return "memory allocation failed";

    default:                      return "unknown status";
    }
}
