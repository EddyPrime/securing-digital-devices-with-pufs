/**
 * @file random.c
 * @brief Implementation of random number generation and sampling utilities.
 */

#include "crypto/random.h"

#include "common/bits.h"

#include <limits.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define RANDOM_SEED_MAX_ATTEMPTS 8

rng_status_t random_bytes(uint8_t *out, size_t out_len_bytes) {
    if (out == NULL && out_len_bytes != 0u) {
        return RNG_ERR_INVALID_ARG;
    }

    while (out_len_bytes > 0u) {
        const int chunk_len = out_len_bytes > (size_t)INT_MAX ? INT_MAX : (int)out_len_bytes;

        if (RAND_bytes(out, chunk_len) != 1) {
            return RNG_ERR_BACKEND_FAIL;
        }

        out += chunk_len;
        out_len_bytes -= (size_t)chunk_len;
    }

    return RNG_OK;
}

rng_status_t random_seed_u32(rng_seed_t *seed) {
    if (seed == NULL) {
        return RNG_ERR_INVALID_ARG;
    }

    for (int attempts = 0; attempts < RANDOM_SEED_MAX_ATTEMPTS; attempts++) {
        rng_status_t status = random_bytes((uint8_t *)seed, sizeof(*seed));
        if (status != RNG_OK) {
            return status;
        }

        if (*seed != 0u) {
            return RNG_OK;
        }
    }

    return RNG_ERR_BACKEND_FAIL;
}
