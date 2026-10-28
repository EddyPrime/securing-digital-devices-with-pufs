/**
 * @file prng.c
 * @brief Implementation of random number generation and sampling utilities.
 */

#include "crypto/prng.h"

#include "common/bits.h"
#include "prng_internal.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define SPLITMIX32_GOLDEN_RATIO 0x9E3779B9u
#define SPLITMIX32_MIX_1        0x85EBCA6Bu
#define SPLITMIX32_MIX_2        0xC2B2AE35u

#define PRNG_LFSR32_FEEDBACK    0x80200003u

static void prng_normalize_state(rng_seed_t *state) {
    if (state == NULL) {
        return;
    }

    if (*state == 0u) {
        *state = PRNG_NONZERO_SEED_FALLBACK;
    }
}

static uint32_t splitmix32(uint32_t x) {
    x += SPLITMIX32_GOLDEN_RATIO;
    x = (uint32_t)((x ^ (x >> 16u)) * SPLITMIX32_MIX_1);
    x = (uint32_t)((x ^ (x >> 13u)) * SPLITMIX32_MIX_2);

    return x ^ (x >> 16u);
}

static uint32_t prng_next_u32_lfsr32(rng_seed_t *state) {
    if (state == NULL) {
        return 0u;
    }

    prng_normalize_state(state);

    uint32_t       x   = *state;
    const uint32_t lsb = x & 1u;

    x >>= 1u;

    if (lsb != 0u) {
        x ^= PRNG_LFSR32_FEEDBACK;
    }

    if (x == 0u) {
        x = splitmix32(*state);
    }

    if (x == 0u) {
        x = PRNG_NONZERO_SEED_FALLBACK;
    }

    *state = x;

    return x;
}

static uint32_t prng_next_u32_xorshift32(rng_seed_t *state) {
    if (state == NULL) {
        return 0u;
    }

    prng_normalize_state(state);

    uint32_t x = *state;

    x ^= x << 13u;
    x ^= x >> 17u;
    x ^= x << 5u;

    if (x == 0u) {
        x = splitmix32(*state);
    }

    if (x == 0u) {
        x = PRNG_NONZERO_SEED_FALLBACK;
    }

    *state = x;

    return x;
}

static uint32_t prng_next_u32_constant(rng_seed_t *state) {
    if (state == NULL) {
        return 0u;
    }

    *state = 1u;

    return *state;
}

static uint32_t prng_next_u32_markov(rng_seed_t *state) {
    if (state == NULL) {
        return 0u;
    }

    prng_normalize_state(state);

    const uint32_t base_step    = 32u;
    const uint32_t jump_size    = 256u;
    const uint32_t jitter_size  = 16u;

    uint32_t       random_value = prng_next_u32_xorshift32(state);

    if ((random_value & 0x07u) == 0u) {
        *state = prng_next_u32_xorshift32(state);
        return *state;
    }

    const int32_t  jump_direction   = (random_value & 1u) != 0u ? 1 : -1;

    const int32_t  jitter_direction = (random_value & 2u) != 0u ? 1 : -1;

    const uint32_t jump             = 1u + ((random_value >> 2u) & (jump_size - 1u));

    const uint32_t jitter           = (random_value >> 16u) % (jitter_size + 1u);

    const int32_t  delta =
        jump_direction * (int32_t)(jump * base_step) + jitter_direction * (int32_t)jitter;

    *state = (uint32_t)((int32_t)*state + delta);

    return *state;
}

static uint32_t prng_next_u32_bucket(rng_seed_t *state) {
    if (state == NULL) {
        return 0u;
    }

    prng_normalize_state(state);

    const uint32_t jump_size    = 64u;

    uint32_t       random_value = prng_next_u32_xorshift32(state);

    if ((random_value & 0x07u) == 0u) {
        *state = prng_next_u32_xorshift32(state);
        return *state;
    }

    const int32_t  current_bucket  = (int32_t)(*state >> 5u);
    const int32_t  jump_direction  = (random_value & 1u) != 0u ? 1 : -1;

    const uint32_t bucket_jump     = 1u + ((random_value >> 2u) & (jump_size - 1u));

    const int32_t  next_bucket     = current_bucket + jump_direction * (int32_t)bucket_jump;

    const uint32_t internal_jitter = (random_value >> 16u) & 31u;

    *state                         = ((uint32_t)next_bucket << 5u) | internal_jitter;

    return *state;
}

uint32_t prng_next_u32(prng_t prng, rng_seed_t *state) {
    switch (prng) {
    case PRNG_XORSHIFT32: return prng_next_u32_xorshift32(state);

    case PRNG_LFSR32:     return prng_next_u32_lfsr32(state);

    case PRNG_CONSTANT:   return prng_next_u32_constant(state);

    case PRNG_MARKOV:     return prng_next_u32_markov(state);

    case PRNG_BUCKET:     return prng_next_u32_bucket(state);

    default:              return 0u;
    }
}

size_t prng_uniform_range_unchecked(prng_t prng, rng_seed_t *state, size_t low, size_t high) {
    const uint32_t bound = (uint32_t)(high - low);
    const uint32_t limit = UINT32_MAX - (UINT32_MAX % bound);

    uint32_t       value = 0u;

    do {
        value = prng_next_u32(prng, state);
    } while (value >= limit);

    return low + (size_t)(value % bound);
}

rng_status_t prng_uniform_range(prng_t prng, rng_seed_t *state, size_t low, size_t high,
                                size_t *out) {
    if (state == NULL || out == NULL) {
        return RNG_ERR_INVALID_ARG;
    }

    if (high <= low) {
        return RNG_ERR_RANGE;
    }

    if (high - low > UINT32_MAX) {
        return RNG_ERR_RANGE;
    }

    if (prng < 0 || prng > PRNG_COUNT) {
        return RNG_ERR_INVALID_ARG;
    }

    *out = prng_uniform_range_unchecked(prng, state, low, high);

    return RNG_OK;
}
