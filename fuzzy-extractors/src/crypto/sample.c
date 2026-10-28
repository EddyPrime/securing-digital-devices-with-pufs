/**
 * @file sample.c
 * @brief Implementation of pseudo-random sampling utilities.
 */

#include "crypto/sample.h"

#include "common/bits.h"
#include "crypto/random.h"
#include "prng_internal.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

size_t sample_used_len_bytes(size_t low, size_t high) {
    return high > low ? ((high - low + 7u) / 8u) : 0u;
}

rng_status_t sample_stream_init(sample_stream_t *stream, prng_t prng, sample_mode_t mode,
                                size_t samples_n, size_t low, size_t high, const rng_seed_t *seed,
                                uint8_t *used, size_t used_len_bytes) {
    if (stream == NULL) {
        return RNG_ERR_INVALID_ARG;
    }

    if (high <= low) {
        return RNG_ERR_RANGE;
    }

    const size_t range = high - low;

    if (range > UINT32_MAX) {
        return RNG_ERR_RANGE;
    }

    if (samples_n > range && mode == SAMPLE_MODE_WITHOUT_REPLACEMENT && prng != PRNG_CONSTANT) {
        return RNG_ERR_RANGE_TOO_SMALL;
    }

    rng_seed_t local_seed = 0u;

    if (seed != NULL) {
        local_seed = *seed;

        if (local_seed == 0u) {
            local_seed = PRNG_NONZERO_SEED_FALLBACK;
        }
    } else {
        rng_status_t status = random_seed_u32(&local_seed);
        if (status != RNG_OK) {
            return status;
        }
    }

    if (mode == SAMPLE_MODE_WITHOUT_REPLACEMENT && prng != PRNG_CONSTANT) {
        const size_t required_len_bytes = sample_used_len_bytes(low, high);

        if (used == NULL || used_len_bytes < required_len_bytes) {
            return RNG_ERR_INVALID_ARG;
        }

        memset(used, 0, required_len_bytes);
    }

    *stream = (sample_stream_t){
        .prng           = prng,
        .mode           = mode,
        .samples_n      = samples_n,
        .sampled        = 0u,
        .low            = low,
        .high           = high,
        .range          = range,
        .state          = local_seed,
        .used           = used,
        .used_len_bytes = used_len_bytes,
    };

    return RNG_OK;
}

static void sample_stream_next_unchecked(sample_stream_t *stream, size_t *out) {
    if (stream->mode == SAMPLE_MODE_WITH_REPLACEMENT || stream->prng == PRNG_CONSTANT) {
        *out =
            prng_uniform_range_unchecked(stream->prng, &stream->state, stream->low, stream->high);
        stream->sampled++;
        return;
    }

    size_t offset = prng_uniform_range_unchecked(stream->prng, &stream->state, 0u, stream->range);

    while (bits_get(stream->used, offset) != 0u) {
        offset = (offset + 1u) % stream->range;
    }

    bits_set(stream->used, offset, 1u);

    *out = stream->low + offset;
    stream->sampled++;
}

rng_status_t sample_stream_next(sample_stream_t *stream, size_t *out) {
    if (stream == NULL || out == NULL) {
        return RNG_ERR_INVALID_ARG;
    }

    if (stream->sampled >= stream->samples_n) {
        return RNG_ERR_RANGE;
    }

    sample_stream_next_unchecked(stream, out);

    return RNG_OK;
}

rng_status_t sample_values(prng_t prng, sample_mode_t mode, size_t samples_n, size_t low,
                           size_t high, size_t *values, const rng_seed_t *seed, uint8_t *used,
                           size_t used_len_bytes) {
    if (values == NULL && samples_n != 0u) {
        return RNG_ERR_INVALID_ARG;
    }

    if (high <= low) {
        return RNG_ERR_RANGE;
    }

    if (high - low > UINT32_MAX) {
        return RNG_ERR_RANGE;
    }

    if (samples_n == 0u) {
        return RNG_OK;
    }

    sample_stream_t stream;

    rng_status_t    status =
        sample_stream_init(&stream, prng, mode, samples_n, low, high, seed, used, used_len_bytes);

    if (status != RNG_OK) {
        return status;
    }

    for (size_t i = 0u; i < samples_n; i++) {
        sample_stream_next_unchecked(&stream, &values[i]);
    }

    return RNG_OK;
}

static rng_status_t sample_flip_bits_with_replacement(prng_t prng, uint8_t *data,
                                                      size_t data_len_bytes, size_t bit_flips_n,
                                                      rng_seed_t *local_seed) {
    const size_t data_len_bits = bits_from_bytes(data_len_bytes);

    for (size_t i = 0u; i < bit_flips_n; i++) {
        size_t       bit_index = 0u;

        rng_status_t status = prng_uniform_range(prng, local_seed, 0u, data_len_bits, &bit_index);

        if (status != RNG_OK) {
            return status;
        }

        data[bit_index >> 3u] ^= (uint8_t)(1u << (bit_index & 7u));
    }

    return RNG_OK;
}

static rng_status_t sample_flip_bits_without_replacement(prng_t prng, uint8_t *data,
                                                         size_t data_len_bytes, size_t bit_flips_n,
                                                         rng_seed_t *local_seed) {
    const size_t data_len_bits = bits_from_bytes(data_len_bytes);

    if (bit_flips_n > data_len_bits) {
        bit_flips_n = data_len_bits;
    }

    if (bit_flips_n == 0u) {
        return RNG_OK;
    }

    const size_t used_len_bytes = sample_used_len_bytes(0u, data_len_bits);

    if (used_len_bytes == 0u) {
        return RNG_ERR_RANGE;
    }

    uint8_t *used = calloc(used_len_bytes, sizeof(*used));
    if (used == NULL) {
        return RNG_ERR_OOM;
    }

    sample_stream_t stream;

    rng_status_t    status =
        sample_stream_init(&stream, prng, SAMPLE_MODE_WITHOUT_REPLACEMENT, bit_flips_n, 0u,
                           data_len_bits, local_seed, used, used_len_bytes);

    if (status != RNG_OK) {
        free(used);
        return status;
    }

    for (size_t i = 0u; i < bit_flips_n; i++) {
        size_t bit_index = 0u;

        status           = sample_stream_next(&stream, &bit_index);
        if (status != RNG_OK) {
            free(used);
            return status;
        }

        data[bit_index >> 3u] ^= (uint8_t)(1u << (bit_index & 7u));
    }

    free(used);

    return RNG_OK;
}

rng_status_t sample_flip_bits(prng_t prng, sample_mode_t mode, uint8_t *data, size_t data_len_bytes,
                              size_t bit_flips_n, const rng_seed_t *seed) {
    if (data == NULL && data_len_bytes != 0u) {
        return RNG_ERR_INVALID_ARG;
    }

    if (data_len_bytes == 0u || bit_flips_n == 0u) {
        return RNG_OK;
    }

    rng_seed_t local_seed = 0u;

    if (seed != NULL) {
        local_seed = *seed;

        if (local_seed == 0u) {
            local_seed = PRNG_NONZERO_SEED_FALLBACK;
        }
    } else {
        rng_status_t status = random_seed_u32(&local_seed);
        if (status != RNG_OK) {
            return status;
        }
    }

    if (prng_is_constant(prng) || mode == SAMPLE_MODE_WITH_REPLACEMENT) {
        return sample_flip_bits_with_replacement(prng, data, data_len_bytes, bit_flips_n,
                                                 &local_seed);
    }

    return sample_flip_bits_without_replacement(prng, data, data_len_bytes, bit_flips_n,
                                                &local_seed);
}
