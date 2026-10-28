/**
 * @file bits.c
 * @brief Bit-level utility functions for byte arrays.
 */

#include "common/bits.h"

#include <limits.h>

int bits_hamming_distance(const uint8_t *a, const uint8_t *b, size_t len_bytes) {
    if (a == NULL || b == NULL) {
        return -1;
    }

    if (len_bytes > (size_t)(INT_MAX / 8)) {
        return -1;
    }

    int distance = 0;

    for (size_t i = 0u; i < len_bytes; i++) {
        const uint8_t diff = (uint8_t)(a[i] ^ b[i]);

#if defined(__GNUC__) || defined(__clang__)
        distance += __builtin_popcount((unsigned int)diff);
#else
        uint8_t x = diff;

        x         = (uint8_t)(x - ((x >> 1u) & 0x55u));
        x         = (uint8_t)((x & 0x33u) + ((x >> 2u) & 0x33u));

        distance += (int)((x + (x >> 4u)) & 0x0Fu);
#endif
    }

    return distance;
}
