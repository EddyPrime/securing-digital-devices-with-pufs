/**
 * @file bits.h
 * @brief Provides bit-level operations on byte arrays.
 *
 * This header defines utility functions for reading, writing, and comparing
 * bits stored in byte arrays.
 *
 * Bits are indexed from the least significant bit of the first byte. Thus,
 * bit index 0 identifies the least significant bit of @c bytes[0], while bit
 * index 8 identifies the least significant bit of @c bytes[1].
 *
 * @note The bit access functions do not perform bounds checking. The caller
 *       must provide valid pointers and ensure that each byte array is large
 *       enough to contain the requested bit index.
 */

#ifndef BITS_H
#define BITS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Retrieves a bit from a byte array.
 *
 * @param[in] bytes     Byte array containing the bit.
 * @param[in] bit_index Zero-based index of the bit to retrieve.
 *
 * @return @c 1 if the specified bit is set.
 * @return @c 0 if the specified bit is cleared.
 *
 * @pre @p bytes must point to an array containing the byte associated with
 *      @p bit_index.
 */
static inline uint8_t bits_get(const uint8_t *bytes, size_t bit_index) {
    return (uint8_t)(((uint32_t)bytes[bit_index >> 3u] >> (bit_index & 7u)) & UINT32_C(1));
}

/**
 * @brief Assigns a value to a bit in a byte array.
 *
 * Only the least significant bit of @p value is considered. The specified bit
 * is set when this value is @c 1 and cleared when it is @c 0.
 *
 * @param[in,out] bytes     Byte array containing the bit to modify.
 * @param[in]     bit_index Zero-based index of the bit to modify.
 * @param[in]     value     Value to assign to the bit.
 *
 * @pre @p bytes must point to an array containing the byte associated with
 *      @p bit_index.
 */
static inline void bits_set(uint8_t *bytes, size_t bit_index, uint8_t value) {
    const uint8_t mask = (uint8_t)(1u << (bit_index & 7u));
    uint8_t      *byte = &bytes[bit_index >> 3u];

    if ((value & 1u) != 0u) {
        *byte = (uint8_t)(*byte | mask);
    } else {
        *byte = (uint8_t)(*byte & (uint8_t)~mask);
    }
}

/**
 * @brief Converts a number of bytes to the corresponding number of bits.
 *
 * @param[in] byte_count Number of bytes to convert.
 *
 * @return Number of bits contained in @p byte_count bytes.
 */
static inline size_t bits_from_bytes(size_t byte_count) { return byte_count * 8u; }

/**
 * @brief Computes the Hamming distance between two byte arrays.
 *
 * The Hamming distance is the number of bit positions whose values differ
 * between the first @p len_bytes bytes of @p a and @p b.
 *
 * @param[in] a         First byte array.
 * @param[in] b         Second byte array.
 * @param[in] len_bytes Number of bytes to compare.
 *
 * @return The Hamming distance between the byte arrays on success.
 * @return @c -1 if an argument is invalid.
 */
int bits_hamming_distance(const uint8_t *a, const uint8_t *b, size_t len_bytes);

#ifdef __cplusplus
}
#endif

#endif /* BITS_H */
