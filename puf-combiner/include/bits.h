#ifndef BITS_H
#define BITS_H

/**
 * @file bits.h
 * @brief Defines bit-wise manipulation macros.
 */

/**
 * @def set_bit
 * @brief Sets the bit at the given position.
 *
 * This macro sets the bit at position `bit` in the number `n`.
 *
 * @param n The number in which to set the bit.
 * @param bit The bit position to set.
 * @return The new number with the bit set.
 */
#define set_bit(n, bit) ((n) | (1u << (bit)))

#endif /* BITS_H */
