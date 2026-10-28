#ifndef MOD_H
#define MOD_H

/**
 * @file mod.h
 * @brief Modular arithmetic operations.
 *
 * This header provides functions for modular arithmetic operations.
 */

/**
 * @brief Normalize a number modulo `mod`.
 *
 * @param a Non-negative integer.
 * @param mod Modulus.
 * @return `a` normalized to `[0, mod-1]`, i.e., `a % mod`.
 */
unsigned long long mod_norm(const unsigned long long a, const unsigned long long mod);

/**
 * @brief Modular addition.
 *
 * @param a Non-negative integer.
 * @param b Non-negative integer.
 * @param mod Modulus.
 * @return `(a + b) % mod`.
 */
unsigned long long mod_add(unsigned long long a, unsigned long long b,
                           const unsigned long long mod);

/**
 * @brief Modular subtraction.
 *
 * @param a Non-negative integer.
 * @param b Non-negative integer.
 * @param mod Modulus.
 * @return `(a - b) % mod`.
 */
unsigned long long mod_sub(const unsigned long long a, const unsigned long long b,
                           const unsigned long long mod);

/**
 * @brief Modular multiplication.
 *
 * @param a Non-negative integer.
 * @param b Non-negative integer.
 * @param mod Modulus.
 * @return `(a * b) % mod`.
 */
unsigned long long mod_mul(const unsigned long long a, const unsigned long long b,
                           const unsigned long long mod);

/**
 * @brief Modular exponentiation.
 *
 * Computes `(base ^ exp) % mod`.
 *
 * @param base Non-negative integer base.
 * @param exp Non-negative integer exponent.
 * @param mod Modulus.
 * @return `(base ^ exp) % mod`.
 */
unsigned long long mod_pow(unsigned long long base, unsigned long long exp,
                           const unsigned long long mod);

/**
 * @brief Modular inverse.
 *
 * Computes the modular inverse of `a` modulo `mod`, if any.
 *
 * @param[in] a Non-negative integer.
 * @param[in] mod Modulus.
 * @param[out] inv The modular inverse.
 * @return 0 on success, negative on failure (e.g., if inverse does not exist).
 */
int mod_inv(const unsigned long long a, const unsigned long long mod, unsigned long long *inv);

#endif /* MOD_H */
