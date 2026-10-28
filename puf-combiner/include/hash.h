#ifndef HASH_H
#define HASH_H

/**
 * @file hash.h
 * @brief Hashing utilities.
 *
 * This header provides hashing wrappers.
 */

/**
 * @brief Compute the hash of an unsigned long long value.
 *
 * This function computes the hash of the input value and stores it in the given output buffer.
 *
 * @param[in] value The value to be hashed.
 * @param[out] hash The buffer where the hash is stored.
 *                  Must be at least HASH_BYTES long.
 */
void hash_ull(const unsigned long long value, unsigned char *hash);

#endif /* HASH_H */
