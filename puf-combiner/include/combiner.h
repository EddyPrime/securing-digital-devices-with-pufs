#ifndef COMBINER_H
#define COMBINER_H

#include "common.h"

#include <stdlib.h>

/**
 * @file combiner.h
 * @brief Declaration of enrollment and reconstruct procedures for error
 * correction using various strategies.
 *
 * This header defines functions for enrolling a secret key and reconstructing it,
 * using the Berlekamp-Welch, the enumeration, or the hashing strategy.
 */

/**
 * @brief Enroll a secret key using the Berlekamp-Welch algorithm.
 *
 * @param[in] n Number of points.
 * @param[in] m Number of additional points.
 * @param[in] mod Modulus of the finite field.
 * @param[in] points Array of `(n + m)` input points.
 * @param[out] sk Pointer to secret key.
 * @param[out] sk_hash Pointer to the secret key hash.
 * @return 0 on success, negative on failure.
 */
int enroll_berlekamp_welch(const size_t n, const size_t m, const unsigned long long mod,
                           struct point_t *points, unsigned long long *sk, unsigned char *sk_hash);

/**
 * @brief Reconstruct a secret key using the Berlekamp-Welch algorithm.
 *
 * @param[in] n Number of points.
 * @param[in] m Number of additional points.
 * @param[in] mod Modulus of the finite field.
 * @param[in] points Array of `(n + m)` input points.
 * @param[out] sk Pointer to secret key.
 * @param[in] sk_hash Pointer to the secret key hash.
 * @param[out] faulty_points Mask identifying faulty points.
 * @return 0 on success, negative on failure.
 */
int reconstruct_berlekamp_welch(const size_t n, const size_t m, const unsigned long long mod,
                                struct point_t *points, unsigned long long *sk,
                                unsigned char *sk_hash, unsigned int *faulty_points);

/**
 * @brief Enroll a secret key using the enumeration strategy.
 *
 * @param[in] n Number of points.
 * @param[in] m Number of additional points.
 * @param[in] mod Modulus of the finite field.
 * @param[in] points Array of `(n + m)` input points.
 * @param[out] sk Pointer to secret key.
 * @param[out] sk_hash Pointer to the secret key hash.
 * @return 0 on success, negative on failure.
 */
int enroll_enumeration(const size_t n, const size_t m, const unsigned long long mod,
                       struct point_t *points, unsigned long long *sk, unsigned char *sk_hash);

/**
 * @brief Reconstruct a secret key using the enumeration strategy.
 *
 * @param[in] n Number of points.
 * @param[in] m Number of additional points.
 * @param[in] mod Modulus of the finite field.
 * @param[in] points Array of `(n + m)` input points.
 * @param[out] sk Pointer to secret key.
 * @param[in] sk_hash Pointer to the secret key hash.
 * @param[out] faulty_points Mask identifying faulty points.
 * @return 0 on success, negative on failure.
 */
int reconstruct_enumeration(const size_t n, const size_t m, const unsigned long long mod,
                            struct point_t *points, unsigned long long *sk, unsigned char *sk_hash,
                            unsigned int *faulty_points);

/**
 * @brief Enroll a secret key with point hashes.
 *
 * @param[in] n Number of points.
 * @param[in] m Number of additional points.
 * @param[in] mod Modulus of the finite field.
 * @param[in] points Array of `(n + m)` input points.
 * @param[out] sk Pointer to secret key.
 * @param[out] sk_hash Pointer to the secret key hash.
 * @param[out] hashes Array of y-coordinates hashes.
 * @return 0 on success, negative on failure.
 */
int enroll_hashing(const size_t n, const size_t m, const unsigned long long mod,
                   struct point_t *points, unsigned long long *sk, unsigned char *sk_hash,
                   unsigned char *hashes);

/**
 * @brief Reconstruct a secret key with point hashes.
 *
 * @param[in] n Number of points.
 * @param[in] m Number of additional points.
 * @param[in] mod Modulus of the finite field.
 * @param[in] points Array of `(n + m)` input points.
 * @param[out] sk Pointer to secret key.
 * @param[in] sk_hash Pointer to the secret key hash.
 * @param[out] faulty_points Mask identifying faulty points.
 * @param[in] hashes Array of y-coordinates hashes.
 * @return 0 on success, negative on failure.
 */
int reconstruct_hashing(const size_t n, const size_t m, const unsigned long long mod,
                        struct point_t *points, unsigned long long *sk, unsigned char *sk_hash,
                        unsigned int *faulty_points, unsigned char *hashes);

#endif /* COMBINER_H */
