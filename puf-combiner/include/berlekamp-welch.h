#ifndef BERLEKAMP_WELCH_H
#define BERLEKAMP_WELCH_H

#include "common.h"

/**
 * @file berlekamp-welch.h
 * @brief Berlekamp-Welch error correction algorithm.
 *
 * This header declares the Berlekamp-Welch algorithm for error correction
 * in polynomial-based coding schemes over a finite field.
 */

/**
 * @brief Perform the Berlekamp-Welch algorithm.
 *
 * Recovers a unique polynomial of degree at most `d` from `n` points,
 * correcting up to `t` errors if `n ≥ d + 2t + 1`.
 *
 * @param[in] n Number of input points.
 * @param[in] d Maximum degree of the output polynomial.
 * @param[in] mod Modulus of the finite field.
 * @param[in] points Array of `n` input points.
 * @param[out] polynomial Recovered polynomial.
 * @return 0 on success, negative on failure.
 */
int berlekamp_welch(unsigned int n, unsigned int d, unsigned long long mod, struct point_t *points,
                    struct polynomial_t *polynomial);

#endif /* BERLEKAMP_WELCH_H */
