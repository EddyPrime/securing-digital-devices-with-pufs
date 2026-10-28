#ifndef COMMON_H
#define COMMON_H

#include "constants.h"

/**
 * @file common.h
 * @brief Data structures for points and polynomials.
 */

/**
 * @struct point_t
 * @brief Representation of a two-dimensional point.
 *
 * This struct represents a two-dimensional point with its x and y non-negative coordinates.
 */
struct point_t {
    unsigned long long x; /** x-coordinate. May be a challenge. */
    unsigned long long y; /** y-coordinate. May be a response. */
};

/**
 * @struct polynomial_t
 * @brief Representation of a polynomial.
 *
 * This struct represents a polynomial with its degree and coefficients.
 */
struct polynomial_t {
    unsigned int degree; /** Degree of the polynomial. */

    /**
     * @brief List of coefficients of the polynomial.
     *
     * The number of coefficients is (degree + 1).
     * The index corresponds to the subscript:
     * coeffs[0] = a_0,
     * coeffs[1] = a_1,
     * ...
     * coeffs[degree] = a_{degree}.
     */
    unsigned long long *coeffs;
};

#endif /* COMMON_H */
