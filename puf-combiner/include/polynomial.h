#ifndef POLYNOMIAL_H
#define POLYNOMIAL_H

#include "common.h"

/**
 * @file polynomial.h
 * @brief Polynomial operations over a finite field.
 *
 * This header provides functions for polynomial operations over
 * a finite field.
 */

/**
 * @brief Evaluate a polynomial at a given x-coordinate.
 *
 * Computes `polynomial(x)` modulo `mod`.
 *
 * @param polynomial The polynomial to evaluate.
 * @param mod Modulus.
 * @param x The x-coordinate.
 * @return The value of the polynomial at `x` modulo `mod`.
 */
unsigned long long polynomial_eval(const struct polynomial_t polynomial,
                                   const unsigned long long mod, const unsigned long long x);

/**
 * @brief Evaluates a point using Lagrange method.
 *
 * Computes the value of a point on the polynomial defined by the
 * input points using the Lagrange method without explicitly constructing
 * the polynomial itself.
 *
 * @param[in] points The set of points defining a polynomial.
 * @param[in] degree The degree of the polynomial.
 * @param[in] mod Modulus.
 * @param[in] x The x-coordinate.
 * @param[out] result The value of the polynomial at `x` modulo `mod`.
 * @return 0 on success, negative value on failure.
 */
int polynomial_lagrange_eval(const struct point_t *points, unsigned int degree,
                             unsigned long long mod, unsigned long long x,
                             unsigned long long *result);

/**
 * @brief Divide two polynomials modulo `mod`.
 *
 * Computes `quotient = numerator / denominator` in the finite field defined by `mod`.
 *
 * @param[in] numerator Numerator polynomial.
 * @param[in] denominator Denominator polynomial.
 * @param[in] mod Modulus.
 * @param[out] quotient Quotient polynomial.
 * @return 0 on success, negative value on failure (e.g., if division is not possible).
 */
int polynomial_mod_div(const struct polynomial_t numerator, const struct polynomial_t denominator,
                       const unsigned long long mod, struct polynomial_t *quotient);

/**
 * @brief Construct the Lagrange interpolating polynomial.
 *
 * Constructs the polynomial resulting from the interpolation of the input points.
 *
 * @param[in] points The set of points to interpolate.
 * @param[in] mod Modulus.
 * @param[out] result The resulting polynomial.
 * @return 0 on success, negative value on failure (e.g., if mod is zero).
 */
int polynomial_lagrange_interpolation(const struct point_t *points, unsigned long long mod,
                                      struct polynomial_t result);

#endif /* POLYNOMIAL_H */
