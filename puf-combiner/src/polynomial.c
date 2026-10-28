#include "polynomial.h"

#include "common.h"
#include "mod.h"

#include <stdio.h>

void polynomial_zero(struct polynomial_t polynomial) {
    for (unsigned int i = 0; i <= polynomial.degree; i++) {
        polynomial.coeffs[i] = 0;
    }
}

/* Horner method */
unsigned long long polynomial_eval(const struct polynomial_t polynomial,
                                   const unsigned long long mod, const unsigned long long x) {
    if (polynomial.degree == 0 || x == 0) {
        return polynomial.coeffs[0];
    }

    unsigned long long y = 0;

    for (unsigned int i = polynomial.degree;; --i) {
        y = mod_mul(y, x, mod);
        y = mod_add(y, polynomial.coeffs[i], mod);

        if (i == 0) {
            break;
        }
    }

    return y;
}

int polynomial_lagrange_eval(const struct point_t *points, unsigned int degree,
                             unsigned long long mod, unsigned long long x,
                             unsigned long long *result) {

    if (mod == 0 || result == NULL || points == NULL) {
        return -1;
    }

    *result = 0;

    for (unsigned int i = 0; i <= degree; i++) {
        unsigned long long term = points[i].y;

        for (unsigned int j = 0; j <= degree; j++) {
            if (j == i) {
                continue;
            }

            unsigned long long num = mod_sub(x, points[j].x, mod);
            unsigned long long den = mod_sub(points[i].x, points[j].x, mod);
            unsigned long long inv_den;

            if (mod_inv(den, mod, &inv_den)) {
                return -1;
            }

            term = mod_mul(term, num, mod);
            term = mod_mul(term, inv_den, mod);
        }

        *result = mod_add(*result, term, mod);
    }

    return 0;
}

static int polynomial_mod_div_linear(const struct polynomial_t numerator, unsigned long long a,
                                     unsigned long long mod, struct polynomial_t *quotient) {
    if (numerator.degree == 0) {
        return -1;
    }

    quotient->degree            = numerator.degree - 1;

    const unsigned long long *Q = numerator.coeffs;
    unsigned long long       *S = quotient->coeffs;

    S[quotient->degree]         = Q[numerator.degree];

    for (unsigned int k = quotient->degree; k > 0;) {
        --k;
        S[k] = mod_add(Q[k + 1], mod_mul(a, S[k + 1], mod), mod);
    }

    return 0;
}

int polynomial_mod_div(const struct polynomial_t numerator, const struct polynomial_t denominator,
                       const unsigned long long mod, struct polynomial_t *result) {

    if (mod == 0) {
        return -1;
    }

    unsigned int i;

    if (denominator.degree == 1) {
        unsigned long long d1_inv;
        if (mod_inv(denominator.coeffs[1], mod, &d1_inv)) {
            return -1;
        }

        unsigned long long a = mod_mul(mod_sub(0, denominator.coeffs[0], mod), d1_inv, mod);

        unsigned long long scaled_coeffs[numerator.degree + 1];
        for (i = 0; i <= numerator.degree; i++) {
            scaled_coeffs[i] = mod_mul(numerator.coeffs[i], d1_inv, mod);
        }

        struct polynomial_t scaled = {numerator.degree, scaled_coeffs};

        return polynomial_mod_div_linear(scaled, a, mod, result);
    }

    if (numerator.degree < denominator.degree) {
        result->degree    = 0;
        result->coeffs[0] = 0;
        return 0;
    }

    unsigned int deg_diff = numerator.degree - denominator.degree;
    result->degree        = deg_diff;

    for (i = 0; i <= result->degree; ++i) {
        result->coeffs[i] = 0;
    }

    unsigned long long temp[numerator.degree + 1];
    for (i = 0; i <= numerator.degree; ++i) {
        temp[i] = numerator.coeffs[i];
    }

    unsigned long long inv;

    if (mod_inv(denominator.coeffs[denominator.degree], mod, &inv)) {
        return -1;
    }

    for (i = numerator.degree + 1; i-- > denominator.degree;) {
        if (temp[i] == 0) {
            continue;
        }

        unsigned int       k      = i - denominator.degree;
        unsigned long long factor = mod_mul(temp[i], inv, mod);
        result->coeffs[k]         = factor;

        for (unsigned int j = 0; j <= denominator.degree; ++j) {
            unsigned int       deg = k + j;
            unsigned long long sub = mod_mul(factor, denominator.coeffs[j], mod);
            temp[deg]              = mod_sub(temp[deg], sub, mod);
        }

        temp[i] = 0;
    }

    return 0;
}

int polynomial_lagrange_interpolation(const struct point_t *points, unsigned long long mod,
                                      struct polynomial_t result) {
    if (mod == 0) {
        return -1;
    }

    unsigned int       i, j;
    const unsigned int n = result.degree;

    unsigned long long Q_coeffs[n + 2];

    for (i = 0; i <= n + 1; i++) {
        Q_coeffs[i] = 0;
    }

    Q_coeffs[0]              = 1;
    unsigned int       Q_deg = 0;
    unsigned long long tmp[n + 2];

    for (i = 0; i <= n; i++) {
        const unsigned long long xi = points[i].x;

        for (j = 0; j <= Q_deg + 1; j++) {
            tmp[j] = 0;
        }

        for (j = 0; j <= Q_deg; j++) {
            tmp[j + 1] = mod_add(tmp[j + 1], Q_coeffs[j], mod);
            tmp[j]     = mod_sub(tmp[j], mod_mul(Q_coeffs[j], xi, mod), mod);
        }

        Q_deg++;
        for (j = 0; j <= Q_deg; j++) {
            Q_coeffs[j] = tmp[j];
        }
    }

    struct polynomial_t vanishing_poly = {Q_deg, Q_coeffs};

    unsigned long long  Qp_coeffs[n + 1];
    for (i = 0; i <= n; i++) {
        Qp_coeffs[i] = 0;
    }

    for (i = 1; i <= vanishing_poly.degree; i++) {
        Qp_coeffs[i - 1] = mod_mul(vanishing_poly.coeffs[i], i, mod);
    }

    struct polynomial_t vanishing_derivative = {n, Qp_coeffs};

    polynomial_zero(result);

    unsigned long long  basis_coeffs[n + 1];
    struct polynomial_t basis   = {n, basis_coeffs};

    struct polynomial_t divisor = {
        1, (unsigned long long[2]){0, 1}  /* placeholder */
    };

    for (i = 0; i <= n; i++) {
        for (j = 0; j <= n; j++) {
            basis_coeffs[j] = 0;
        }

        unsigned long long div_coeffs[2];
        div_coeffs[0]  = mod_sub(0, points[i].x, mod);
        div_coeffs[1]  = 1;
        divisor.coeffs = div_coeffs;

        if (polynomial_mod_div(vanishing_poly, divisor, mod, &basis)) {
            return -1;
        }

        const unsigned long long denom = polynomial_eval(vanishing_derivative, mod, points[i].x);

        unsigned long long       inv_denom;
        if (mod_inv(denom, mod, &inv_denom)) {
            return -1;
        }

        const unsigned long long scale = mod_mul(points[i].y, inv_denom, mod);

        for (j = 0; j <= n; j++) {
            result.coeffs[j] = mod_add(result.coeffs[j], mod_mul(basis_coeffs[j], scale, mod), mod);
        }
    }

    return 0;
}
