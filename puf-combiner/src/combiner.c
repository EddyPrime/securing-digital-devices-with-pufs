#if defined DEBUG
#include <stdio.h>
#endif

#include "berlekamp-welch.h"
#include "bits.h"
#include "combiner.h"
#include "hash.h"
#include "polynomial.h"

#include <limits.h>
#include <math.h>
#include <string.h>

static int valid_point_counts(const size_t n, const size_t m) {
    return n > 0 && n < sizeof(unsigned int) * CHAR_BIT && m <= UINT_MAX - n;
}

unsigned int _next_combination_with_ones(const unsigned int n) {
    if (n == 0) {
        return 0;
    }

    const unsigned int smallest = n & -n;
    const unsigned int ripple   = n + smallest;
    const unsigned int new_bits = ((n ^ ripple) >> 2) / smallest;
    return ripple | new_bits;
}

int _enroll(const size_t n, const size_t m, const unsigned long long mod, struct point_t *points,
            unsigned long long *sk, unsigned char *sk_hash) {
    if (!valid_point_counts(n, m)) {
        return -1;
    }

    struct polynomial_t polynomial;
    unsigned long long  coeffs[n];

    polynomial.degree = (unsigned int)(n - 1);
    polynomial.coeffs = coeffs;

    if (polynomial_lagrange_interpolation(points, mod, polynomial)) {
        return -1;
    }

    for (size_t i = 0; i < m; i++) {
        points[n + i].y = polynomial_eval(polynomial, mod, points[n + i].x);
    }

    *sk = polynomial_eval(polynomial, mod, 0);
    hash_ull(*sk, sk_hash);

    return 0;
}

int enroll_berlekamp_welch(const size_t n, const size_t m, const unsigned long long mod,
                           struct point_t *points, unsigned long long *sk, unsigned char *sk_hash) {
    return _enroll(n, m, mod, points, sk, sk_hash);
}

int reconstruct_berlekamp_welch(const size_t n, const size_t m, const unsigned long long mod,
                                struct point_t *points, unsigned long long *sk,
                                unsigned char *sk_hash, unsigned int *faulty_points) {
    if (!valid_point_counts(n, m)) {
        return -1;
    }

    struct polynomial_t polynomial;
    unsigned long long  coeffs[n];
    unsigned char       sk_hash_computed[HASH_BYTES];

    *faulty_points    = 0;

    polynomial.degree = (unsigned int)(n - 1);
    polynomial.coeffs = coeffs;

    if (berlekamp_welch((unsigned int)(n + m), polynomial.degree, mod, points, &polynomial) != 0) {
        return -1;
    }

    for (size_t i = 0; i < n; i++) {
        if (points[i].y != polynomial_eval(polynomial, mod, points[i].x)) {
            *faulty_points = set_bit(*faulty_points, i);
        }
    }

    *sk = polynomial_eval(polynomial, mod, 0);
    hash_ull(*sk, sk_hash_computed);

    return memcmp(sk_hash, sk_hash_computed, HASH_BYTES) ? -1 : 0;
}

int enroll_enumeration(const size_t n, const size_t m, const unsigned long long mod,
                       struct point_t *points, unsigned long long *sk, unsigned char *sk_hash) {
    return _enroll(n, m, mod, points, sk, sk_hash);
}

int reconstruct_enumeration(const size_t n, const size_t m, const unsigned long long mod,
                            struct point_t *points, unsigned long long *sk, unsigned char *sk_hash,
                            unsigned int *faulty_points) {
    if (!valid_point_counts(n, m) || m > n) {
        return -1;
    }

    size_t        i;
    unsigned char sk_hash_computed[HASH_BYTES];

    *faulty_points = 0;
    struct point_t points_for_rec[n];

    if (m == 0) {
        polynomial_lagrange_eval(points, (unsigned int)(n - 1), mod, 0, sk);
        hash_ull(*sk, sk_hash_computed);

        if (memcmp(sk_hash, sk_hash_computed, HASH_BYTES) == 0) {
            return 0;
        }
    }

    for (unsigned int mask_points_to_replace = (1u << m) - 1u;
         m != 0 && mask_points_to_replace < (1u << n);
         mask_points_to_replace = _next_combination_with_ones(mask_points_to_replace)) {

        size_t additional_points_index = n;

        for (i = 0; i < n; i++) {
            if ((mask_points_to_replace & (1u << i))) {
                points_for_rec[i] = points[additional_points_index++];
            } else {
                points_for_rec[i] = points[i];
            }
        }

        polynomial_lagrange_eval(points_for_rec, (unsigned int)(n - 1), mod, 0, sk);
        hash_ull(*sk, sk_hash_computed);

        if (memcmp(sk_hash, sk_hash_computed, HASH_BYTES) == 0) {
            *faulty_points = mask_points_to_replace;
            return 0;
        }
    }

    return -1;
}

int enroll_hashing(const size_t n, const size_t m, const unsigned long long mod,
                   struct point_t *points, unsigned long long *sk, unsigned char *sk_hash,
                   unsigned char *hashes) {
    if (_enroll(n, m, mod, points, sk, sk_hash)) {
        return -1;
    }

    for (size_t i = 0; i < n; i++) {
        hash_ull(points[i].y, &hashes[i * HASH_BYTES]);
    }

    return 0;
}

int reconstruct_hashing(const size_t n, const size_t m, const unsigned long long mod,
                        struct point_t *points, unsigned long long *sk, unsigned char *sk_hash,
                        unsigned int *faulty_points, unsigned char *hashes) {
    if (!valid_point_counts(n, m)) {
        return -1;
    }

    size_t        j = 0;
    unsigned char sk_hash_computed[HASH_BYTES];

    *faulty_points = 0;

    for (size_t i = 0; i < n; i++) {
        hash_ull(points[i].y, sk_hash_computed);

        if (memcmp(&hashes[i * HASH_BYTES], sk_hash_computed, HASH_BYTES) == 0) {
            continue;
        }

        *faulty_points = set_bit(*faulty_points, i);

        if (j >= m) {
            return -1;
        }

        points[i] = points[n + j];
        ++j;
    }

    polynomial_lagrange_eval(points, (unsigned int)(n - 1), mod, 0, sk);
    hash_ull(*sk, sk_hash_computed);

    return memcmp(sk_hash, sk_hash_computed, HASH_BYTES) ? -1 : 0;
}
