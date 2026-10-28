#include "berlekamp-welch.h"

#include "mod.h"
#include "polynomial.h"

#include <stdio.h>
#include <string.h>

int gauss_jordan_general(unsigned int m, unsigned int n, unsigned long long **A_ext,
                         unsigned long long mod, unsigned long long *x, char *is_free_variable) {
    unsigned int       row;
    unsigned int       i, col, r, k, pivot_row, pivot_col;
    unsigned long long tmp, inv, factor;
    int                all_zero;

    row = 0;

    for (i = 0; i < n; ++i) {
        is_free_variable[i] = 0;
    }

    for (col = 0; col < n && row < m; ++col) {
        pivot_row = m;

        for (r = row; r < m; ++r) {
            if (A_ext[r][col] % mod != 0) {
                pivot_row = r;
                break;
            }
        }

        if (pivot_row == m) {
            is_free_variable[col] = 1;
            continue;
        }

        if (pivot_row != row) {
            for (k = 0; k <= n; ++k) {
                tmp                 = A_ext[row][k];
                A_ext[row][k]       = A_ext[pivot_row][k];
                A_ext[pivot_row][k] = tmp;
            }
        }

        if (mod_inv(A_ext[row][col], mod, &inv)) {
            return -1;
        }

        for (k = 0; k <= n; ++k) {
            A_ext[row][k] = (A_ext[row][k] * inv) % mod;
        }

        for (r = 0; r < m; ++r) {
            if (r != row && A_ext[r][col] != 0) {
                factor = A_ext[r][col];
                for (k = 0; k <= n; ++k) {
                    A_ext[r][k] = (mod + A_ext[r][k] - (factor * A_ext[row][k]) % mod) % mod;
                }
            }
        }

        ++row;
    }

    for (r = row; r < m; ++r) {
        all_zero = 1;
        for (col = 0; col < n; ++col) {
            if (A_ext[r][col] % mod != 0) {
                all_zero = 0;
                break;
            }
        }

        if (all_zero && A_ext[r][n] % mod != 0) {
            return -1;
        }
    }

    for (i = 0; i < n; ++i) {
        x[i] = 0;
    }

    for (r = 0; r < m; ++r) {
        pivot_col = 0;
        while (pivot_col < n && A_ext[r][pivot_col] == 0) {
            ++pivot_col;
        }

        if (pivot_col < n) {
            x[pivot_col] = A_ext[r][n];
        }
    }

    for (i = 0; i < n; ++i) {
        if (is_free_variable[i]) {
            return 1;
        }
    }

    return 0;
}

int berlekamp_welch(unsigned int n, unsigned int d, unsigned long long mod, struct point_t *points,
                    struct polynomial_t *polynomial) {

    unsigned int        i, j;

    unsigned int        errors       = (n - d - 1) / 2;
    unsigned int        deg_q        = d + errors;
    unsigned int        deg_e        = errors;
    unsigned int        num_unknowns = deg_q + 1 + deg_e;

    unsigned long long  A_ext[n][num_unknowns + 1];
    unsigned long long *A_ptrs[n];
    char                is_free_variable[n];
    unsigned long long  solution[num_unknowns];

    unsigned long long  Q_coeffs[deg_q + 1];
    struct polynomial_t Q = {.degree = deg_q, .coeffs = Q_coeffs};

    unsigned long long  E_coeffs[deg_e + 1];
    struct polynomial_t E = {.degree = deg_e, .coeffs = E_coeffs};
    unsigned long long  x, y, term;

    for (i = 0; i < n; ++i) {
        x = points[i].x;
        y = points[i].y;

        for (j = 0; j <= deg_q; ++j) {
            A_ext[i][j] = mod_pow(x, j, mod);
        }

        for (j = 0; j < deg_e; ++j) {
            term                    = mod_mul(mod_pow(x, j, mod), y, mod);
            A_ext[i][deg_q + 1 + j] = mod_sub(0, term, mod);
        }

        A_ext[i][num_unknowns] = mod_mul(y, mod_pow(x, deg_e, mod), mod);

        A_ptrs[i]              = A_ext[i];
    }

    if (gauss_jordan_general(n, num_unknowns, A_ptrs, mod, solution, is_free_variable) < 0) {
        return -1;
    }

    for (i = 0; i <= deg_q; ++i) {
        Q.coeffs[i] = solution[i];
    }

    for (i = 0; i < deg_e; ++i) {
        E.coeffs[i] = solution[deg_q + 1 + i];
    }
    E.coeffs[deg_e] = 1;

    if (polynomial_mod_div(Q, E, mod, polynomial)) {
        return -1;
    }

    return 0;
}
