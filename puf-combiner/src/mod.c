#include "mod.h"

#include <limits.h>

unsigned long long mod_norm(const unsigned long long a, const unsigned long long mod) {
    return a % mod;
}

unsigned long long mod_add(unsigned long long a, unsigned long long b,
                           const unsigned long long mod) {

    a = mod_norm(a, mod);
    b = mod_norm(b, mod);
    return (a >= mod - b) ? (a - (mod - b)) : (a + b);
}

unsigned long long mod_sub(const unsigned long long a, const unsigned long long b,
                           const unsigned long long mod) {
    return (a >= b) ? (a - b) : (mod + a - b);
}

unsigned long long mod_mul(const unsigned long long a, const unsigned long long b,
                           const unsigned long long mod) {
    return mod_norm(a * b, mod);
}

unsigned long long mod_pow(unsigned long long base, unsigned long long exp,
                           const unsigned long long mod) {
    unsigned long long result = 1;

    base                      = mod_norm(base, mod);

    while (exp > 0) {
        if (exp & 1) {
            result = mod_norm(result * base, mod);
        }

        base = mod_mul(base, base, mod);
        exp >>= 1;
    }

    return result;
}

// int mod_inv(const unsigned long long a, const unsigned long long mod, unsigned long long *inv) {
//     long long          t = 0, new_t = 1;
//     long long          r = mod, new_r = a;
//     long long          temp_t, temp_r;
//     unsigned long long quotient;

//     while (new_r != 0) {
//         quotient = r / new_r;
//         temp_t   = t;
//         t        = new_t;
//         new_t    = temp_t - quotient * new_t;

//         temp_r   = r;
//         r        = new_r;
//         new_r    = temp_r - quotient * new_r;
//     }

//     if (r > 1) {
//         return -1;
//     }

//     if (t < 0) {
//         t += mod;
//     }

//     *inv = t;

//     return 0;
// }

int mod_inv(const unsigned long long a, const unsigned long long mod, unsigned long long *inv) {
    if (!inv || mod <= 1 || mod > (unsigned long long)LLONG_MAX) {
        return -1;
    }

    long long t = 0, new_t = 1;
    long long r     = (long long)mod;
    long long new_r = (long long)(a % mod);

    while (new_r != 0) {
        long long quotient = r / new_r;
        long long temp_t   = t - quotient * new_t;
        long long temp_r   = r - quotient * new_r;

        t                  = new_t;
        new_t              = temp_t;
        r                  = new_r;
        new_r              = temp_r;
    }

    if (r != 1) {
        return -1;
    }

    if (t < 0) {
        t += (long long)mod;
    }

    *inv = (unsigned long long)t;
    return 0;
}
