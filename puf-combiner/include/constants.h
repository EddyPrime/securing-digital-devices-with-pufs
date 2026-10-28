#ifndef CONSTANTS_H
#define CONSTANTS_H

/**
 * @file constants.h
 * @brief Global constants.
 */

/** @def P
 * @brief Prime number for the finite field.
 */
#define P 1000000007

/** @def N
 * @brief Number of candidates.
 */
#define N 3

/** @def M
 * @brief Number of additional points.
 */
#define M 2

/** @def T
 * @brief Maximum number of faulty candidates.
 */
#define T 0

/** @def HASH_BYTES
 * @brief Size of the hash in bytes.
 */
#define HASH_BYTES 32

/** @def NUM_ATTEMPTS
 * @brief Number of tests.
 */
#define NUM_ATTEMPTS 1000

/** @def STRAT_BERLEKAMP_WELCH
 * @brief Use Berlekamp-Welch strategy.
 */
#define STRAT_BERLEKAMP_WELCH 1

/** @def STRAT_ENUMERATION
 * @brief Use enumeration strategy.
 */
#define STRAT_ENUMERATION 2

/** @def STRAT_HASHING
 * @brief Use hashing strategy.
 */
#define STRAT_HASHING 3

#endif /* CONSTANTS_H */
