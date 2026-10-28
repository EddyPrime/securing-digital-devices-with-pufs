#ifndef TICTOC_H
#define TICTOC_H

/**
 * @file tictoc.h
 * @brief Structures and macros for execution time evaluation.
 *
 * This header provides macros to measure elapsed CPU time (user and system) using `getrusage`.
 */

#include <sys/resource.h>
#include <time.h>

/**
 * @brief Convert nanoseconds to microseconds.
 *
 * @param ns Nanoseconds.
 * @return Equivalent time in microseconds.
 */
#define nano_to_micro(ns) ((ns) / 1000)

/**
 * @brief Convert nanoseconds to milliseconds.
 *
 * @param ns Nanoseconds.
 * @return Equivalent time in milliseconds.
 */
#define nano_to_milli(ns) ((ns) / 1000000)

/**
 * @brief Resource usage timer.
 *
 * Holds two `rusage` snapshots for start and end time.
 */
struct ru_timer {
    struct rusage start; /** Resource usage at start. */
    struct rusage end;   /** Resource usage at end. */
};

/**
 * @brief Record the start resource usage.
 *
 * Initializes `timer.start` using `getrusage(RUSAGE_SELF)`.
 *
 * @param timer `ru_timer` struct.
 */
#define RU_TIC(timer)                           \
    do {                                        \
        getrusage(RUSAGE_SELF, &(timer).start); \
    } while (0)

/**
 * @brief Record the end resource usage.
 *
 * Initializes `timer.end` using `getrusage(RUSAGE_SELF)`.
 *
 * @param timer `ru_timer` struct.
 */
#define RU_TOC(timer)                         \
    do {                                      \
        getrusage(RUSAGE_SELF, &(timer).end); \
    } while (0)

/**
 * @brief Compute elapsed user CPU time between TIC and TOC.
 *
 * Computes user time in nanoseconds.
 *
 * @param timer `ru_timer` struct.
 * @return User CPU time in nanoseconds.
 */
#define RU_TIC_TOC_USER(timer)                                                                   \
    (((long long)((timer).end.ru_utime.tv_sec - (timer).start.ru_utime.tv_sec) * 1000000000LL) + \
     ((long long)((timer).end.ru_utime.tv_usec - (timer).start.ru_utime.tv_usec) * 1000LL))

/**
 * @brief Compute elapsed system CPU time between TIC and TOC.
 *
 * Computes system time in nanoseconds.
 *
 * @param timer `ru_timer` struct.
 * @return System CPU time in nanoseconds.
 */
#define RU_TIC_TOC_SYS(timer)                                                                    \
    (((long long)((timer).end.ru_stime.tv_sec - (timer).start.ru_stime.tv_sec) * 1000000000LL) + \
     ((long long)((timer).end.ru_stime.tv_usec - (timer).start.ru_stime.tv_usec) * 1000LL))

/**
 * @brief Compute total CPU time (user + system) in nanoseconds.
 *
 * @param timer `ru_timer` struct.
 * @return Total CPU time in nanoseconds.
 */
#define RU_TIC_TOC(timer) (RU_TIC_TOC_USER(timer) + RU_TIC_TOC_SYS(timer))

#endif /* TICTOC_H */
