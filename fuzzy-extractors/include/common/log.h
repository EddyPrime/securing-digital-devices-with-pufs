/**
 * @file log.h
 * @brief Provides logging and hexadecimal output utilities.
 *
 * This header defines utilities for writing formatted diagnostic messages and
 * hexadecimal representations of byte arrays.
 *
 * When @c DEBUG is defined, logging output is written to the standard error
 * stream. Otherwise, the logging macros expand to no-op expressions and their
 * arguments are not evaluated.
 */

#ifndef LOG_H
#define LOG_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Prints a byte array in hexadecimal format.
 *
 * When @p label is not @c NULL, the label is printed before the hexadecimal
 * representation of the byte array.
 *
 * @param[in] bytes     Byte array to print.
 * @param[in] len_bytes Number of bytes to print.
 * @param[in] label     Optional null-terminated label, or @c NULL if no label
 *                      is required.
 *
 * @pre @p bytes must point to an array containing at least @p len_bytes bytes
 *      when @p len_bytes is greater than zero.
 */
void log_print_hex(const uint8_t *bytes, size_t len_bytes, const char *label);

#ifdef DEBUG

/**
 * @brief Writes a formatted diagnostic message when debugging is enabled.
 *
 * The arguments follow the same format and semantics as @c fprintf, with
 * output directed to the standard error stream.
 *
 * When debugging is disabled, this macro produces no output and does not
 * evaluate its arguments.
 */
#define LOG(...)                            \
    do {                                    \
        (void)fprintf(stderr, __VA_ARGS__); \
    } while (0)

/**
 * @brief Prints a byte array in hexadecimal format when debugging is enabled.
 *
 * The arguments are forwarded to log_print_hex().
 *
 * When debugging is disabled, this macro produces no output and does not
 * evaluate its arguments.
 */
#define LOG_HEX(...)                \
    do {                            \
        log_print_hex(__VA_ARGS__); \
    } while (0)

#else

/**
 * @brief Discards a diagnostic log operation when debugging is disabled.
 *
 * The macro produces no output and does not evaluate its arguments.
 */
#define LOG(...)     ((void)0)

/**
 * @brief Discards a hexadecimal log operation when debugging is disabled.
 *
 * The macro produces no output and does not evaluate its arguments.
 */
#define LOG_HEX(...) ((void)0)

#endif

#ifdef __cplusplus
}
#endif

#endif /* LOG_H */
