/**
 * @file secure_memory.h
 * @brief Provides utilities for handling sensitive memory.
 *
 * This header defines functions for securely erasing and releasing memory that
 * may contain sensitive data, as well as comparing memory regions without
 * data-dependent early termination, hence in constant-time.
 */

#ifndef SECURE_MEMORY_H
#define SECURE_MEMORY_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Securely erases a memory region.
 *
 * The function overwrites the first @p len_bytes bytes of the memory region
 * referenced by @p ptr. The erasure is performed in a manner intended to
 * prevent its removal by compiler optimizations.
 *
 * When @p ptr is @c NULL or @p len_bytes is zero, the function has no effect.
 *
 * @param[in,out] ptr       Memory region to erase.
 * @param[in]     len_bytes Number of bytes to erase.
 */
void secure_bzero(void *ptr, size_t len_bytes);

/**
 * @brief Securely erases and releases a dynamically allocated memory region.
 *
 * The function overwrites the first @p len_bytes bytes of the memory region
 * referenced by @p ptr before releasing it with free().
 *
 * When @p ptr is @c NULL, the function has no effect.
 *
 * @param[in,out] ptr       Dynamically allocated memory region to erase and
 *                          release.
 * @param[in]     len_bytes Number of bytes to erase before releasing the
 *                          memory region.
 */
void secure_free(void *ptr, size_t len_bytes);

/**
 * @brief Compares two memory regions without data-dependent early termination.
 *
 * The function compares the first @p len_bytes bytes of @p a and @p b without
 * terminating when the first differing byte is encountered. It determines
 * equality only and does not provide lexicographical ordering.
 *
 * @param[in] a         First memory region.
 * @param[in] b         Second memory region.
 * @param[in] len_bytes Number of bytes to compare.
 *
 * @return @c 0 if the memory regions are equal.
 * @return A non-zero value if the memory regions differ.
 * @return @c -1 if an argument is invalid.
 *
 * @pre @p a and @p b must each reference a memory region containing at least
 *      @p len_bytes bytes when @p len_bytes is greater than zero.
 */
int secure_memcmp(const void *a, const void *b, size_t len_bytes);

#ifdef __cplusplus
}
#endif

#endif /* SECURE_MEMORY_H */
