/**
 * @file workspace_internal.h
 * @brief Provides internal workspace management utilities.
 *
 * This header defines helper functions used by fuzzy extractor
 * implementations to align cursors and partition preallocated workspaces into
 * contiguous memory regions.
 *
 * These functions do not perform bounds checking or argument validation. The
 * caller must ensure that the workspace is sufficiently large and that all
 * documented preconditions are satisfied.
 *
 * @warning This header is intended for internal use only.
 */

#ifndef WORKSPACE_INTERNAL_H
#define WORKSPACE_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Advances a workspace cursor to the next aligned address.
 *
 * The function returns the first address greater than or equal to @p cursor
 * that satisfies the requested byte alignment.
 *
 * @param[in] cursor    Current workspace cursor.
 * @param[in] alignment Required byte alignment.
 *
 * @return The aligned workspace cursor.
 *
 * @pre @p cursor must point within a valid workspace.
 * @pre @p alignment must be a non-zero power of two.
 * @pre The address calculation must not overflow @c uintptr_t.
 */
static inline uint8_t *workspace_align_cursor(uint8_t *cursor, size_t alignment) {
    const uintptr_t address = (uintptr_t)cursor;
    const uintptr_t aligned = (address + (uintptr_t)alignment - 1u) & ~((uintptr_t)alignment - 1u);

    return (uint8_t *)aligned;
}

/**
 * @brief Allocates a contiguous slice from a workspace.
 *
 * The function returns the region beginning at the current workspace cursor
 * and advances the cursor by @p len_bytes. No bounds checking or alignment
 * adjustment is performed.
 *
 * @param[in,out] cursor    Address of the current workspace cursor.
 * @param[in]     len_bytes Length of the requested slice in bytes.
 *
 * @return A pointer to the beginning of the allocated slice.
 *
 * @pre @p cursor must not be @c NULL.
 * @pre @p cursor must reference a valid workspace cursor.
 * @pre The workspace must contain at least @p len_bytes bytes beginning at
 *      the current cursor.
 * @pre The current cursor must already satisfy any alignment required by the
 *      allocated object.
 */
static inline uint8_t *workspace_alloc_slice(uint8_t **cursor, size_t len_bytes) {
    uint8_t *slice = *cursor;
    *cursor += len_bytes;

    return slice;
}

#ifdef __cplusplus
}
#endif

#endif /* WORKSPACE_INTERNAL_H */
