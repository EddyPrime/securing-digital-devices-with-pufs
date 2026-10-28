/**
 * @file log.c
 * @brief Implementation of logging and debug output utilities.
 */

#include "common/log.h"

void log_print_hex(const uint8_t *bytes, size_t len_bytes, const char *label) {
    if (bytes == NULL && len_bytes != 0u) {
        return;
    }

    printf("%s (%zu bytes): ", label != NULL ? label : "", len_bytes);

    for (size_t i = 0u; i < len_bytes; i++) {
        printf("%02X", bytes[i]);
    }

    printf("\n");
}
