/**
 * @file secure_memory.c
 * @brief Implements functions for securely handling sensitive memory.
 */

#include "common/secure_memory.h"

#include <openssl/crypto.h>
#include <stdlib.h>

void secure_bzero(void *ptr, size_t len_bytes) {
    if (ptr == NULL || len_bytes == 0u) {
        return;
    }

    // volatile uint8_t *p = (volatile uint8_t *)ptr;

    // while (len_bytes > 0u) {
    //     *p = 0u;
    //     p++;
    //     len_bytes--;
    // }

    OPENSSL_cleanse(ptr, len_bytes);
}

void secure_free(void *ptr, size_t len_bytes) {
    if (ptr == NULL) {
        return;
    }

    secure_bzero(ptr, len_bytes);
    free(ptr);
}

int secure_memcmp(const void *a, const void *b, size_t len_bytes) {
    if (len_bytes == 0u) {
        return 0;
    }

    if (a == NULL || b == NULL) {
        return -1;
    }

    return CRYPTO_memcmp(a, b, len_bytes);
}
