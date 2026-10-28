#include "hash.h"

#include <stdlib.h>

#ifdef __linux__
#include <stdint.h>
#endif

#ifdef ESP_PLATFORM
#include "mbedtls/sha256.h"
#else
#include <openssl/sha.h>
#endif

void _sha256(const void *data, const size_t length, unsigned char *hash) {
    const unsigned char *bytes = (const unsigned char *)data;

#ifdef ESP_PLATFORM
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, bytes, length);
    mbedtls_sha256_finish(&ctx, hash);
    mbedtls_sha256_free(&ctx);
#else
    SHA256(bytes, length, hash);
#endif
}

void hash_ull(const unsigned long long value, unsigned char *hash) {
    _sha256(&value, sizeof(unsigned long long), hash);
}
