/**
 * @file hash.c
 * @brief Implementation of the generic hash interface.
 */

#include "crypto/hash.h"

#include <openssl/sha.h>

#define FNV1A_32_OFFSET_BASIS 0x811C9DC5u
#define FNV1A_32_PRIME        0x01000193u
#define FNV1A_32_DIGEST_LEN   4u

struct hash_alg {
    size_t      digest_len_bytes;
    const char *name;

    hash_status_t (*digest)(const uint8_t *data, size_t data_len_bytes, uint8_t *digest,
                            size_t digest_len_bytes);
};

const char *hash_status_string(hash_status_t status) {
    switch (status) {
    case HASH_OK:                return "success";

    case HASH_ERR_NULL_ARG:      return "null argument";

    case HASH_ERR_OUT_TOO_SMALL: return "output buffer too small";

    case HASH_ERR_BACKEND_FAIL:  return "backend failure";

    default:                     return "unknown status";
    }
}

size_t hash_digest_len_bytes(const hash_alg_t *alg) {
    return alg != NULL ? alg->digest_len_bytes : 0u;
}

hash_status_t hash_digest(const hash_alg_t *alg, const void *data, size_t data_len_bytes,
                          uint8_t *digest, size_t digest_len_bytes) {
    if (alg == NULL || digest == NULL) {
        return HASH_ERR_NULL_ARG;
    }

    if (data == NULL && data_len_bytes != 0u) {
        return HASH_ERR_NULL_ARG;
    }

    if (digest_len_bytes < alg->digest_len_bytes) {
        return HASH_ERR_OUT_TOO_SMALL;
    }

    return alg->digest(data, data_len_bytes, digest, digest_len_bytes);
}

static hash_status_t sha_256_digest(const uint8_t *data, size_t data_len_bytes, uint8_t *digest,
                                    size_t digest_len_bytes) {
    if (digest == NULL) {
        return HASH_ERR_NULL_ARG;
    }

    if (data == NULL && data_len_bytes != 0u) {
        return HASH_ERR_NULL_ARG;
    }

    if (digest_len_bytes < SHA256_DIGEST_LENGTH) {
        return HASH_ERR_OUT_TOO_SMALL;
    }

    if (SHA256(data, data_len_bytes, digest) == NULL) {
        return HASH_ERR_BACKEND_FAIL;
    }

    return HASH_OK;
}

static hash_status_t sha_512_digest(const uint8_t *data, size_t data_len_bytes, uint8_t *digest,
                                    size_t digest_len_bytes) {
    if (digest == NULL) {
        return HASH_ERR_NULL_ARG;
    }

    if (data == NULL && data_len_bytes != 0u) {
        return HASH_ERR_NULL_ARG;
    }

    if (digest_len_bytes < SHA512_DIGEST_LENGTH) {
        return HASH_ERR_OUT_TOO_SMALL;
    }

    if (SHA512(data, data_len_bytes, digest) == NULL) {
        return HASH_ERR_BACKEND_FAIL;
    }

    return HASH_OK;
}

static hash_status_t fnv1a_32_digest(const uint8_t *data, size_t data_len_bytes, uint8_t *digest,
                                     size_t digest_len_bytes) {
    if (digest == NULL) {
        return HASH_ERR_NULL_ARG;
    }

    if (data == NULL && data_len_bytes != 0u) {
        return HASH_ERR_NULL_ARG;
    }

    if (digest_len_bytes < FNV1A_32_DIGEST_LEN) {
        return HASH_ERR_OUT_TOO_SMALL;
    }

    uint32_t hash = FNV1A_32_OFFSET_BASIS;

    for (size_t i = 0u; i < data_len_bytes; i++) {
        hash ^= data[i];
        hash *= FNV1A_32_PRIME;
    }

    digest[0] = (uint8_t)((hash >> 24u) & 0xFFu);
    digest[1] = (uint8_t)((hash >> 16u) & 0xFFu);
    digest[2] = (uint8_t)((hash >> 8u) & 0xFFu);
    digest[3] = (uint8_t)(hash & 0xFFu);

    return HASH_OK;
}

const hash_alg_t hash_alg_sha_256 = {
    .digest_len_bytes = SHA256_DIGEST_LENGTH,
    .name             = "SHA-256",
    .digest           = sha_256_digest,
};

const hash_alg_t hash_alg_sha_512 = {
    .digest_len_bytes = SHA512_DIGEST_LENGTH,
    .name             = "SHA-512",
    .digest           = sha_512_digest,
};

const hash_alg_t hash_alg_fnv1a_32 = {
    .digest_len_bytes = FNV1A_32_DIGEST_LEN,
    .name             = "FNV-1a-32",
    .digest           = fnv1a_32_digest,
};
