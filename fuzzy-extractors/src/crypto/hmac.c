/**
 * @file hmac.c
 * @brief Implementation of the generic HMAC interface.
 */

#include "crypto/hmac.h"

#include <limits.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

struct hmac_alg {
    const EVP_MD *(*md)(void);
    size_t      digest_len_bytes;
    const char *name;
};

const char *hmac_status_string(hmac_status_t status) {
    switch (status) {
    case HMAC_OK:                return "success";

    case HMAC_ERR_NULL_ARG:      return "null argument";

    case HMAC_ERR_OUT_TOO_SMALL: return "output buffer too small";

    case HMAC_ERR_KEY_TOO_LARGE: return "key too large";

    case HMAC_ERR_BACKEND_FAIL:  return "backend failure";

    default:                     return "unknown status";
    }
}

size_t hmac_digest_len_bytes(const hmac_alg_t *alg) {
    return alg != NULL ? alg->digest_len_bytes : 0u;
}

hmac_status_t hmac_digest(const hmac_alg_t *alg, const void *key, size_t key_len_bytes,
                          const void *data, size_t data_len_bytes, uint8_t *digest,
                          size_t digest_len_bytes) {
    if (alg == NULL || digest == NULL) {
        return HMAC_ERR_NULL_ARG;
    }

    if (key == NULL && key_len_bytes != 0u) {
        return HMAC_ERR_NULL_ARG;
    }

    if (data == NULL && data_len_bytes != 0u) {
        return HMAC_ERR_NULL_ARG;
    }

    if (digest_len_bytes < alg->digest_len_bytes) {
        return HMAC_ERR_OUT_TOO_SMALL;
    }

    if (key_len_bytes > (size_t)INT_MAX) {
        return HMAC_ERR_KEY_TOO_LARGE;
    }

    unsigned int out_len_bytes = 0u;

    if (HMAC(alg->md(), key, (int)key_len_bytes, data, data_len_bytes, digest, &out_len_bytes) ==
        NULL) {
        return HMAC_ERR_BACKEND_FAIL;
    }

    if ((size_t)out_len_bytes != alg->digest_len_bytes) {
        return HMAC_ERR_BACKEND_FAIL;
    }

    return HMAC_OK;
}

hmac_status_t hmac_digest_parts(const hmac_alg_t *alg, const void *key, size_t key_len_bytes,
                                const hmac_part_t *parts, size_t parts_n, uint8_t *digest,
                                size_t digest_len_bytes) {

    if (alg == NULL || digest == NULL || (key == NULL && key_len_bytes != 0u) ||
        (parts == NULL && parts_n != 0u)) {
        return HMAC_ERR_NULL_ARG;
    }

    if (digest_len_bytes < alg->digest_len_bytes) {
        return HMAC_ERR_OUT_TOO_SMALL;
    }

    if (key_len_bytes > (size_t)INT_MAX) {
        return HMAC_ERR_KEY_TOO_LARGE;
    }

    EVP_PKEY *pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, (int)key_len_bytes);

    if (pkey == NULL) {
        return HMAC_ERR_BACKEND_FAIL;
    }

    EVP_MD_CTX   *mdctx  = EVP_MD_CTX_new();
    hmac_status_t status = HMAC_ERR_BACKEND_FAIL;

    if (mdctx != NULL && EVP_DigestSignInit(mdctx, NULL, alg->md(), NULL, pkey) == 1) {

        size_t i = 0u;

        for (; i < parts_n; i++) {
            if (parts[i].data == NULL && parts[i].len_bytes != 0u) {
                status = HMAC_ERR_NULL_ARG;
                break;
            }

            if (parts[i].len_bytes != 0u &&
                EVP_DigestSignUpdate(mdctx, parts[i].data, parts[i].len_bytes) != 1) {
                break;
            }
        }

        size_t actual_len = digest_len_bytes;

        if (i == parts_n && EVP_DigestSignFinal(mdctx, digest, &actual_len) == 1 &&
            actual_len == alg->digest_len_bytes) {
            status = HMAC_OK;
        }
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);

    return status;
}

const hmac_alg_t hmac_alg_sha_256 = {
    .md               = EVP_sha256,
    .digest_len_bytes = SHA256_DIGEST_LENGTH,
    .name             = "SHA-256",
};

const hmac_alg_t hmac_alg_sha_512 = {
    .md               = EVP_sha512,
    .digest_len_bytes = SHA512_DIGEST_LENGTH,
    .name             = "SHA-512",
};
