/**
 * @file main.c
 * @brief Command-line program for fuzzy extractor experiments.
 */

#include "common/bits.h"
#include "common/log.h"
#include "common/secure_memory.h"
#include "crypto/hash.h"
#include "crypto/hmac.h"
#include "crypto/random.h"
#include "crypto/sample.h"
#include "fuzzy_extractor/fuzzy_extractor.h"
#include "fuzzy_extractor/implementations/stl.h"
#include "fuzzy_extractor/implementations/xlock-2024.h"
#include "fuzzy_extractor/implementations/xlock-2026.h"

#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXPERIMENT_KEY_LEN_BYTES     32u
#define EXPERIMENT_NONCE_LEN_BYTES   16u
#define EXPERIMENT_POOL_LEN_BYTES    16u
#define EXPERIMENT_KEY_PRE_LEN_BYTES 16u
#define EXPERIMENT_DL_KEY_LEN_BYTES  16u

typedef struct {
    fuzzy_extractor_implementation_t impl;
    prng_t                           prng;
    size_t                           w_len_bytes;
    double                           ber;
    size_t                           trials;
    size_t                           locks_n;
    size_t                           xor_n;
} app_config_t;

typedef struct {
    uint8_t *storage;
    uint8_t *w;
    uint8_t *w_noisy;
    uint8_t *key_gen;
    uint8_t *key_rep;
    size_t   storage_len_bytes;
} experiment_buffers_t;

static const char *impl_name(fuzzy_extractor_implementation_t impl) {
    switch (impl) {
    case FUZZY_EXTRACTOR_IMPL_XLOCK_2024: return "XLOCK-2024";
    case FUZZY_EXTRACTOR_IMPL_XLOCK_2026: return "XLOCK-2026";
    case FUZZY_EXTRACTOR_IMPL_STL:        return "STL";
    default:                              return "UNKNOWN";
    }
}

static bool is_xlock_impl(fuzzy_extractor_implementation_t impl) {
    return impl == FUZZY_EXTRACTOR_IMPL_XLOCK_2024 || impl == FUZZY_EXTRACTOR_IMPL_XLOCK_2026;
}

static const char *prng_name(prng_t prng) {
    switch (prng) {
    case PRNG_XORSHIFT32: return "XORSHIFT32";
    case PRNG_LFSR32:     return "LFSR32";
    case PRNG_CONSTANT:   return "CONSTANT";
    case PRNG_MARKOV:     return "MARKOV";
    case PRNG_BUCKET:     return "BUCKET";
    default:              return "UNKNOWN";
    }
}

static void print_usage(const char *program_name) {
    printf("Usage:\n");
    printf("  %s [options]\n", program_name);
    printf("\n");

    printf("Required options:\n");
    printf("  --impl <name>          Fuzzy extractor implementation:\n");
    printf("                         xlock-2024, xlock-2026 or stl\n");
    printf("\n");

    printf("  --prng <name>          Pseudorandom number generator:\n");
    printf("                         xorshift32, lfsr32, constant,\n");
    printf("                         markov or bucket\n");
    printf("\n");

    printf("  --w-len-bytes <n>      Noisy input length in bytes\n");
    printf("  --ber <percentage>     Bit error rate in [0, 100]\n");
    printf("  --trials <n>           Number of reproduction trials\n");
    printf("  --locks-n <n>          Number of locks\n");
    printf("\n");

    printf("XLOCK options:\n");
    printf("  --xor-n <n>            Number of XOR operations per lock bit\n");
    printf("\n");

    printf("Other options:\n");
    printf("  -h, --help             Display this help message\n");
    printf("\n");

    printf("Examples:\n");
    printf("  %s --impl xlock-2024 --prng xorshift32 \\\n", program_name);
    printf("     --w-len-bytes 1024 --ber 7.5 --trials 1000 \\\n");
    printf("     --locks-n 21 --xor-n 3\n");
    printf("\n");

    printf("  %s --impl stl --prng xorshift32 \\\n", program_name);
    printf("     --w-len-bytes 1024 --ber 2.5 --trials 1000 \\\n");
    printf("     --locks-n 51\n");
}

static int parse_impl(const char *value, fuzzy_extractor_implementation_t *impl) {
    if (value == NULL || impl == NULL) {
        return EXIT_FAILURE;
    }

    if (strcmp(value, "xlock-2024") == 0) {
        *impl = FUZZY_EXTRACTOR_IMPL_XLOCK_2024;
        return EXIT_SUCCESS;
    }

    if (strcmp(value, "xlock-2026") == 0) {
        *impl = FUZZY_EXTRACTOR_IMPL_XLOCK_2026;
        return EXIT_SUCCESS;
    }

    if (strcmp(value, "stl") == 0) {
        *impl = FUZZY_EXTRACTOR_IMPL_STL;
        return EXIT_SUCCESS;
    }

    return EXIT_FAILURE;
}

static int parse_prng(const char *value, prng_t *prng) {
    if (value == NULL || prng == NULL) {
        return EXIT_FAILURE;
    }

    if (strcmp(value, "xorshift32") == 0) {
        *prng = PRNG_XORSHIFT32;
        return EXIT_SUCCESS;
    }

    if (strcmp(value, "lfsr32") == 0) {
        *prng = PRNG_LFSR32;
        return EXIT_SUCCESS;
    }

    if (strcmp(value, "constant") == 0) {
        *prng = PRNG_CONSTANT;
        return EXIT_SUCCESS;
    }

    if (strcmp(value, "markov") == 0) {
        *prng = PRNG_MARKOV;
        return EXIT_SUCCESS;
    }

    if (strcmp(value, "bucket") == 0) {
        *prng = PRNG_BUCKET;
        return EXIT_SUCCESS;
    }

    return EXIT_FAILURE;
}

static int parse_size_value(const char *value, size_t *result) {
    char              *end    = NULL;
    unsigned long long parsed = 0u;

    if (value == NULL || result == NULL || value[0] == '\0') {
        return EXIT_FAILURE;
    }

    /*
     * strtoull() accepts an optional minus sign. Negative values must
     * therefore be rejected explicitly.
     */
    if (value[0] == '-') {
        return EXIT_FAILURE;
    }

    errno  = 0;
    parsed = strtoull(value, &end, 10);

    if (errno == ERANGE) {
        return EXIT_FAILURE;
    }

    if (end == value || *end != '\0') {
        return EXIT_FAILURE;
    }

    if (parsed > SIZE_MAX) {
        return EXIT_FAILURE;
    }

    *result = (size_t)parsed;

    return EXIT_SUCCESS;
}

static int parse_double_value(const char *value, double *result) {
    char  *end    = NULL;
    double parsed = 0.0;

    if (value == NULL || result == NULL || value[0] == '\0') {
        return EXIT_FAILURE;
    }

    errno  = 0;
    parsed = strtod(value, &end);

    if (errno == ERANGE) {
        return EXIT_FAILURE;
    }

    if (end == value || *end != '\0') {
        return EXIT_FAILURE;
    }

    if (!isfinite(parsed)) {
        return EXIT_FAILURE;
    }

    *result = parsed;

    return EXIT_SUCCESS;
}

static int read_option_value(const char *option, int argc, char **argv, int *index,
                             const char **value) {
    if (option == NULL || argv == NULL || index == NULL || value == NULL) {
        return EXIT_FAILURE;
    }

    if (*index + 1 >= argc) {
        fprintf(stderr, "Error: missing value for option '%s'.\n", option);
        return EXIT_FAILURE;
    }

    *value = argv[++(*index)];

    return EXIT_SUCCESS;
}

static int reject_duplicate_option(const char *option, bool *is_set) {
    if (option == NULL || is_set == NULL) {
        return EXIT_FAILURE;
    }

    if (*is_set) {
        fprintf(stderr, "Error: option '%s' was specified more than once.\n", option);
        return EXIT_FAILURE;
    }

    *is_set = true;

    return EXIT_SUCCESS;
}

static int validate_config(const app_config_t *config) {
    if (config == NULL) {
        return EXIT_FAILURE;
    }

    if (config->w_len_bytes == 0u) {
        fprintf(stderr, "Error: '--w-len-bytes' must be greater than zero.\n");
        return EXIT_FAILURE;
    }

    if (config->w_len_bytes > SIZE_MAX / CHAR_BIT) {
        fprintf(stderr, "Error: '--w-len-bytes' is too large.\n");
        return EXIT_FAILURE;
    }

    if (config->ber < 0.0 || config->ber > 100.0) {
        fprintf(stderr, "Error: '--ber' must be between 0 and 100.\n");
        return EXIT_FAILURE;
    }

    if (config->trials == 0u) {
        fprintf(stderr, "Error: '--trials' must be greater than zero.\n");
        return EXIT_FAILURE;
    }

    if (config->locks_n == 0u) {
        fprintf(stderr, "Error: '--locks-n' must be greater than zero.\n");
        return EXIT_FAILURE;
    }

    if (is_xlock_impl(config->impl) && config->xor_n == 0u) {
        fprintf(stderr, "Error: '--xor-n' must be greater than zero.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static int parse_config(app_config_t *config, int argc, char **argv) {
    bool impl_set    = false;
    bool prng_set    = false;
    bool w_len_set   = false;
    bool ber_set     = false;
    bool trials_set  = false;
    bool locks_n_set = false;
    bool xor_n_set   = false;

    if (config == NULL || argv == NULL) {
        return EXIT_FAILURE;
    }

    *config = (app_config_t){0};

    for (int i = 1; i < argc; ++i) {
        const char *option = argv[i];
        const char *value  = NULL;

        if (strcmp(option, "-h") == 0 || strcmp(option, "--help") == 0) {
            print_usage(argv[0]);
            exit(EXIT_SUCCESS);
        }

        if (strcmp(option, "--impl") == 0) {
            if (reject_duplicate_option(option, &impl_set) != EXIT_SUCCESS ||
                read_option_value(option, argc, argv, &i, &value) != EXIT_SUCCESS) {
                return EXIT_FAILURE;
            }

            if (parse_impl(value, &config->impl) != EXIT_SUCCESS) {
                fprintf(stderr,
                        "Error: unknown implementation '%s'. "
                        "Expected 'xlock-2024', 'xlock-2026' or 'stl'.\n",
                        value);
                return EXIT_FAILURE;
            }

            continue;
        }

        if (strcmp(option, "--prng") == 0) {
            if (reject_duplicate_option(option, &prng_set) != EXIT_SUCCESS ||
                read_option_value(option, argc, argv, &i, &value) != EXIT_SUCCESS) {
                return EXIT_FAILURE;
            }

            if (parse_prng(value, &config->prng) != EXIT_SUCCESS) {
                fprintf(stderr, "Error: unknown PRNG '%s'.\n", value);
                return EXIT_FAILURE;
            }

            continue;
        }

        if (strcmp(option, "--w-len-bytes") == 0) {
            if (reject_duplicate_option(option, &w_len_set) != EXIT_SUCCESS ||
                read_option_value(option, argc, argv, &i, &value) != EXIT_SUCCESS) {
                return EXIT_FAILURE;
            }

            if (parse_size_value(value, &config->w_len_bytes) != EXIT_SUCCESS) {
                fprintf(stderr, "Error: invalid value '%s' for '%s'.\n", value, option);
                return EXIT_FAILURE;
            }

            continue;
        }

        if (strcmp(option, "--ber") == 0) {
            if (reject_duplicate_option(option, &ber_set) != EXIT_SUCCESS ||
                read_option_value(option, argc, argv, &i, &value) != EXIT_SUCCESS) {
                return EXIT_FAILURE;
            }

            if (parse_double_value(value, &config->ber) != EXIT_SUCCESS) {
                fprintf(stderr, "Error: invalid value '%s' for '%s'.\n", value, option);
                return EXIT_FAILURE;
            }

            continue;
        }

        if (strcmp(option, "--trials") == 0) {
            if (reject_duplicate_option(option, &trials_set) != EXIT_SUCCESS ||
                read_option_value(option, argc, argv, &i, &value) != EXIT_SUCCESS) {
                return EXIT_FAILURE;
            }

            if (parse_size_value(value, &config->trials) != EXIT_SUCCESS) {
                fprintf(stderr, "Error: invalid value '%s' for '%s'.\n", value, option);
                return EXIT_FAILURE;
            }

            continue;
        }

        if (strcmp(option, "--locks-n") == 0) {
            if (reject_duplicate_option(option, &locks_n_set) != EXIT_SUCCESS ||
                read_option_value(option, argc, argv, &i, &value) != EXIT_SUCCESS) {
                return EXIT_FAILURE;
            }

            if (parse_size_value(value, &config->locks_n) != EXIT_SUCCESS) {
                fprintf(stderr, "Error: invalid value '%s' for '%s'.\n", value, option);
                return EXIT_FAILURE;
            }

            continue;
        }

        if (strcmp(option, "--xor-n") == 0) {
            if (reject_duplicate_option(option, &xor_n_set) != EXIT_SUCCESS ||
                read_option_value(option, argc, argv, &i, &value) != EXIT_SUCCESS) {
                return EXIT_FAILURE;
            }

            if (parse_size_value(value, &config->xor_n) != EXIT_SUCCESS) {
                fprintf(stderr, "Error: invalid value '%s' for '%s'.\n", value, option);
                return EXIT_FAILURE;
            }

            continue;
        }

        fprintf(stderr, "Error: unknown option '%s'.\n", option);
        return EXIT_FAILURE;
    }

    if (!impl_set) {
        fprintf(stderr, "Error: required option '--impl' is missing.\n");
        return EXIT_FAILURE;
    }

    if (!prng_set) {
        fprintf(stderr, "Error: required option '--prng' is missing.\n");
        return EXIT_FAILURE;
    }

    if (!w_len_set) {
        fprintf(stderr, "Error: required option '--w-len-bytes' is missing.\n");
        return EXIT_FAILURE;
    }

    if (!ber_set) {
        fprintf(stderr, "Error: required option '--ber' is missing.\n");
        return EXIT_FAILURE;
    }

    if (!trials_set) {
        fprintf(stderr, "Error: required option '--trials' is missing.\n");
        return EXIT_FAILURE;
    }

    if (!locks_n_set) {
        fprintf(stderr, "Error: required option '--locks-n' is missing.\n");
        return EXIT_FAILURE;
    }

    if (is_xlock_impl(config->impl) && !xor_n_set) {
        fprintf(stderr, "Error: XLOCK requires option '--xor-n'.\n");
        return EXIT_FAILURE;
    }

    return validate_config(config);
}

static void print_config(const app_config_t *config) {
    printf("impl              : %s\n", impl_name(config->impl));

    printf("prng              : %s\n", prng_name(config->prng));

    printf("w_len_bytes       : %zu\n", config->w_len_bytes);

    printf("ber               : %.3f %%\n", config->ber);

    printf("trials            : %zu\n", config->trials);

    printf("locks_n           : %zu\n", config->locks_n);

    if (is_xlock_impl(config->impl)) {
        printf("xor_n             : %zu\n", config->xor_n);
    }
}

static int buffers_init(experiment_buffers_t *buffers, size_t w_len_bytes, size_t key_len_bytes) {
    size_t key_storage_len = 0u;

    if (buffers == NULL) {
        return EXIT_FAILURE;
    }

    *buffers = (experiment_buffers_t){0};

    if (key_len_bytes > SIZE_MAX / 2u) {
        return EXIT_FAILURE;
    }

    key_storage_len = 2u * key_len_bytes;

    if (w_len_bytes > (SIZE_MAX - key_storage_len) / 2u) {
        return EXIT_FAILURE;
    }

    buffers->storage_len_bytes = 2u * w_len_bytes + key_storage_len;

    buffers->storage           = calloc(1u, buffers->storage_len_bytes);

    if (buffers->storage == NULL) {
        return EXIT_FAILURE;
    }

    buffers->w       = buffers->storage;

    buffers->w_noisy = buffers->w + w_len_bytes;

    buffers->key_gen = buffers->w_noisy + w_len_bytes;

    buffers->key_rep = buffers->key_gen + key_len_bytes;

    return EXIT_SUCCESS;
}

static void buffers_free(experiment_buffers_t *buffers) {
    if (buffers == NULL) {
        return;
    }

    secure_free(buffers->storage, buffers->storage_len_bytes);

    *buffers = (experiment_buffers_t){0};
}

static fuzzy_extractor_params_t *
build_params(const app_config_t *config, fuzzy_extractor_stl_params_t *stl_params,
             fuzzy_extractor_xlock_2024_params_t *xlock_2024_params,
             fuzzy_extractor_xlock_2026_params_t *xlock_2026_params) {
    const hash_alg_t *hash_alg                     = &hash_alg_sha_512;
    const hmac_alg_t *hmac_alg                     = &hmac_alg_sha_512;

    const size_t      key_len_bytes                = EXPERIMENT_KEY_LEN_BYTES;

    const size_t      nonce_len_bytes              = EXPERIMENT_NONCE_LEN_BYTES;

    const size_t      pool_len_bytes               = EXPERIMENT_POOL_LEN_BYTES;

    const size_t      key_pre_len_bytes            = EXPERIMENT_KEY_PRE_LEN_BYTES;

    const size_t      digital_locker_key_len_bytes = EXPERIMENT_DL_KEY_LEN_BYTES;

    const size_t      hmac_len_bytes               = hmac_digest_len_bytes(hmac_alg);

    const size_t      digital_locker_tag_len_bytes = hmac_len_bytes - key_len_bytes;

    if (config->impl == FUZZY_EXTRACTOR_IMPL_XLOCK_2024) {
        *xlock_2024_params = (fuzzy_extractor_xlock_2024_params_t){
            .common =
                {
                         .impl        = FUZZY_EXTRACTOR_IMPL_XLOCK_2024,
                         .w_len_bytes = config->w_len_bytes,
                         .prng        = config->prng,
                         },
            .pool_len_bytes    = pool_len_bytes,
            .key_pre_len_bytes = key_pre_len_bytes,
            .key_len_bytes     = key_len_bytes,
            .xor_n             = config->xor_n,
            .locks_n           = config->locks_n,
            .nonce_len_bytes   = nonce_len_bytes,
            .hmac_alg          = hmac_alg,
        };

        return (fuzzy_extractor_params_t *)xlock_2024_params;
    }

    if (config->impl == FUZZY_EXTRACTOR_IMPL_XLOCK_2026) {
        *xlock_2026_params = (fuzzy_extractor_xlock_2026_params_t){
            .common =
                {
                         .impl        = FUZZY_EXTRACTOR_IMPL_XLOCK_2026,
                         .w_len_bytes = config->w_len_bytes,
                         .prng        = config->prng,
                         },
            .pool_len_bytes    = pool_len_bytes,
            .key_pre_len_bytes = key_pre_len_bytes,
            .key_len_bytes     = key_len_bytes,
            .xor_n             = config->xor_n,
            .locks_n           = config->locks_n,
            .nonce_len_bytes   = nonce_len_bytes,
            .hmac_alg          = hmac_alg,
        };

        return (fuzzy_extractor_params_t *)xlock_2026_params;
    }

    *stl_params = (fuzzy_extractor_stl_params_t){
        .common =
            {
                     .impl        = FUZZY_EXTRACTOR_IMPL_STL,
                     .w_len_bytes = config->w_len_bytes,
                     .prng        = config->prng,
                     },
        .digital_locker_nonce_len_bytes = nonce_len_bytes,
        .digital_locker_tag_len_bytes   = digital_locker_tag_len_bytes,
        .digital_locker_key_len_bytes   = digital_locker_key_len_bytes,
        .locks_n                        = config->locks_n,
        .key_len_bytes                  = key_len_bytes,
        .hash_alg                       = hash_alg,
    };

    return (fuzzy_extractor_params_t *)stl_params;
}

static int run_experiment(const app_config_t *config) {
    int                                 ret               = EXIT_FAILURE;

    fuzzy_extractor_t                   fe                = {0};

    void                               *helper_data       = NULL;
    void                               *workspace         = NULL;

    fuzzy_extractor_stl_params_t        stl_params        = {0};
    fuzzy_extractor_xlock_2024_params_t xlock_2024_params = {0};
    fuzzy_extractor_xlock_2026_params_t xlock_2026_params = {0};

    experiment_buffers_t                buffers           = {0};

    const size_t                        key_len_bytes     = EXPERIMENT_KEY_LEN_BYTES;

    const size_t                        w_len_bits        = bits_from_bytes(config->w_len_bytes);

    const size_t bit_flips_n = (size_t)round((config->ber / 100.0) * (double)w_len_bits);

    printf("bit_flips/trial   : %zu\n\n", bit_flips_n);

    if (buffers_init(&buffers, config->w_len_bytes, key_len_bytes) != EXIT_SUCCESS) {
        printf("[err] alloc: experiment buffers\n");
        goto cleanup;
    }

    fuzzy_extractor_key_t key_gen = {
        .data      = buffers.key_gen,
        .len_bytes = key_len_bytes,
    };

    fuzzy_extractor_key_t key_rep = {
        .data      = buffers.key_rep,
        .len_bytes = key_len_bytes,
    };

    fuzzy_extractor_params_t *params =
        build_params(config, &stl_params, &xlock_2024_params, &xlock_2026_params);

    fuzzy_extractor_status_t fe_status = fuzzy_extractor_init(&fe, params);

    if (fe_status != FUZZY_EXTRACTOR_OK) {
        printf("[err] fuzzy_extractor_init: %s (%d)\n", fuzzy_extractor_status_string(fe_status),
               fe_status);
        goto cleanup;
    }

    helper_data = fuzzy_extractor_helper_data_create(&fe);

    if (helper_data == NULL) {
        printf("[err] alloc: helper data\n");
        goto cleanup;
    }

    workspace = fuzzy_extractor_workspace_create(&fe);

    if (workspace == NULL) {
        printf("[err] alloc: workspace\n");
        goto cleanup;
    }

    rng_status_t rng_status = random_bytes(buffers.w, config->w_len_bytes);

    if (rng_status != RNG_OK) {
        printf("[err] random_bytes: %s (%d)\n", rng_status_string(rng_status), rng_status);
        goto cleanup;
    }

    fe_status = fuzzy_extractor_generate(&fe, workspace, buffers.w, config->w_len_bytes,
                                         helper_data, &key_gen);

    if (fe_status != FUZZY_EXTRACTOR_OK) {
        printf("[err] fuzzy_extractor_generate: %s (%d)\n",
               fuzzy_extractor_status_string(fe_status), fe_status);
        goto cleanup;
    }

#ifdef DEBUG
    LOG_HEX(key_gen.data, key_gen.len_bytes, "gen key");
#endif

    size_t success_n            = 0u;
    size_t reproduction_error_n = 0u;

    double input_hd_sum         = 0.0;

    for (size_t trial = 0u; trial < config->trials; ++trial) {
        memcpy(buffers.w_noisy, buffers.w, config->w_len_bytes);

        secure_bzero(key_rep.data, key_rep.len_bytes);

        rng_status = sample_flip_bits(config->prng, SAMPLE_MODE_WITHOUT_REPLACEMENT,
                                      buffers.w_noisy, config->w_len_bytes, bit_flips_n, NULL);

        if (rng_status != RNG_OK) {
            printf("[err] sample_flip_bits failed "
                   "during trial %zu: %d\n",
                   trial, rng_status);
            goto cleanup;
        }

        const int input_hd = bits_hamming_distance(buffers.w, buffers.w_noisy, config->w_len_bytes);

        if (input_hd < 0) {
            printf("[err] hamming_distance failed "
                   "during trial %zu\n",
                   trial);
            goto cleanup;
        }

        if ((size_t)input_hd != bit_flips_n) {
            printf("[err] unexpected input Hamming distance "
                   "during trial %zu: expected %zu, got %d\n",
                   trial, bit_flips_n, input_hd);
            goto cleanup;
        }

        input_hd_sum += (double)input_hd;

        fe_status = fuzzy_extractor_reproduce(&fe, workspace, buffers.w_noisy, config->w_len_bytes,
                                              helper_data, &key_rep);

        if (fe_status != FUZZY_EXTRACTOR_OK) {
            reproduction_error_n++;
            continue;
        }

        if (secure_memcmp(key_gen.data, key_rep.data, key_len_bytes) != 0) {
            continue;
        }

        success_n++;
    }

    const double trials_d = (double)config->trials;

    printf("successes         : %zu / %zu (%.3f %%)\n", success_n, config->trials,
           100.0 * (double)success_n / trials_d);

    printf("reproduce errors  : %zu / %zu (%.3f %%)\n", reproduction_error_n, config->trials,
           100.0 * (double)reproduction_error_n / trials_d);

    printf("avg input HD      : %.3f bits\n", input_hd_sum / trials_d);

    ret = EXIT_SUCCESS;

cleanup:
    if (workspace != NULL) {
        fuzzy_extractor_workspace_destroy(&fe, workspace);
    }

    if (helper_data != NULL) {
        fuzzy_extractor_helper_data_destroy(&fe, helper_data);
    }

    fuzzy_extractor_destroy(&fe);
    buffers_free(&buffers);

    return ret;
}

int main(int argc, char **argv) {
    app_config_t config = {0};

    if (parse_config(&config, argc, argv) != EXIT_SUCCESS) {
        fprintf(stderr, "Use '%s --help' for usage information.\n", argv[0]);
        return EXIT_FAILURE;
    }

    print_config(&config);

    return run_experiment(&config);
}
