
#include "combiner.h"
#include "common.h"
#include "hash.h"
#include "mod.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef ESP_PLATFORM
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#else
#include "tictoc.h"
#endif

typedef struct {
    unsigned int attempts;
    size_t       n;
    size_t       m;
    size_t       t;
    unsigned int strategy;
} experiment_config_t;

static void print_usage(const char *program) {
    printf("Usage:\n");
    printf("  %s [options]\n", program);

    printf("\nOptions:\n");
    printf("  --strategy <name>  Reconstruction strategy:\n");
    printf("                     hashing, enumeration, berlekamp-welch\n");
    printf("  --trials <n>       Number of trials (default: %u)\n", (unsigned int)NUM_ATTEMPTS);
    printf("  --n <n>            Number of PUF candidates (default: %d)\n", N);
    printf("  --m <n>            Number of additional points (default: %d)\n", M);
    printf("  --t <n>            Number of faulty candidates (default: %d)\n", T);
    printf("  -h, --help         Display this help message\n");

    printf("\nExample:\n");
    printf("  %s --strategy hashing --trials 1000 --n 5 --m 2 --t 1\n", program);
}

static int parse_number(const char *value, size_t *result) {
    char              *end = NULL;
    unsigned long long number;

    if (value == NULL || value[0] == '\0' || value[0] == '-') {
        return -1;
    }

    errno  = 0;
    number = strtoull(value, &end, 10);

    if (errno == ERANGE || end == value || *end != '\0' || number > SIZE_MAX) {
        return -1;
    }

    *result = (size_t)number;
    return 0;
}

static int parse_strategy(const char *value, unsigned int *strategy) {
    if (strcmp(value, "hashing") == 0) {
        *strategy = STRAT_HASHING;
    } else if (strcmp(value, "enumeration") == 0) {
        *strategy = STRAT_ENUMERATION;
    } else if (strcmp(value, "berlekamp-welch") == 0) {
        *strategy = STRAT_BERLEKAMP_WELCH;
    } else {
        return -1;
    }

    return 0;
}

static int parse_config(int argc, char **argv, experiment_config_t *config) {
    *config = (experiment_config_t){NUM_ATTEMPTS, N, M, T, STRAT_HASHING};

    for (int i = 1; i < argc; ++i) {
        const char *option = argv[i];

        if (strcmp(option, "-h") == 0 || strcmp(option, "--help") == 0) {
            print_usage(argv[0]);
            return 1;
        }

        if (strcmp(option, "--strategy") != 0 && strcmp(option, "--trials") != 0 &&
            strcmp(option, "--n") != 0 && strcmp(option, "--m") != 0 &&
            strcmp(option, "--t") != 0) {
            fprintf(stderr, "Error: unknown option '%s'.\n", option);
            return -1;
        }

        if (i + 1 >= argc) {
            fprintf(stderr, "Error: missing value for '%s'.\n", option);
            return -1;
        }

        const char *value = argv[++i];

        if (strcmp(option, "--strategy") == 0) {
            if (parse_strategy(value, &config->strategy) != 0) {
                fprintf(stderr, "Error: unknown strategy '%s'.\n", value);
                return -1;
            }
            continue;
        }

        size_t parsed;

        if (parse_number(value, &parsed) != 0) {
            fprintf(stderr, "Error: invalid value '%s'.\n", value);
            return -1;
        }

        if (strcmp(option, "--trials") == 0) {
            if (parsed > UINT_MAX) {
                fprintf(stderr, "Error: too many trials.\n");
                return -1;
            }
            config->attempts = (unsigned int)parsed;
        } else if (strcmp(option, "--n") == 0) {
            config->n = parsed;
        } else if (strcmp(option, "--m") == 0) {
            config->m = parsed;
        } else if (strcmp(option, "--t") == 0) {
            config->t = parsed;
        }
    }

    if (config->attempts == 0 || config->n == 0 || config->t > config->n ||
        config->n > (size_t)(sizeof(unsigned int) * CHAR_BIT - 2) ||
        config->m > SIZE_MAX - config->n || config->n + config->m >= P ||
        config->n + config->m > 256 ||
        (config->strategy == STRAT_ENUMERATION && config->m > config->n)) {
        fprintf(stderr, "Error: invalid experimental parameters.\n");
        return -1;
    }

    return 0;
}

typedef int (*enroll_fn_t)(size_t, size_t, unsigned long long, struct point_t *,
                           unsigned long long *, unsigned char *, unsigned char *);

typedef int (*reconstruct_fn_t)(size_t, size_t, unsigned long long, struct point_t *,
                                unsigned long long *, unsigned char *, unsigned int *,
                                unsigned char *);

static int enroll_no_hashes(size_t n, size_t m, unsigned long long p, struct point_t *points,
                            unsigned long long *sk, unsigned char *sk_hash, unsigned char *hashes) {
    (void)hashes;
    return enroll_enumeration(n, m, p, points, sk, sk_hash);
}

static int reconstruct_no_hashes(size_t n, size_t m, unsigned long long p, struct point_t *points,
                                 unsigned long long *sk, unsigned char *sk_hash,
                                 unsigned int *faulty, unsigned char *hashes) {
    (void)hashes;
    return reconstruct_enumeration(n, m, p, points, sk, sk_hash, faulty);
}

static int enroll_bw(size_t n, size_t m, unsigned long long p, struct point_t *points,
                     unsigned long long *sk, unsigned char *sk_hash, unsigned char *hashes) {
    (void)hashes;
    return enroll_berlekamp_welch(n, m, p, points, sk, sk_hash);
}

static int reconstruct_bw(size_t n, size_t m, unsigned long long p, struct point_t *points,
                          unsigned long long *sk, unsigned char *sk_hash, unsigned int *faulty,
                          unsigned char *hashes) {
    (void)hashes;
    return reconstruct_berlekamp_welch(n, m, p, points, sk, sk_hash, faulty);
}

static void corrupt_points(size_t n, size_t t, struct point_t *points) {
    size_t indexes[n];

    for (size_t i = 0; i < n; ++i) {
        indexes[i] = i;
    }

    /* Fisher--Yates shuffle. */
    for (size_t i = n; i > 1; --i) {
        size_t j       = (size_t)(unsigned int)rand() % i;
        size_t tmp     = indexes[i - 1];

        indexes[i - 1] = indexes[j];
        indexes[j]     = tmp;
    }

    for (size_t i = 0; i < t; ++i) {
        points[indexes[i]].y = (unsigned long long)(unsigned int)rand();
    }
}

static void test_combiner(const experiment_config_t *config) {
    const size_t             n                = config->n;
    const size_t             m                = config->m;
    const size_t             t                = config->t;
    const unsigned int       attempts         = config->attempts;
    const unsigned long long p                = P;

    unsigned int             errors           = 0;
    long long                time_enroll      = 0;
    long long                time_reconstruct = 0;

    struct point_t           ok_points[n + m];
    struct point_t           ko_points[n + m];

    unsigned char            sk_hash[HASH_BYTES];
    unsigned char            hashes[n * HASH_BYTES];

    enroll_fn_t              enroll      = enroll_hashing;
    reconstruct_fn_t         reconstruct = reconstruct_hashing;

    if (config->strategy == STRAT_ENUMERATION) {
        enroll      = enroll_no_hashes;
        reconstruct = reconstruct_no_hashes;
    } else if (config->strategy == STRAT_BERLEKAMP_WELCH) {
        enroll      = enroll_bw;
        reconstruct = reconstruct_bw;
    }

#ifdef ESP_PLATFORM
    srand((unsigned int)esp_random());
#else
    struct ru_timer ru;
    srand((unsigned int)time(NULL));
#endif

    for (unsigned int i = 0; i < attempts; ++i) {
        unsigned long long sk_enroll      = 0;
        unsigned long long sk_reconstruct = 0;
        unsigned int       faulty_points  = 0;
        int                status;
        long long          elapsed;

        for (size_t j = 0; j < n + m; ++j) {
            ok_points[j].x = mod_add((unsigned long long)j, 1, p);
            ok_points[j].y = mod_norm((unsigned long long)(unsigned int)rand(), p);
        }

#ifdef ESP_PLATFORM
        long long start = esp_timer_get_time();
#else
        RU_TIC(ru);
#endif

        status = enroll(n, m, p, ok_points, &sk_enroll, sk_hash, hashes);

#ifdef ESP_PLATFORM
        elapsed = esp_timer_get_time() - start;
#else
        RU_TOC(ru);
        elapsed = RU_TIC_TOC(ru);
#endif

        time_enroll += elapsed;

        if (status != 0) {
            ++errors;
            continue;
        }

        for (size_t j = 0; j < n + m; ++j) {
            ko_points[j] = ok_points[j];
        }

        corrupt_points(n, t, ko_points);

#ifdef ESP_PLATFORM
        start = esp_timer_get_time();
#else
        RU_TIC(ru);
#endif

        status = reconstruct(n, m, p, ko_points, &sk_reconstruct, sk_hash, &faulty_points, hashes);

#ifdef ESP_PLATFORM
        elapsed = esp_timer_get_time() - start;

        if (i % 75 == 0) {
            vTaskDelay(1);
        }
#else
        RU_TOC(ru);
        elapsed = RU_TIC_TOC(ru);
#endif

        time_reconstruct += elapsed;

        if (status != 0 || sk_reconstruct != sk_enroll) {
            ++errors;
        }
    }

    printf("%zu,%zu,%zu,%lld,%lld,%u,%u\n", n, m, t, time_enroll, time_reconstruct, errors,
           attempts);
}

int main(int argc, char **argv) {
    experiment_config_t config;

#ifndef ESP_PLATFORM
    int result = parse_config(argc, argv, &config);

    if (result > 0) {
        return EXIT_SUCCESS;
    }

    if (result < 0) {
        fprintf(stderr, "Use '%s --help' for usage information.\n", argv[0]);
        return EXIT_FAILURE;
    }
#else
    (void)argc;
    (void)argv;

    config = (experiment_config_t){NUM_ATTEMPTS, N, M, T, STRAT_HASHING};
#endif

    test_combiner(&config);
    return EXIT_SUCCESS;
}
