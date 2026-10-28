
FE_DIR := fuzzy-extractors
COMBINER_DIR := puf-combiner

FE_ARGS ?= --help
COMBINER_ARGS ?= --help

.DEFAULT_GOAL := all

all: release

# Build, checks, formatting, and cleanup.
release debug asan check format format-check clean:
	$(MAKE) -C $(FE_DIR) $@
	$(MAKE) -C $(COMBINER_DIR) $@

# Run each experimental application independently.
run-fe:
	$(MAKE) -C $(FE_DIR) run RUN_ARGS="$(FE_ARGS)"

run-combiner:
	$(MAKE) -C $(COMBINER_DIR) run RUN_ARGS="$(COMBINER_ARGS)"

help:
	@printf '%s\n' \
		'Targets:' \
		'  make                 Build both projects (release)' \
		'  make release         Build both projects (release)' \
		'  make debug           Build both projects (debug)' \
		'  make asan            Build both projects with sanitisers' \
		'  make check           Run the checks for both projects' \
		'  make format          Format C sources in both projects' \
		'  make format-check    Check formatting without changing files' \
		'  make clean           Remove generated files from both projects' \
		'  make run-fe FE_ARGS="--help"' \
		'  make run-combiner COMBINER_ARGS="--help"' \
		'' \
		'Build options (passed to both projects): CC=..., WERROR=1, CLANG_FORMAT=...'

.PHONY: all release debug asan check format format-check clean run-fe run-combiner help
