
CC ?= cc

# Directories and files
INCDIR := include
SRCDIR := src
APPDIR := app/experiment
BUILDDIR := build
BINDIR := bin

TARGET := $(BINDIR)/experiment
SRC := $(shell find $(SRCDIR) $(APPDIR) -type f -name '*.c' | sort)
OBJ := $(patsubst %.c,$(BUILDDIR)/%.o,$(SRC))
DEP := $(OBJ:.o=.d)

FORMAT_FILES := $(shell find $(INCDIR) $(SRCDIR) $(APPDIR) \
	-type f \( -name '*.c' -o -name '*.h' \) | sort)

# Tools
CLANG_FORMAT ?= $(shell \
	command -v clang-format 2>/dev/null || \
	command -v clang-format-20 2>/dev/null || \
	command -v clang-format-19 2>/dev/null || \
	command -v clang-format-18 2>/dev/null || \
	command -v clang-format-17 2>/dev/null || \
	command -v clang-format-16 2>/dev/null || \
	command -v clang-format-15 2>/dev/null || \
	command -v clang-format-14 2>/dev/null)

# Compiler and linker flags
WARNFLAGS := \
	-Wall \
	-Wextra \
	-Wpedantic \
	-Wconversion \
	-Wshadow \
	-Wstrict-prototypes \
	-Wformat=2 \
	-Wundef

ifeq ($(WERROR),1)
WARNFLAGS += -Werror
endif

PROJECT_CPPFLAGS := -I$(INCDIR) -I$(SRCDIR) -I$(APPDIR)
PROJECT_CFLAGS := -std=c11 $(WARNFLAGS)

OPTFLAGS ?= -O2
LDLIBS ?= -lcrypto -lm

# Execution and test parameters
RUN_ARGS ?= --help

CHECK_ARGS_XLOCK_2024 ?= \
	--impl xlock-2024 \
	--prng xorshift32 \
	--w-len-bytes 1024 \
	--ber 7.5 \
	--trials 1000 \
	--locks-n 21 \
	--xor-n 3

CHECK_ARGS_XLOCK_2026 ?= \
	--impl xlock-2026 \
	--prng xorshift32 \
	--w-len-bytes 1024 \
	--ber 7.5 \
	--trials 1000 \
	--locks-n 21 \
	--xor-n 3

CHECK_ARGS_STL ?= \
	--impl stl \
	--prng xorshift32 \
	--w-len-bytes 1024 \
	--ber 2.5 \
	--trials 1000 \
	--locks-n 51

.DEFAULT_GOAL := all

# Build targets
all: release

release: CFLAGS += $(OPTFLAGS) -DNDEBUG
release: $(TARGET)

debug: CFLAGS += -g3 -Og -DDEBUG
debug: $(TARGET)

asan: CFLAGS += -g -O1 -fsanitize=address,undefined \
	-fno-omit-frame-pointer
asan: LDFLAGS += -fsanitize=address,undefined
asan: $(TARGET)

# Tests
check: asan
	@echo 'Checking X-Lock (2024)'
	./$(TARGET) $(CHECK_ARGS_XLOCK_2024)
	@echo 'Checking X-Lock (2026)'
	./$(TARGET) $(CHECK_ARGS_XLOCK_2026)
	@echo 'Checking Sample-then-Lock'
	./$(TARGET) $(CHECK_ARGS_STL)

# Execution
run: release
	./$(TARGET) $(RUN_ARGS)

# Formatting
format:
	@if [ -z "$(CLANG_FORMAT)" ]; then \
		echo "Error: clang-format not found."; \
		exit 1; \
	fi
	$(CLANG_FORMAT) -i $(FORMAT_FILES)

format-check:
	@if [ -z "$(CLANG_FORMAT)" ]; then \
		echo "Error: clang-format not found."; \
		exit 1; \
	fi
	$(CLANG_FORMAT) --dry-run --Werror $(FORMAT_FILES)

# Build configuration tracking
.PHONY: FORCE

$(BUILDDIR)/.build-config: FORCE
	@mkdir -p $(BUILDDIR)
	@printf '%s\n' '$(CC)|$(PROJECT_CPPFLAGS)|$(CPPFLAGS)|$(PROJECT_CFLAGS)|$(CFLAGS)|$(LDFLAGS)|$(LDLIBS)' > $@.tmp
	@if cmp -s $@.tmp $@; then \
		rm -f $@.tmp; \
	else \
		mv -f $@.tmp $@; \
	fi

$(OBJ): $(BUILDDIR)/.build-config

# Compilation and linking
$(TARGET): $(OBJ) | $(BINDIR)
	$(CC) $(LDFLAGS) $(OBJ) -o $@ $(LDLIBS)

$(BUILDDIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(PROJECT_CPPFLAGS) $(CPPFLAGS) \
		$(PROJECT_CFLAGS) $(CFLAGS) \
		-MMD -MP -c $< -o $@

$(BINDIR):
	mkdir -p $@

# Maintenance
clean:
	rm -rf $(BUILDDIR) $(BINDIR)

help:
	@printf '%s\n' \
		'Targets: all, release, debug, asan, check, run, format, format-check, clean, help' \
		'Run: make run RUN_ARGS="--impl xlock-2024 --trials 100"' \
		'Options: CC=..., OPTFLAGS=..., WERROR=1, CLANG_FORMAT=...'

-include $(DEP)

.PHONY: all release debug asan check run format format-check clean help
