# Host-side unit tests (TZ 13). Builds the platform-independent core with gcc
# and runs it natively - no ESP32 hardware required.
#
#   make            build + run every suite
#   make V=1        verbose
#   make asan       build with AddressSanitizer + UBSan
#   make <suite>    run a single suite, e.g. `make test_mnemonic`

CC      ?= gcc
ROOT    := ..
# The sources live in the Arduino sketch folder (the sketch must carry its
# own src/ so the IDE compiles it).
SRC     := $(ROOT)/MoneroColdWallet/src

# Sanitizer and plain builds MUST NOT share an object directory: now that
# CORE_OBJ survives a run (see .SECONDARY below), a plain `make run` after a
# `make asan` would otherwise relink stale instrumented objects and fail on
# __asan_* / __ubsan_* being undefined.
BUILD   := build$(if $(filter 1,$(ASAN)),-asan,)

CFLAGS  := -std=c11 -Wall -Wextra -Wno-unused-parameter -O2 -g \
           -I$(SRC) -I$(ROOT)/test -DMW_HOST_BUILD=1
LDFLAGS :=

ifeq ($(ASAN),1)
CFLAGS  += -fsanitize=address,undefined -fno-omit-frame-pointer -O1
LDFLAGS += -fsanitize=address,undefined
endif

# Everything the host build can compile: the platform-independent core plus
# the host HAL stub, which resolves the mw_hal_*/mw_sd_*/mw_camera_* symbols
# that transfer/ calls. The device-only .cpp files are never listed here.
#
# Keep this as plain wildcards over whole directories and let `sort` dedupe -
# listing an individual file as well as its directory silently produces a
# "multiple definition" link error.
CORE_SRC := $(sort $(wildcard $(SRC)/crypto/*.c) \
                   $(wildcard $(SRC)/monero/*.c) \
                   $(wildcard $(SRC)/data/*.c) \
                   $(wildcard $(SRC)/wallet/*.c) \
                   $(wildcard $(SRC)/transfer/*.c) \
                   $(SRC)/hal/hal_host.c \
                   $(SRC)/hal/log.c \
                   $(wildcard $(SRC)/hal/touch_map.c) \
                   $(wildcard $(SRC)/ui/game_model.c))

CORE_OBJ := $(patsubst $(ROOT)/%.c,$(BUILD)/%.o,$(CORE_SRC))

SUITES   := $(basename $(notdir $(wildcard test_*.c)))
SUITES   := $(filter-out test_framework,$(SUITES))
BINS     := $(addprefix $(BUILD)/,$(SUITES))

.PHONY: all run clean asan $(SUITES)

# CORE_OBJ are only ever made by a pattern rule and only ever consumed as
# prerequisites, which makes them "intermediate": make deletes them at the end
# of a run, so the NEXT `make run` fails with "cannot find build/src/...".
.SECONDARY: $(CORE_OBJ)

all: run

$(BUILD)/%.o: $(ROOT)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_framework.o: test_framework.c
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/%: %.c $(CORE_OBJ) $(BUILD)/test_framework.o
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $< $(CORE_OBJ) $(BUILD)/test_framework.o -o $@ $(LDFLAGS)

run: $(BINS)
	@fail=0; \
	for b in $(BINS); do \
	  echo "=== $$b ==="; \
	  $$b || fail=1; \
	done; \
	if [ $$fail -ne 0 ]; then echo "SUITES FAILED"; exit 1; fi; \
	echo "ALL SUITES PASSED"

$(SUITES): %: $(BUILD)/%
	@$(BUILD)/$@

asan:
	@$(MAKE) ASAN=1 run

clean:
	rm -rf build build-asan

# Static frame sizes of the core (bug 4: crypto task stack overflow). Builds
# every core file with -Os -fstack-usage, using the 32-bit compiler when there
# is one (its type sizes match the ESP32's), and lists frames over 6 KiB.
# Informational only; not part of `run`.
STACK_CC    := $(if $(shell command -v i686-w64-mingw32-gcc 2>/dev/null),i686-w64-mingw32-gcc,$(CC))
STACK_DIR   := build-stackcheck
STACK_LIMIT := 6144

.PHONY: stackcheck
stackcheck:
	@rm -rf $(STACK_DIR); mkdir -p $(STACK_DIR)
	@for f in $(CORE_SRC); do \
	  o=$(STACK_DIR)/$$(basename $$f .c).o; \
	  $(STACK_CC) -std=c11 -Os -fstack-usage -I$(SRC) -I$(ROOT)/test -DMW_HOST_BUILD=1 \
	    -c $$f -o $$o || exit 1; \
	done
	@echo "frames over $(STACK_LIMIT) B ($(STACK_CC) -Os):"
	@cat $(STACK_DIR)/*.su | awk -F'\t' '$$2 + 0 > $(STACK_LIMIT) { print "  " $$2 "\t" $$1 }' \
	  | sort -rn; true
