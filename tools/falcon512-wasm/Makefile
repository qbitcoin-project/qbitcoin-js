# Falcon-512 WASM build.
#
# Compiles PQClean's Falcon-512 clean variant + our shim.c into a
# WebAssembly module that exports `wallet_falcon512_*` functions.
#
# Run via:
#   make            # builds out/falcon512.{wasm,mjs}
#   make install    # copies to ../../packages/crypto/wasm/
#   make clean      # removes build artifacts

# ─── Configuration ───────────────────────────────────────────────────

EMCC ?= emcc

PQCLEAN_SRC := pqclean-src
COMMON_DIR  := $(PQCLEAN_SRC)/common
FALCON_DIR  := $(PQCLEAN_SRC)/falcon-512

OUT_DIR     := out
OUT_NAME    := falcon512
DEST_DIR    := ../../packages/crypto/wasm

# ─── Source files ────────────────────────────────────────────────────

# PQClean Falcon-512 clean implementation.
FALCON_SOURCES := \
  $(FALCON_DIR)/codec.c \
  $(FALCON_DIR)/common.c \
  $(FALCON_DIR)/fft.c \
  $(FALCON_DIR)/fpr.c \
  $(FALCON_DIR)/keygen.c \
  $(FALCON_DIR)/pqclean.c \
  $(FALCON_DIR)/rng.c \
  $(FALCON_DIR)/sign.c \
  $(FALCON_DIR)/vrfy.c

# PQClean common — SHA-3/SHAKE used by Falcon.
# Note: randombytes.c is REMOVED by fetch-pqclean.sh; shim.c provides
# our own implementation.
COMMON_SOURCES := \
  $(COMMON_DIR)/fips202.c

SOURCES := shim.c $(FALCON_SOURCES) $(COMMON_SOURCES)

# ─── Compiler flags ──────────────────────────────────────────────────

INCLUDES := -I$(COMMON_DIR) -I$(FALCON_DIR)

CFLAGS := \
  -O3 -flto \
  -Wall -Wextra \
  $(INCLUDES) \
  -DPQCLEAN_FALCON512_CLEAN

# Functions visible from JS.
EXPORTED_FUNCTIONS := \
  _wallet_falcon512_keygen_from_seed \
  _wallet_falcon512_sign_detached \
  _wallet_falcon512_verify \
  _wallet_falcon512_pubkey_bytes \
  _wallet_falcon512_privkey_bytes \
  _wallet_falcon512_sig_max_bytes \
  _wallet_falcon512_seed_bytes \
  _malloc _free

# Comma-separated single-quoted form Emscripten wants.
EMPTY :=
SPACE := $(EMPTY) $(EMPTY)
EXPORTED_QUOTED := $(subst $(SPACE),$(EMPTY),$(foreach f,$(EXPORTED_FUNCTIONS),"$(f)",))
EXPORTED_LIST := [$(EXPORTED_QUOTED:%,=%)]

LDFLAGS := \
  -O3 -flto \
  -sWASM=1 \
  -sMODULARIZE=1 \
  -sEXPORT_ES6=1 \
  -sENVIRONMENT='web,worker' \
  -sINITIAL_MEMORY=4MB \
  -sSTACK_SIZE=128KB \
  -sALLOW_MEMORY_GROWTH=1 \
  -sEXPORTED_FUNCTIONS='$(EXPORTED_LIST)' \
  -sEXPORTED_RUNTIME_METHODS='["HEAPU8"]' \
  -sFILESYSTEM=0 \
  -sASSERTIONS=0 \
  --no-entry

# ─── Targets ─────────────────────────────────────────────────────────

.PHONY: all install clean check-deps

all: $(OUT_DIR)/$(OUT_NAME).wasm

$(OUT_DIR)/$(OUT_NAME).wasm: check-deps $(SOURCES)
	@mkdir -p $(OUT_DIR)
	$(EMCC) $(CFLAGS) $(SOURCES) $(LDFLAGS) -o $(OUT_DIR)/$(OUT_NAME).mjs
	@echo
	@echo "Built:"
	@ls -lh $(OUT_DIR)/$(OUT_NAME).wasm $(OUT_DIR)/$(OUT_NAME).mjs

check-deps:
	@if [ ! -d "$(PQCLEAN_SRC)" ]; then \
	  echo "PQClean source not found at $(PQCLEAN_SRC)/"; \
	  echo "Run ./fetch-pqclean.sh first."; \
	  exit 1; \
	fi
	@if ! command -v $(EMCC) >/dev/null 2>&1; then \
	  echo "emcc not in PATH. Install Emscripten, or use ./build.sh (Docker)."; \
	  exit 1; \
	fi

install: all
	@mkdir -p $(DEST_DIR)
	cp $(OUT_DIR)/$(OUT_NAME).wasm $(DEST_DIR)/
	cp $(OUT_DIR)/$(OUT_NAME).mjs  $(DEST_DIR)/
	@echo
	@echo "Installed to $(DEST_DIR)/"
	@sha256sum $(DEST_DIR)/$(OUT_NAME).wasm

clean:
	rm -rf $(OUT_DIR)
