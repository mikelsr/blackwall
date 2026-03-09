WASM_PACK ?= wasm-pack
TWIGGY ?= twiggy
WASM_OPT ?= wasm-opt
TARGET ?= web
OUT_DIR ?= pkg
CARGO_TARGET_DIR ?= target
WASM_FILE := $(OUT_DIR)/challenge_wasm_bg.wasm

build:
	CARGO_TARGET_DIR=$(CARGO_TARGET_DIR) \
	CARGO_PROFILE_RELEASE_OPT_LEVEL=3 \
	CARGO_PROFILE_RELEASE_LTO=thin \
	CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
	CARGO_PROFILE_RELEASE_PANIC=abort \
	CARGO_PROFILE_RELEASE_STRIP=symbols \
	$(WASM_PACK) build --target $(TARGET) --release --no-opt --out-dir $(OUT_DIR)
