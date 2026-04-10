WASM_PACK ?= wasm-pack
TWIGGY ?= twiggy
WASM_OPT ?= wasm-opt
TARGET ?= web
OUT_DIR ?= pkg
CARGO_TARGET_DIR ?= target
MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
WASM_FILE := $(OUT_DIR)/challenge_wasm_bg.wasm

.PHONY: install test build build-wasm compress-wasm stats twiggy

install:
	rustup target add wasm32-unknown-unknown
	cargo install wasm-opt --locked
	cargo install twiggy

test: build
	@ # There are no manual tests, but there is a neat little web page.
	@ echo "Access the web page at http://localhost:9999/www/index.html"
	@ python3 -m http.server 9999 --directory $(MAKEFILE_DIR)

build: build-wasm compress-wasm

build-wasm:
	CARGO_TARGET_DIR=$(CARGO_TARGET_DIR) \
	CARGO_PROFILE_RELEASE_OPT_LEVEL=3 \
	CARGO_PROFILE_RELEASE_LTO=thin \
	CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
	CARGO_PROFILE_RELEASE_PANIC=abort \
	CARGO_PROFILE_RELEASE_STRIP=symbols \
	$(WASM_PACK) build --target $(TARGET) --release --no-opt --out-dir $(OUT_DIR)

compress-wasm:
	@if command -v $(WASM_OPT) >/dev/null 2>&1; then \
	    $(WASM_OPT) -Oz --enable-bulk-memory --strip-debug --strip-producers $(WASM_FILE) -o $(WASM_FILE); \
	else \
		echo "wasm-opt not found on PATH"; \
		echo "set WASM_OPT=/absolute/path/to/wasm-opt or install binaryen"; \
	fi
	gzip -9 -f -k $(WASM_FILE)
	brotli -f -k -q 11 $(WASM_FILE)
	zstd -f -k --ultra -22 $(WASM_FILE)

stats:
	@if [ ! -f "$(WASM_FILE)" ]; then echo "missing $(WASM_FILE) (run: make build)"; exit 1; fi
	@echo "raw bytes:" && wc -c $(WASM_FILE)
	@echo "gzip bytes:" && gzip -9 -c $(WASM_FILE) | wc -c
	@if command -v brotli >/dev/null 2>&1; then \
		echo "brotli bytes:" && brotli -f -q 11 -c $(WASM_FILE) | wc -c; \
	else \
		echo "brotli bytes: brotli not found"; \
	fi

twiggy:
	@if ! command -v $(TWIGGY) >/dev/null 2>&1; then echo "twiggy not found"; exit 1; fi
	@if [ -f "$(WASM_FILE)" ]; then \
		echo "analyzing $(WASM_FILE)"; \
		$(TWIGGY) top -n 30 $(WASM_FILE); \
	else \
		echo "missing $(WASM_FILE) (run: make build)"; \
		exit 1; \
	fi
