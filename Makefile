VERSION := $(shell cat ./VERSION)
CARGO ?= cargo
WWW_PORT ?= 3000

.PHONY: build build-wasm prebaked-build www www-proxy

build: build-wasm
	$(CARGO) build -p cli --bin blackwall

build-wasm:
	make -C ./challenge-wasm build

prebaked-build:
	B7L_VERSION="$(VERSION)" $(CARGO) build -p cli --bin blackwall --release

www: # TODO: replace with proper web servers: http and unix sockets. Check Anubis for reference.
	@ python3 -m http.server $(WWW_PORT) --directory test/shared/www

www-proxy:
	set -a \
	&& . run/default.env \
	&& $(CARGO) run --verbose -p cli --bin blackwall
