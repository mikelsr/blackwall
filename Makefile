VERSION := $(shell cat ./VERSION)
CARGO ?= cargo
WWW_PORT ?= 3923
PROXY_PORT ?= 8923

.PHONY: build prebaked-build www www-proxy

build:
	$(CARGO) build -p cli --bin blackwall

prebaked-build:
	B7L_VERSION="$(VERSION)" $(CARGO) build -p cli --bin blackwall --release

www: # TODO: replace with proper web servers: http and unix sockets. Check Anubis for reference.
	@ python3 -m http.server $(WWW_PORT) --directory test/shared/www

www-proxy:
	$(CARGO) run -p cli --bin blackwall -- \
		--bind 127.0.0.1:$(PROXY_PORT) \
		--target http://127.0.0.1:$(WWW_PORT)
