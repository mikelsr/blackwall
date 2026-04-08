VERSION := $(shell cat ./VERSION)
CARGO ?= cargo
WWW_PORT ?= 3000

.PHONY: build prebaked-build www www-proxy

build:
	$(CARGO) build -p cli --bin blackwall

prebaked-build:
	B7L_VERSION="$(VERSION)" $(CARGO) build -p cli --bin blackwall --release

www: # TODO: replace with proper web servers: http and unix sockets. Check Anubis for reference.
	@ python3 -m http.server $(WWW_PORT) --directory test/shared/www

www-proxy:
	set -a \
	&& . run/default.env \
	&& $(CARGO) run --verbose -p cli --bin blackwall
