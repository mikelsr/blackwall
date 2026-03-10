VERSION := $(shell cat ./VERSION)
CARGO ?= cargo

.PHONY: build prebaked-build

build:
	$(CARGO) build -p cli --bin blackwall

prebaked-build:
	B7L_VERSION="$(VERSION)" $(CARGO) build -p cli --bin blackwall --release

www: # TODO: replace with proper web servers: http and unix sockets. Check Anubis for reference.
	@ python3 -m http.server 3923 --directory test/shared/www
