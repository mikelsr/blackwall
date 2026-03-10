VERSION := $(shell cat ./VERSION)
CARGO ?= cargo

.PHONY: build prebaked-build

build:
	$(CARGO) build -p cli --bin blackwall

prebaked-build:
	B7L_VERSION="$(VERSION)" $(CARGO) build -p cli --bin blackwall --release
