VERSION := $(shell cat ./VERSION)
CARGO ?= cargo

.PHONY: build prebaked-build

build:
	$(CARGO) build -p cli --bin b7l

prebaked-build:
	B7L_VERSION="$(VERSION)" $(CARGO) build -p cli --bin b7l --release
