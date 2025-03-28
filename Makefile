ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

.PHONY: build
build:
	@cd .. && cargo build --release -p go-dkls -p go-schnorr

.PHONY: check-lint
check-lint:
	@which golangci-lint > /dev/null || (echo "golangci-lint is not installed. Please install and try again."; exit 1)

.PHONY: lint
lint: check-lint
	golangci-lint run --config .golangci.yml
