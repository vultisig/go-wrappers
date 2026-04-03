ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

MOBILE_DIR := $(ROOT_DIR)mobile
ANDROID_OUT := $(MOBILE_DIR)/android
IOS_OUT := $(MOBILE_DIR)/ios

.PHONY: build
build:
	@cd .. && cargo build --release -p go-dkls -p go-schnorr

.PHONY: check-lint
check-lint:
	@which golangci-lint > /dev/null || (echo "golangci-lint is not installed. Please install and try again."; exit 1)

.PHONY: lint
lint: check-lint
	golangci-lint run --config .golangci.yml

# --- Mobile targets ---
# These targets use gomobile bind to produce Android .aar and iOS .xcframework
# outputs from the go-dkls and go-schnorr packages.
#
# Prerequisites:
#   - Go 1.22+
#   - gomobile: go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init
#   - Android: ANDROID_HOME set, NDK installed (sdkmanager "ndk-bundle")
#   - iOS: macOS with Xcode and command-line tools
#
# IMPORTANT: The Go packages use CGO to link pre-built Rust static libraries
# via platform-specific build tags (lib_darwin.go, lib_linux.go). gomobile's
# cross-compilation may conflict with these CGO flags. If gomobile bind fails,
# see BUILD-MOBILE.md for alternative approaches.

.PHONY: check-gomobile
check-gomobile:
	@which gomobile > /dev/null || (echo "gomobile is not installed. Run: go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init"; exit 1)

.PHONY: mobile-android
mobile-android: check-gomobile
	@echo "Building Android .aar files..."
	@mkdir -p $(ANDROID_OUT)
	CGO_ENABLED=1 gomobile bind -target=android -androidapi=21 \
		-ldflags="-s -w" \
		-o $(ANDROID_OUT)/godkls.aar \
		./go-dkls/sessions/
	CGO_ENABLED=1 gomobile bind -target=android -androidapi=21 \
		-ldflags="-s -w" \
		-o $(ANDROID_OUT)/goschnorr.aar \
		./go-schnorr/sessions/
	@echo "Android builds complete: $(ANDROID_OUT)/"

.PHONY: mobile-ios
mobile-ios: check-gomobile
	@echo "Building iOS .xcframework files..."
	@mkdir -p $(IOS_OUT)
	CGO_ENABLED=1 gomobile bind -target=ios \
		-ldflags="-s -w" \
		-o $(IOS_OUT)/godkls.xcframework \
		./go-dkls/sessions/
	CGO_ENABLED=1 gomobile bind -target=ios \
		-ldflags="-s -w" \
		-o $(IOS_OUT)/goschnorr.xcframework \
		./go-schnorr/sessions/
	@echo "iOS builds complete: $(IOS_OUT)/"

.PHONY: mobile
mobile: mobile-android mobile-ios
	@echo "All mobile builds complete."

.PHONY: mobile-clean
mobile-clean:
	rm -rf $(ANDROID_OUT)/*.aar $(ANDROID_OUT)/*.jar
	rm -rf $(IOS_OUT)/*.xcframework
	@echo "Mobile build artifacts cleaned."
