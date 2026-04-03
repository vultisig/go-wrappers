# Building Mobile Binaries

This document explains how to build Android `.aar` and iOS `.xcframework`
binaries from the `go-dkls` and `go-schnorr` Go packages.

## Quick Start

```bash
# Install gomobile
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init

# Build both platforms (iOS requires macOS)
make mobile
```

## Prerequisites

### Common

- Go 1.22+
- gomobile: `go install golang.org/x/mobile/cmd/gomobile@latest`
- Run `gomobile init` once after installing

### Android

- Android SDK installed (`ANDROID_HOME` must be set)
- Android NDK installed: `sdkmanager "ndk-bundle"` or `sdkmanager "ndk;26.1.10909125"`
- Minimum API level: 21

### iOS

- macOS only
- Xcode with command-line tools: `xcode-select --install`

## CGO Compatibility Notes

The Go packages in this repo use CGO to link pre-built Rust static libraries
(`includes/darwin/`, `includes/linux/`, etc.) via platform-specific build files:

- `go-dkls/sessions/lib_darwin.go` — links `libgodkls.a` from `includes/darwin/`
- `go-dkls/sessions/lib_linux.go` — links `libgodkls.so` from `includes/linux/`
- `go-schnorr/sessions/lib_darwin.go` — links `libgoschnorr.a` from `includes/darwin/`
- `go-schnorr/sessions/lib_linux.go` — links `libgoschnorr.so` from `includes/linux/`

`gomobile bind` performs its own cross-compilation, which may conflict with these
CGO linker flags. Known issues:

1. **Android cross-compilation**: gomobile uses the Android NDK toolchain for
   cross-compiling. The existing LDFLAGS point to `../../includes/darwin` or
   `../../includes/linux`, but Android needs ARM/ARM64 variants of the Rust
   libraries that do not exist yet.

2. **Build tag conflicts**: The `//go:build darwin` and `//go:build linux` tags
   mean gomobile may not find the right linker configuration for Android/iOS
   targets.

## Workarounds

If `gomobile bind` fails due to CGO conflicts, here are alternative approaches:

### Option A: Build platform-specific Rust libraries first

Build the Rust libraries for Android and iOS targets, then add them to
`includes/`:

```bash
# Android (requires Rust cross-compilation toolchain)
rustup target add aarch64-linux-android armv7-linux-androideabi
cargo build --release --target aarch64-linux-android -p go-dkls -p go-schnorr

# iOS
rustup target add aarch64-apple-ios x86_64-apple-ios
cargo build --release --target aarch64-apple-ios -p go-dkls -p go-schnorr
```

Then add corresponding `lib_android.go` and `lib_ios.go` build-tagged files
with the correct LDFLAGS for the new library paths.

### Option B: Thin wrapper package

Create a separate Go package that re-exports the needed functions without
CGO build tags, letting gomobile handle the compilation independently.

### Option C: Pre-built assembly

If the consuming apps only need the `.aar` and `.xcframework` as opaque
binaries, they can be assembled manually:
- Build the Rust `.so`/`.a` for each target arch
- Package them into an AAR (Android) or xcframework (iOS) using standard
  Android/Xcode tooling without gomobile

## Outputs

Successful builds produce:

```
mobile/
  android/
    godkls.aar          # DKLs ECDSA for Android
    goschnorr.aar       # Schnorr EdDSA for Android
  ios/
    godkls.xcframework/   # DKLs ECDSA for iOS
    goschnorr.xcframework/ # Schnorr EdDSA for iOS
```

## Cleaning

```bash
make mobile-clean
```
