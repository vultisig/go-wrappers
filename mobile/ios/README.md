# iOS Binaries

This directory contains `.xcframework` bundles built by `gomobile bind`.

## Expected outputs

- `godkls.xcframework/` — DKLs23 ECDSA threshold signatures
- `goschnorr.xcframework/` — Multi-party Schnorr signatures (EdDSA)

## Build

```bash
make mobile-ios
```

### Prerequisites

- macOS with Xcode and command-line tools (`xcode-select --install`)
- Go 1.22+
- `gomobile` (`go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init`)
