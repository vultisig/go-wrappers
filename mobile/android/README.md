# Android Binaries

This directory contains `.aar` files built by `gomobile bind`.

## Expected outputs

- `godkls.aar` — DKLs23 ECDSA threshold signatures
- `goschnorr.aar` — Multi-party Schnorr signatures (EdDSA)

## Build

```bash
make mobile-android
```

### Prerequisites

- Go 1.22+
- `gomobile` (`go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init`)
- Android SDK with NDK installed (`sdkmanager "ndk-bundle"`)
- `ANDROID_HOME` environment variable set
