# Mobile Binaries

Pre-built mobile binaries for Android (.aar) and iOS (.xcframework) produced by
`gomobile bind` from the `go-dkls` and `go-schnorr` packages.

## Directory Structure

```
mobile/
  android/     # .aar files for Android
  ios/         # .xcframework bundles for iOS
```

## Building

From the repository root:

```bash
# Both platforms
make mobile

# Android only (requires Android NDK)
make mobile-android

# iOS only (requires macOS + Xcode)
make mobile-ios

# Clean build artifacts
make mobile-clean
```

See [BUILD-MOBILE.md](../BUILD-MOBILE.md) for detailed prerequisites and
troubleshooting.

## Consuming in Apps

These binaries are published as release assets. Downstream repos (vultisig-ios,
vultiagent-app, vultisig-sdk) should download them from the
[releases page](https://github.com/vultisig/go-wrappers/releases) rather than
committing binaries directly.
