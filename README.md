# Go Wrappers

Go bindings for Vultisig TSS (Threshold Signature Scheme) libraries.

## Overview

This package provides Go bindings for:
- **go-dkls**: DKLs23 ECDSA threshold signatures
- **go-schnorr**: Multi-party Schnorr signatures (EdDSA)

## Platform Support

| Platform | Architecture | Directory | Status |
|----------|-------------|-----------|--------|
| Linux | amd64 (x86_64) | `includes/linux-amd64/` | ✅ Supported |
| Linux | arm64 (aarch64) | `includes/linux-arm64/` | ✅ Supported |
| macOS | arm64 (Apple Silicon) | `includes/darwin/` | ✅ Supported |
| macOS | amd64 (Intel) | - | ❌ Not available |

**Note:** The `includes/linux/` directory contains amd64 libraries for backwards compatibility.

## Installation

### From Release

Download the pre-built libraries from the [releases page](https://github.com/vultisig/go-wrappers/releases).

```bash
# Linux amd64
wget https://github.com/vultisig/go-wrappers/releases/latest/download/go-wrappers-linux-amd64.tar.gz
sudo mkdir -p /usr/local/lib/dkls
sudo tar -xzf go-wrappers-linux-amd64.tar.gz -C /usr/local/lib/dkls
export LD_LIBRARY_PATH=/usr/local/lib/dkls/includes/linux:$LD_LIBRARY_PATH

# macOS arm64
wget https://github.com/vultisig/go-wrappers/releases/latest/download/go-wrappers-darwin-arm64.tar.gz
sudo mkdir -p /usr/local/lib/dkls
sudo tar -xzf go-wrappers-darwin-arm64.tar.gz -C /usr/local/lib/dkls
```

### From Source

```bash
# Clone the repository
git clone https://github.com/vultisig/go-wrappers.git

# The includes/ directory contains pre-built libraries
# Copy them to your library path
sudo cp -r includes /usr/local/lib/dkls
```

## Usage

```go
import (
    "github.com/vultisig/go-wrappers/go-dkls"
    "github.com/vultisig/go-wrappers/go-schnorr"
)
```

## Building from Source (Rust)

The native libraries are built from the Rust implementations:
- [dkls23-rs](https://github.com/vultisig/dkls23-rs) - DKLs23 ECDSA
- [multi-party-schnorr](https://github.com/vultisig/multi-party-schnorr) - Schnorr signatures

To rebuild:

```bash
# Requires Rust toolchain
cd ..  # Parent directory with dkls23-rs checkout
cargo build --release -p go-dkls -p go-schnorr
```

## Adding Multi-Architecture Support

To add support for additional platforms (e.g., Linux arm64), you need to:

1. Set up Rust cross-compilation toolchain:
   ```bash
   rustup target add aarch64-unknown-linux-gnu
   # Install cross-compilation tools (e.g., zig, musl-cross)
   ```

2. Build the Rust libraries for the target:
   ```bash
   cargo build --release --target aarch64-unknown-linux-gnu -p go-dkls -p go-schnorr
   ```

3. Copy the built libraries to `includes/linux-arm64/` (new directory)

4. Update the Go bindings to detect and use the correct library path

## Docker Support

For Docker-based builds, the libraries are automatically downloaded during the build process:

```dockerfile
RUN wget https://github.com/vultisig/go-wrappers/archive/refs/heads/master.tar.gz && \
    tar -xzf master.tar.gz && \
    cd go-wrappers-master && \
    mkdir -p /usr/local/lib/dkls && \
    cp -r includes /usr/local/lib/dkls
```

**Note**: Docker images are currently limited to `linux/amd64` due to library availability.

## License

See [LICENSE](LICENSE) for details.
