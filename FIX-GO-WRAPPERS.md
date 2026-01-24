# Fix: Hardcoded Library Paths in go-wrappers

## Problem

The Darwin dylibs (`libgodkls.dylib`, `libgoschnorr.dylib`) have hardcoded absolute paths baked into their `install_name`:

```
/Users/johnnyluo/project/wallet/dkls23-rs/target/release/deps/libgodkls.dylib
```

This causes any binary built with go-wrappers to fail on other machines:
```
dyld: Library not loaded: /Users/johnnyluo/project/wallet/dkls23-rs/...
```

## Solution

Rebuild the dylibs with `@rpath` install names instead of absolute paths.

### Step 1: Update Cargo configs in dkls23-rs

Edit `/path/to/dkls23-rs/wrapper/go-dkls/.cargo/config.toml`:
```toml
[target.x86_64-unknown-linux-gnu]
rustflags = ["-C", "link-args=-Wl,-soname=libgodkls.so"]

[target.aarch64-unknown-linux-gnu]
rustflags = ["-C", "link-args=-Wl,-soname=libgodkls.so"]

[target.x86_64-apple-darwin]
rustflags = ["-C", "link-args=-Wl,-install_name,@rpath/libgodkls.dylib"]

[target.aarch64-apple-darwin]
rustflags = ["-C", "link-args=-Wl,-install_name,@rpath/libgodkls.dylib"]
```

Same for `/path/to/dkls23-rs/wrapper/go-schnorr/.cargo/config.toml` (use `libgoschnorr` instead).

### Step 2: Build the libraries

```bash
cd /path/to/dkls23-rs
cargo clean
cargo build --release -p go-dkls -p go-schnorr
```

### Step 3: Fix install names (if cargo flags didn't take effect)

```bash
cd target/release
install_name_tool -id "@rpath/libgodkls.dylib" libgodkls.dylib
install_name_tool -id "@rpath/libgoschnorr.dylib" libgoschnorr.dylib
```

### Step 4: Verify

```bash
otool -D libgodkls.dylib
# Should show: @rpath/libgodkls.dylib
```

### Step 5: Copy to go-wrappers and commit

```bash
cp target/release/libgodkls.dylib /path/to/go-wrappers/includes/darwin/
cp target/release/libgoschnorr.dylib /path/to/go-wrappers/includes/darwin/
cd /path/to/go-wrappers
git add includes/darwin/*.dylib
git commit -m "fix(darwin): use @rpath install names for dylibs"
git push
```

### Step 6: Update dependent repos

After merging to main, in repos that use go-wrappers:
```bash
go get github.com/vultisig/go-wrappers@latest
go mod tidy
go clean -cache
go build
```

## Temporary Workaround

Until fixed, developers can create symlinks:
```bash
sudo mkdir -p /Users/johnnyluo/project/wallet/dkls23-rs/target/release/deps/
sudo ln -s /path/to/go-wrappers/includes/darwin/libgodkls.dylib \
    /Users/johnnyluo/project/wallet/dkls23-rs/target/release/deps/libgodkls.dylib
sudo ln -s /path/to/go-wrappers/includes/darwin/libgoschnorr.dylib \
    /Users/johnnyluo/project/wallet/dkls23-rs/target/release/deps/libgoschnorr.dylib
```
