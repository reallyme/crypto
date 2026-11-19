# Swift vector conformance

This harness checks shared vectors against CryptoKit, libsecp256k1 through
[reallyme/CSecp256k1](https://github.com/reallyme/CSecp256k1), and selected Rust
C ABI functions. The SDK is in [`packages/swift`](../../../../packages/swift).

```sh
swift test --package-path crates/conformance/platform/swift
```

Tests read the root `vectors/` directory.
