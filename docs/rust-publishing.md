# Rust packages and features

Use `reallyme-crypto` for the Rust facade or `reallyme-crypto-proto` for wire
types without the facade. Other `reallyme-crypto-*` crates provide individual
primitives. Workspace packages share one release version and require Rust 1.96.0+.

With defaults disabled, select an execution lane (`native` or `wasm`) and the
algorithms you call. The `wasm` lane targets `wasm32-unknown-unknown`; host builds
use `native`. `dispatch` and `signer` do not enable every algorithm.

```toml
reallyme-crypto = { version = "0.4.3", default-features = false, features = [
  "native", "messaging-primitives"
] }
```

`messaging-primitives` enables ChaCha20-Poly1305/XChaCha20-Poly1305, HKDF, HMAC,
ML-KEM-768, SHA-2 and X25519, including `dispatch` but not `signer`.

Use `hpke-openmls` for the narrow MLS component set or `hpke` for the full HPKE
aggregate. The [HPKE crate](../crates/hpke/README.md#feature-selection) also
provides individual `kem-*`, `kdf-*` and `aead-*` features.

Published crates contain source, README, license and notice files. For publishing
commands and artifact checks, follow [the release process](release-process.md)
and [release checklist](../RELEASE_CHECKLIST.md).
