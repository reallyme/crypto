# Rust Publishing

Rust crates are published as a namespaced workspace, not as one collapsed
crate. Consumers normally depend on the umbrella crate, or on the proto crate
when they only need the stable protobuf/wire contract:

- `reallyme-crypto`
- `reallyme-crypto-proto`

The smaller `reallyme-crypto-*` crates are transitive workspace components.
They keep the development boundaries, lint posture, and feature gates clear
while allowing crates.io to resolve published dependencies.

## Toolchain

The Rust packages require Rust `1.96.0` or newer. The project intentionally
tracks current stable Rust for public releases so the conformance wall, lints,
target support, and dependency graph are exercised on the same compiler family
used by CI. Lowering MSRV should be treated as a toolchain-support project, not a
metadata-only edit.

Backend features are separate from algorithm features. `native` and `wasm`
select the Rust backend lane for whichever primitive crates are enabled; they
do not enable every algorithm by themselves. The root crate also exposes
`messaging-primitives` for consumers that only need ChaCha20-Poly1305,
HKDF, HMAC, ML-KEM-768, SHA-2, and X25519. This bundle includes `dispatch`
because ML-KEM-768 and X25519 are algorithm-selected routes. `dispatch` and
`signer` are algorithm-feature gated; they should be paired with the specific
algorithm features a consumer actually calls.

HPKE follows the same rule. The root `hpke` feature is the complete
compatibility aggregate, while `hpke-openmls` selects only ML-KEM-768,
ML-KEM-1024, ML-KEM-1024/P-384, X-Wing, HKDF-SHA256, HKDF-SHA384,
AES-256-GCM, and ChaCha20-Poly1305. The focused HPKE crate also exposes granular `kem-*`,
`kdf-*`, and `aead-*` features for protocol-specific dependency graphs. CI
rejects unrelated P-256, P-521, secp256k1/K-256, and X448 packages in the
OpenMLS graph. The OpenMLS aggregate does not enable the SHAKE256 HPKE KDF;
ML-KEM retains its required SHAKE primitive dependency for KEM-internal use.

The `wasm` lane is a `wasm32-unknown-unknown` lane. Host checks should use
`native`; wasm checks should include `--target wasm32-unknown-unknown`.

## Package Contents

`reallyme-crypto-proto` is a separately versioned public crate. The umbrella
crate exposes its optional `operation-response` feature through that package.
Published crates contain their source, README, license, and notice files. Their
workspace dependency versions agree with the release version.
