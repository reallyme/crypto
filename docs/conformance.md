<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Conformance

Shared vectors live in [../vectors](../vectors). The generator and platform
verifiers live in [../crates/conformance/vectors](../crates/conformance/vectors).
Those vectors are part of the canonical Crypto contract together with the
protobuf/enums, package algorithm identifiers, typed error taxonomy, and
provider manifest.

Every provider route must prove the same contract: identical input validation
and normalization, output encoding, typed failure semantics, and edge-case
behavior. Positive vectors prove byte output. Negative vectors and malformed
input tests prove fail-closed behavior. Where a native/provider route replaces
the Rust/reference path, differential tests should prove the two routes remain
interchangeable.

Shared negative vectors are listed in `vectors/manifest.json` under
`negative_vectors` and validated by `scripts/check_negative_vectors.mjs`.
Lane-local malformed-input tests may add broader coverage, but they do not
replace the shared cases that pin cross-lane typed failure semantics.

The normal Rust all-feature check is:

```sh
cargo nextest run --workspace --all-features
```

## Full Release Wall

Run the full wall before publishing a release or changing a cryptographic
contract:

```sh
cargo fmt --check
cargo check --workspace --all-features
cargo test -p reallyme-crypto-dispatch --test feature_lane_tests --no-default-features
cargo test -p reallyme-crypto-dispatch --test feature_lane_tests --no-default-features --features native,x25519,ml-kem-768,chacha20-poly1305,hmac,sha2
cargo test -p reallyme-crypto-signer --no-default-features
cargo test -p reallyme-crypto-signer --no-default-features --features native
cargo test -p reallyme-crypto-signer --no-default-features --features native,ed25519
cargo check -p reallyme-crypto --no-default-features --features native,messaging-dispatch
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace --all-features
cargo nextest run --workspace --no-default-features --features native
cargo check --workspace --no-default-features --features native
cargo check --workspace --no-default-features --features wasm --target wasm32-unknown-unknown
cargo run -p crypto-conformance-vectors --bin gen_vectors
npm run --prefix crates/conformance/vectors verify:ts-native
npm run --prefix crates/conformance/vectors verify:noble-pq
swift test
swift test --package-path crates/conformance/vectors/platform/swift
cd packages/kotlin && ./gradlew test --rerun-tasks
cd crates/conformance/vectors/platform/kotlin && ./gradlew test --rerun-tasks
npm --prefix packages/ts ci && npm --prefix packages/ts test
node scripts/generate_provider_matrix.mjs --check
node scripts/check_release_readiness.mjs
buf lint
buf generate
cargo deny check
cargo audit
```

Do not regenerate vectors unless the public byte contract intentionally
changes. If vectors change, update proto adapters, provider policy, package
facades, and conformance tests in the same pass.
