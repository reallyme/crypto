<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Conformance

Shared vectors live in [../vectors](../vectors). The generator and platform
verifiers live in [../crates/conformance/vectors](../crates/conformance/vectors).

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
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace --all-features
cargo nextest run --workspace --no-default-features --features native
cargo check --workspace --no-default-features --features native
cargo check --workspace --no-default-features --features wasm
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
