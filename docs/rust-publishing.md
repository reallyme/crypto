<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

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

The `wasm` lane is a `wasm32-unknown-unknown` lane. Host checks should use
`native`; wasm checks should include `--target wasm32-unknown-unknown`.

## Order

The dependency order matters. Core leaves must exist on crates.io before
primitives and umbrellas can package cleanly.
`reallyme-crypto-proto` is a separately published public crate and must be
published before `reallyme-crypto`, because the umbrella crate exposes the
optional `operation-response` feature through that package.

Use the manual **Crates.io Release** workflow for Rust publishing. Its preflight
job inspects every publishable crate tarball in workspace dependency order. The
publish job runs after the protected `crates-io-release` environment approves
the credentialed step and the repository has `CARGO_REGISTRY_TOKEN` configured.

The first publish cannot use `cargo publish --dry-run` end-to-end for downstream
workspace crates, because Cargo resolves already-published dependencies from
crates.io. Until the lower-level ReallyMe crates actually exist there, a
simulated downstream publish fails even when the real ordered publish would
succeed. The workflow therefore uses `scripts/publish_crates_in_order.mjs` to
inspect tarballs before publishing, then publishes crates in the same
topological order.

## Local Inspection

```sh
cargo package -p reallyme-crypto --list --allow-dirty
node scripts/publish_crates_in_order.mjs inspect
```

Before publishing, inspect the package list and make sure the umbrella crate
ships only source, README, license, and notice files.
