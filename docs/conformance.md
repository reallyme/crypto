# Conformance

Shared vectors live in [../vectors](../vectors). The generator and platform
verifiers live in [../crates/conformance](../crates/conformance).
Third-party vector coverage from NIST ACVP, CCTV, and supplementary corpora is tracked separately in
[External conformance vectors](external-conformance-vectors.md). Those adapters
exercise public primitive boundaries and keep raw upstream files intact under
[../vectors/external](../vectors/external).

WASM browser tests use the repository-owned wrapper rather than invoking
`wasm-pack test --chrome` directly. The wrapper checks Chrome and ChromeDriver
major versions before the Chrome lane starts, so a local driver mismatch is a
preflight failure instead of a skipped browser claim.

```sh
node scripts/run_wasm_browser_tests.mjs --browser=chrome
node scripts/run_wasm_browser_tests.mjs --browser=firefox
```

Provider tests compare input validation, output bytes and typed errors across
supported SDKs. Run the affected positive and negative cases when changing a
provider; test unavailable-provider behavior as well as success.

Shared negative vectors are listed in `vectors/manifest.json` under
`negative_vectors` and validated by `scripts/check_negative_vectors.mjs`.
Lane-local malformed-input tests may add broader coverage, but they do not
replace the shared cases that pin cross-lane typed failure semantics.

For Rust-only changes:

```sh
cargo nextest run --workspace --all-features
```

## Release checks

Before publishing a release or changing a cryptographic contract, run the
[protobuf generation checks](protobuf.md#generation), then the following
commands from the repository root. See the Swift README for testing locally
modified Rust sources through the development runtime override.

```sh
cargo fmt --check
cargo check --workspace --all-features
RUSTFLAGS=-Dwarnings cargo check --workspace --all-features
cargo test -p reallyme-crypto-dispatch --test feature_lane_tests --no-default-features
cargo test -p reallyme-crypto-dispatch --test feature_lane_tests --no-default-features --features native,x25519,ml-kem-768
cargo test -p reallyme-crypto-signer --no-default-features
cargo test -p reallyme-crypto-signer --no-default-features --features native
cargo test -p reallyme-crypto-signer --no-default-features --features native,ed25519
cargo check -p reallyme-crypto --no-default-features --features native,messaging-primitives
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo nextest run --workspace --no-default-features --features native
cargo check --workspace --no-default-features --features native
cargo check --workspace --no-default-features --features wasm --target wasm32-unknown-unknown
cargo run -p crypto-conformance-vectors --bin gen_vectors
npm run --prefix crates/conformance verify:ts-native
npm run --prefix crates/conformance verify:noble-pq
swift test
swift test --package-path crates/conformance/platform/swift
(cd packages/kotlin && ./gradlew test --rerun-tasks)
(cd crates/conformance/platform/kotlin && ./gradlew test --rerun-tasks)
npm --prefix packages/ts ci && npm --prefix packages/ts test
node scripts/check_provider_routing.mjs
node scripts/check_release_readiness.mjs
cargo deny check
bash scripts/audit_committed_lockfiles.sh
```

Install local Git safeguards after cloning:

```sh
python3 -B scripts/install_repository_hooks.py
python3 -B scripts/check_repository_privacy.py --index
```

The installer refuses to replace active hooks; add these checks to an existing
hook chain when needed. To stop tracking an excluded file while preserving its
local contents, use `git rm --cached -- PATH`.

The generation commands above must reproduce the committed files. Review any
diff before accepting it. Do not change expected bytes to accommodate an
unexplained mismatch. If vectors change, update proto adapters, provider policy, package
facades, and conformance tests in the same pass.
