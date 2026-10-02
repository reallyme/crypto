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

## Order

The dependency order matters. Core leaves must exist on crates.io before
primitives and umbrellas can package cleanly.
`reallyme-crypto-proto` is a separately published public crate and must be
published before `reallyme-crypto`, because the umbrella crate exposes the
optional `operation-response` feature through that package.

Use the manual **Crates.io Release** workflow for Rust publishing. Its preflight
job inspects every publishable crate tarball in workspace dependency order and
verifies the entire workspace with `cargo publish --workspace --dry-run --locked`. The
publish job is assigned to the `crates-io-release` environment and requires
`CARGO_REGISTRY_TOKEN`. Check environment reviewers and deployment branch
restrictions in GitHub settings before publication; the workflow file does not
create those protections. The repository-level token remains available to the
workflow even when the named environment has no protection rules.

Individual crate dry runs can stop while Cargo resolves unpublished workspace
dependencies from crates.io. The workspace-wide dry run verifies all candidate
packages together before publication. The workflow still uses
`scripts/publish_crates_in_order.mjs` to inspect tarballs and publish crates in
topological order.

If a version already exists during a partial publish, the workflow stops. A
matching crate name and version do not establish that the published archive
came from the release commit. Before a manual resume, compare its packaged
files and resolved dependency versions with the reviewed candidate; account
for Cargo's generated lockfile separately. Resume only the remaining crates
after that review.

## Local Inspection

```sh
cargo package -p reallyme-crypto --list --allow-dirty
node scripts/publish_crates_in_order.mjs inspect
cargo publish --workspace --dry-run --locked
```

Before publishing, inspect the package list and make sure the umbrella crate
ships only source, README, license, and notice files.
