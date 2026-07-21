<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Release Process

ReallyMe Crypto releases are reviewed-source releases. Package credentials are
available only after the exact release SHA has passed the required checks.

## Required Local Validation

Before asking CI to publish, run the repository validation suite:

```sh
cargo fmt --check
cargo check --workspace --all-features
RUSTFLAGS=-Dwarnings cargo check --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace --no-default-features --features native
cargo check --workspace --no-default-features --features native
cargo check --workspace --no-default-features --features wasm --target wasm32-unknown-unknown
cargo test -p crypto-conformance-vectors --test vectors_tests --all-features
node scripts/check_release_readiness.mjs
cargo deny check
```

When SDK packages are touched, also run Swift, Kotlin, Android where
applicable, and TypeScript package tests.

Before creating the release commit, finish every Rust and SDK source/version
change. `scripts/prepare_swift_release_candidate.sh 0.3.2` remains available as
an optional local packaging check, but its machine-specific checksum is not a
release input. The Swift preflight produces the canonical archive on the pinned
GitHub runner, tests it, and retains those exact bytes. The release workflow
binds `Package.swift` to that retained archive mechanically, so operators do
not amend or force-push a release commit to discover a checksum.

## Release Gates

Release workflows require:

- generated protobuf and package artifacts to be fresh;
- Rust public API semver checks against the reviewed baseline;
- npm `pack:check` evidence for the package file list and raw WASM
  import/export surface;
- Gradle dependency verification for Kotlin/JVM, Android, and conformance;
- C ABI, JNI, Swift, Kotlin, TypeScript, and WASM package tests;
- exact-SHA workflow-success evidence for `rust-ci` and the matching versioned
  package preflight, including the Swift preflight run that owns the promoted
  XCFramework artifact;
- protected environments or equivalent approval gates before credentials;
- immutable Swift release-asset behavior;
- Maven credential preflight and signing evidence;
- crates.io publish retry tests with terminal failure on exhausted retries, and
  release-runner resume behavior for crate versions that are already present on
  crates.io from an interrupted ordered publish.

## Publishing Credentials

- The protected `npm-release` environment provides `NPM_TOKEN` for the
  `@reallyme/crypto` scope. GitHub's OIDC token supplies npm provenance; no OIDC
  credential is stored as a repository secret.
- The protected `crates-io-release` environment provides
  `CARGO_REGISTRY_TOKEN` for the approved ReallyMe crate owners.
- The protected `maven-release` environment provides the HTTPS repository URL,
  repository credentials, and in-memory PGP signing key used for both the JVM
  and Android publications.
- The protected `github-release` environment approves creation of the SwiftPM
  tag and immutable XCFramework release asset; it uses the scoped GitHub token
  rather than a long-lived repository credential.

Do not place registry tokens in source, workflow inputs, build artifacts, or
local configuration committed to the repository.

## Publication

Rust crates are published in dependency order through
`scripts/publish_crates_in_order.mjs`. Swift releases upload a checksum-bound
`ReallyMeCryptoFFI.xcframework.zip` artifact. Kotlin/JVM and Android releases
publish Maven artifacts with bundled native resources. The npm package ships
the TypeScript facades and package-owned WASM provider artifact.

Run the package preflight workflows first. Each accepts a version and an
optional full `release_sha`, but only the current `origin/main` tip can be
certified, and that tip must equal the workflow run's recorded head SHA. The
workflow run title binds the successful evidence to that version:

- `crates-package-preflight.yml`;
- `swift-package-preflight.yml`;
- `kotlin-android-package-preflight.yml`;
- `npm-package-preflight.yml`.

The corresponding release workflows resolve the current `main` SHA again and
fail closed unless the newest `Code Checks` push run and newest matching
preflight run both succeeded for that SHA and version. A newer failed,
cancelled, queued, or in-progress run invalidates an older success.

Run `swift-package-release.yml` after the Swift preflight succeeds. The release
resolves that attested preflight run and downloads its retained zip and checksum
sidecar; it never recompiles the XCFramework. A separate macOS job recomputes
the SwiftPM checksum and verifies the generated manifest binding. The protected
release job repeats that verification and, when necessary, creates a
deterministic `Package.swift`-only child of the reviewed source SHA before
creating the immutable tag and GitHub release. `main` is never rewritten or
force-pushed for a Swift checksum.

Run `kotlin-android-package-release.yml` to publish `me.really:crypto` and
`me.really:crypto-android`. The JVM matrix builds and tests each supported host
native library and records a distinct SHA-256 job output before upload. The
Maven job verifies every downloaded library against those outputs before it
writes the integrity manifest. The Android job builds all supported ABI
libraries with the pinned NDK, verifies the AAR contents and integrity manifest,
and publishes the signed artifact. Missing repository or signing credentials
terminate the release.

Run `npm-package-release.yml` to build an immutable tarball, transfer it between
jobs with a SHA-256 sidecar, bind it to an independent producer job output, and
publish those exact bytes with npm provenance.
Run `crates-release.yml` independently for crates.io; it derives the version
from the umbrella crate, reinspects every publishable tarball, and publishes in
dependency order. Starting any release workflow is an authorization to publish.

Normal release paths do not clobber existing tags, release assets, registry
versions, or Maven artifacts. Recovery requires separate byte-for-byte artifact
identity evidence and reviewer approval.

## Residual Risk Records

Any skipped command or unavailable hardware lane must be recorded with a
concrete reason and release risk. Secure Enclave and Android hardware tests may
be hardware-skip-aware, but the skip must not hide a provider-policy failure.
