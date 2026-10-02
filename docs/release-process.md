# Release Process

ReallyMe Crypto releases use a reviewed source commit. The release workflows
check that the exact source SHA passed the required runs before invoking a
credentialed publish step. Repository environment protection and credentials
must be configured separately before publication.

## Required Local Validation

Run the [full conformance validation](conformance.md#full-release-wall), including
the affected SDK and hardware lanes, before asking CI to publish. Package-specific
artifact gates are listed in [the release checklist](../RELEASE_CHECKLIST.md).

Before creating the release commit, finish every Rust and SDK source/version
change. `scripts/prepare_swift_release_candidate.sh 0.3.10` remains available as
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
- derived JVM and Android runtime dependency locks, dependency scanning, and
  publisher checksum provenance for Gradle artifacts;
- C ABI, JNI, Swift, Kotlin, TypeScript, and WASM package tests;
- browser execution of the built WASM package, C ABI sanitizer, and focused
  FFI Miri checks;
- exact-SHA workflow-success evidence for `rust-ci`, `dependency-security`, and the matching versioned
  package preflight, including the Swift preflight run that owns the promoted
  XCFramework artifact;
- release environment protection before credentials are provisioned;
- refusal to overwrite an existing Swift tag or release asset;
- Maven credential preflight and signing evidence;
- crates.io publish retry tests with terminal failure on exhausted retries, and
  a fail-closed stop when a crate version is already present during an
  interrupted ordered publish.

## Publishing Credentials

The workflows name `npm-release`, `crates-io-release`, `maven-release`, and
`github-release` environments. An environment name alone does not enforce
review or restrict branches. Before starting publication, verify the live
protection rules and provision the required secrets for that environment:

- `npm-release` needs `NPM_TOKEN` for `@reallyme/crypto`; the workflow requests
  npm provenance using GitHub OIDC. Verify provenance on the published package.
- `crates-io-release` needs `CARGO_REGISTRY_TOKEN` for the approved crate owners.
- `maven-release` needs the repository URL, credentials, and signing key for the
  JVM and Android publications.
- `github-release` uses the scoped GitHub token to create the SwiftPM tag and
  XCFramework release asset.

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
fail closed unless the newest `Code Checks` and `Dependency Security` push runs
and newest matching preflight run all succeeded for that SHA and version. A newer failed,
cancelled, queued, or in-progress run invalidates an older success.

Run `swift-package-release.yml` after the Swift preflight succeeds. The release
resolves that attested preflight run and downloads its retained zip and checksum
sidecar; it never recompiles the XCFramework. A separate macOS job recomputes
the SwiftPM checksum and verifies the generated manifest binding. The
release job repeats that verification and, when necessary, creates a
deterministic `Package.swift`-only child of the reviewed source SHA before
creating the tag and GitHub release. It refuses a conflicting tag or asset.
`main` is never rewritten or force-pushed for a Swift checksum.

Immediately before tag publication, the release job reads `Package.swift`
back from the proposed tag commit and verifies it against the retained
archive and checksum sidecar. The GitHub release notes are extracted from the
matching version section in `RELEASE_NOTES.md` and fail closed if that section
is missing or duplicated.

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
publish those exact bytes with npm provenance when the registry accepts the
OIDC attestation. Confirm that the resulting registry package has provenance.
Run `crates-release.yml` independently for crates.io; it derives the version
from the umbrella crate, reinspects every publishable tarball, and publishes in
dependency order. Starting any release workflow is an authorization to publish.

Normal release paths do not clobber existing tags, release assets, registry
versions, or Maven artifacts. Recovery requires separate byte-for-byte artifact
identity evidence and reviewer approval.

## Dependency Migration Scope

The Android package remains on Android Gradle Plugin `8.13.2` with the
reviewed Gradle `8.14.4` wrapper for this release. Moving to AGP 9 requires a
separate migration of built-in Kotlin support, build DSL, Gradle verification
metadata, and the Android packaging checks; follow the
[official built-in Kotlin migration](https://developer.android.com/build/migrate-to-built-in-kotlin)
and [AGP compatibility notes](https://developer.android.com/build/releases/agp-9-4-0-release-notes).
The Rust `getrandom` `0.2` line
is retained only by the arkworks graph used for Poseidon2; its standalone WASM
entropy feature is selected in the Poseidon2 crate. KMAC retains `sha3` `0.10`
because `sha3-kmac` `0.3.0` uses that line and its sponge state needs the
matching zeroization feature. These compatibility lines should change with
their dependent libraries and cross-target validation, not by independently
raising their direct version requirements.

## Residual Risk Records

Any skipped command or unavailable hardware lane must be recorded with a
concrete reason and release risk. Secure Enclave and Android hardware tests may
be hardware-skip-aware, but the skip must not hide a provider-policy failure.

## Repository Scripts

The public `scripts/` directory contains the tools used by CI and maintainers:

- Provider, operation-route, negative-vector, and release-readiness checks
  enforce the documented contract. Their `.test.mjs` files test the checks.
- Protobuf hardening and provider-matrix generation keep generated files aligned
  with the schema and manifest. See [protobuf generation](protobuf.md#generation).
- Native builders, manifest writers, and artifact verifiers build and validate
  the JNI and Swift artifacts consumed by package workflows.
- The semver-baseline preparer freezes dependencies of the pinned historical
  checkout used for API compatibility checks; it does not update current code.
- External-vector tools maintain pinned public corpora and run optional slow
  conformance checks. See [external conformance](external-conformance-vectors.md).
- Browser and package-local scripts build, initialize, and test WASM artifacts.

`maven-central-bundle.local.sh` is an optional maintainer tool for manual Central
Portal submission. It builds and signs a local bundle; it does not upload it.
It requires the latest successful Kotlin/Android package preflight for the
current `origin/main` commit and version, then downloads that run's attested
JVM native artifacts. It requires the
local GPG key, signing environment variables, GitHub CLI authentication, and
Android build tools. Load passphrases through a secret manager or a non-echoing
prompt, not literal commands saved in shell history. Output/resource overrides
must name dedicated, trusted build directories: the script replaces their
staging contents. The normal CI release path is described above.

The shared `scripts/release-readiness/core.mjs` is vendored from the pinned
ReallyMe release-readiness repository. Its original Apache license and exact
bytes are retained so its SHA-256 verification remains meaningful. Project
license checks are configured by the local consumer script.
