# Release Integrity

ReallyMe Crypto releases are identified by a version and a reviewed source
commit. The public artifacts for that version must have the same source and
cryptographic behavior across supported Rust and SDK lanes.

## Artifact Requirements

- Published Rust crates use the same release version for all workspace
  dependencies and pass the package, semver, conformance, and dependency checks.
- The Swift package binds `ReallyMeCryptoFFI.xcframework.zip` to its exact
  checksum. Its published manifest and binary artifact must agree.
- `me.really:crypto` includes the supported JVM native libraries and a checksum
  manifest. `me.really:crypto-android` includes the supported Android JNI
  libraries in its AAR and a checksum manifest.
- `@reallyme/crypto` includes the TypeScript facade and its package-owned WASM
  artifact. The published tarball must contain the expected files and pass its
  package tests.
- Public conformance vectors and provider policy must match the released APIs.
  A lane without an implementation must return a typed unsupported result.

## Verification

Release evidence must identify the source commit, package version, and exact
artifact bytes. A checksum or signature is meaningful only for the bytes that
are published. A failed or unavailable verification is recorded as a release
risk rather than treated as a passing check.

Hardware-dependent behavior requires device evidence. A skipped Secure Enclave
or Android hardware test does not establish that the hardware route passed.
