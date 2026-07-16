<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Release Readiness Requirements

This document records the public packaging requirements that must hold before
ReallyMe Crypto is released as a normal one-line install across Swift Package
Manager, Maven, npm, and crates.io. The marker scripts are release-readiness
tripwires for drift-prone packaging and contract files; executable assurance
comes from the Rust, protobuf, Swift, Kotlin, TypeScript, preflight, and package
workflows that build and test the artifacts for the release SHA.

## Swift Package Manager

- Public SwiftPM releases ship `ReallyMeCryptoFFI` as a versioned
  `.xcframework` binary target.
- The root `Package.swift` must be patched with the release version and SwiftPM
  checksum in a reviewed commit before release CI is run.
- The public release tag must point at the reviewed manifest commit containing
  the non-placeholder checksum, never at a source-preparation commit that still
  has the all-zero placeholder.
- Release workflows never modify or push source. They verify that the checked-in
  manifest checksum matches the artifact rebuilt for the exact release SHA and
  tag that already-tested SHA without creating a post-gate commit.
- Source-tree tests may use `REALLYME_CRYPTO_FFI_LIBRARY_PATH` for a freshly
  built local dylib, but release preflight must also test the linked
  `ReallyMeCryptoFFI.xcframework` path without that environment variable.
- The default Swift facade must work for consumers that add
  `.product(name: "ReallyMeCrypto", package: "crypto")` without requiring an
  application-owned dylib build step.

## Maven And Android

- JVM releases bundle per-OS and per-architecture Rust JNI libraries inside the
  `me.really:crypto` artifact.
- Android releases publish `me.really:crypto-android` as an AAR containing the
  standard Android ABI JNI libraries under `jni/**`.
- JVM and Android artifacts include native checksum manifests so package tests
  can verify the bundled native resources.
- Release preflight must run Maven local publication checks and verify that the
  Android AAR contains every required JNI library and native manifest entry.

## npm And Rust

- The npm package must include its generated WASM provider artifacts and pass
  `npm test` and `npm run pack:check`, which rebuilds and inspects the actual
  npm tarball file list for `reallyme_crypto_wasm_bg.wasm`.
- Publishable Rust crates must pass package inspection before release.
- Provider policy, generated matrices, protobuf files, and conformance vectors
  must be fresh before any package release.

## Manual Release Checks

Before publishing a cross-language release, build the Swift artifact, patch and
review `Package.swift` with `scripts/prepare_swift_binary_manifest.mjs`, then run
all required CI and the release preflight workflow on that exact commit. Confirm
that package release verifies the checked-in checksum, uploads the
`ReallyMeCryptoFFI.xcframework.zip` asset, builds bundled JVM native resources,
builds the Android AAR, and tags the same commit without modifying source.

## ReallyMe Codec Proto Retirement

The 0.2.0 release intentionally removes the accidentally bundled
`reallyme/codec/v1/codec.proto` file from this repository because Codec is
released as its own package family. Crypto's Buf module is now rooted at
`crates/proto/crypto/proto`; the protobuf CI keeps a scoped one-time
`--exclude-path proto/reallyme/codec/v1/codec.proto` comparison exception so
release PRs can compare against `origin/main` without normalizing a broad Buf
bypass.
