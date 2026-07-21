<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Release Checklist

Every ReallyMe Crypto release is built and verified from one immutable,
reviewed source commit. A Swift tag may add one deterministic manifest-only
child commit that binds the attested XCFramework checksum; it never changes
production source. This checklist defines the package-specific gates for Swift
Package Manager, Maven Central, npm, and crates.io. Automated readiness checks
guard the files most likely to drift, and package workflows build and test the
published artifacts from the reviewed source commit.

## Swift Package Manager

- Public SwiftPM releases ship `ReallyMeCryptoFFI` as a versioned
  `.xcframework` binary target.
- The Swift preflight builds the XCFramework once on the pinned GitHub macOS
  runner, tests it, and retains that exact archive as the release candidate.
- The Swift release downloads the successful preflight's artifact instead of
  rebuilding it. It derives the manifest checksum from those exact bytes and
  verifies the archive, sidecar, version, URL, and binary-target binding again.
- If the reviewed source commit's `Package.swift` does not already contain the
  runner-produced checksum, the release workflow creates a deterministic
  manifest-only child commit and tags that commit. It never rewrites or
  force-pushes `main`, and no production source differs from the attested SHA.
- A partial release can be resumed only when an existing version tag targets
  the same deterministic manifest commit. A conflicting tag fails closed.
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
- `scripts/maven-central-bundle.local.sh` assembles the JVM jar and Android AAR
  into one signed Central Portal upload bundle. It accepts the signing key id
  and passphrase only through the documented environment variables and never
  writes those credentials into the bundle or repository.
- JVM and Android artifacts include native checksum manifests so package tests
  can verify the bundled native resources.
- Each JVM matrix producer records its native-library digest as an independent
  job output. The Maven job verifies all downloaded libraries against those
  outputs before it writes the bundled checksum manifest.
- `kotlin-android-package-preflight.yml` must run Maven local publication
  checks, host-native loader tests, Android AAR verification, and the supported
  Android instrumented-test matrix for the exact release commit.

## npm And Rust

- The npm package must include its generated WASM provider artifacts and pass
  `npm test` and `npm run pack:check`, which rebuilds and inspects the actual
  npm tarball file list for `reallyme_crypto_wasm_bg.wasm`.
- The npm release workflow must publish the exact checked tarball with npm
  provenance. The build job records its SHA-256 digest as a job output outside
  the artifact transport; the credentialed job verifies the downloaded bytes
  against that independent digest instead of rebuilding the package.
- Publishable Rust crates must pass package inspection before release.
- Every publishable Rust crate and workspace path dependency must resolve to
  the requested release version before the crates.io workflow can publish.
- Provider policy, generated matrices, protobuf files, and conformance vectors
  must be fresh before any package release.

## Release Commit

Before publishing a cross-language release, finish all source and package
version changes and create the release commit once. Push that commit to `main`.
Run the four versioned package preflights on that exact commit:

- `crates-package-preflight.yml`;
- `swift-package-preflight.yml`;
- `kotlin-android-package-preflight.yml`;
- `npm-package-preflight.yml`.

Each preflight fails unless its resolved release commit matches both the
current `origin/main` tip and the workflow run's recorded head SHA.

After every preflight and the `Code Checks` push workflow succeeds, invoke the
matching release workflow. `swift-package-release.yml` retrieves the exact
XCFramework retained by the successful Swift preflight, recomputes its SwiftPM
checksum in a separate job, and publishes that same zip on a tag whose tree
differs from the reviewed commit only when a generated `Package.swift` binding
is required. `kotlin-android-package-release.yml`
publishes the JVM jar and Android AAR. `crates-release.yml` and
`npm-package-release.yml` publish their registries independently. Starting a
release workflow is an authorization to publish; release workflows do not have
dry-run boolean inputs.

The complete operator sequence, required credentials, and recovery guidance
are documented in [`docs/release-process.md`](docs/release-process.md).
