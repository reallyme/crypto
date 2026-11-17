# Release Integrity

A ReallyMe Crypto release consists of versioned artifacts for Rust, Swift,
Kotlin/JVM, Android, and TypeScript. The [artifact requirements](../RELEASE_CHECKLIST.md)
state the properties that each published package must satisfy.

The release version and reviewed source commit must agree across published
artifacts. The Swift package's binary checksum must match its XCFramework
archive. JVM and Android packages must carry native libraries and integrity
manifests for their supported platforms. The npm package must include the WASM
module used by its public facade.

Release evidence includes package tests, cross-lane conformance vectors,
dependency checks, and integrity checks for the final artifacts. Supported
hardware routes require device evidence; a hardware skip does not count as a
successful device test. Public provenance and repository protection claims are
made only when independently verified.

Formal Verification is a separate manual release requirement. Before publishing,
dispatch its workflow for the reviewed source revision and confirm every proof
job succeeds with the same full source SHA as the package preflights. Record
the run URL, attempt, and results with the release evidence. Required CI and
the automated preflight receipt do not check this workflow; follow the
[formal verification checklist](../RELEASE_CHECKLIST.md#formal-verification-before-publication)
before authorizing publication.

Dispatch each package preflight from the reviewed main commit with its full
SHA and release version. Each successful preflight retains a CI receipt and
the package artifacts for seven days. Use the version and SHA from its job
summary in the matching release workflow. The same summary gives you a
GitHub CLI command with both inputs filled in. The release workflow verifies
the receipt and retrieves the recorded artifact IDs. For Rust, the publish job
checks each Cargo archive against its preflight archive before uploading it.
Swift owns the canonical version tag.

For Maven Central Portal upload from a local checkout, sign and bundle the
retained JVM and Android publications with the local signing key. Authenticate
`gh` for `reallyme/crypto` before running the script. The staging step uses
the verified preflight artifacts, so it needs no local Android NDK.

```sh
MAVEN_SIGNING_KEY_ID='<gpg-key-id>' \
  ./scripts/maven-central-bundle.local.sh <version> <source-sha>
```

With no positional arguments, the script gets the version from the JVM
package manifest and the source SHA from the current checkout.
