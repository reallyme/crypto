# Release Integrity

ReallyMe Crypto releases are identified by a version and a reviewed source
commit. The public artifacts for that version must have the same source and
cryptographic behavior across supported Rust and SDK lanes.

Verify [trusted publisher identities and release-environment protections](docs/trusted-publishing.md)
for npm and every published crate. Complete the workflow cutover and revoke
legacy publishing tokens in repository and organization secret stores.

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

After each package preflight succeeds, copy its version and full source SHA
from the Actions summary to that ecosystem's release form. Use the same
version and SHA for every ecosystem in the release.

Hardware-dependent behavior requires device evidence. A skipped Secure Enclave
or Android hardware test does not establish that the hardware route passed.

## Formal Verification Before Publication

Formal Verification is manually dispatched. It is not part of Required CI or
the automated package preflight attestation. Before publishing any ecosystem's
artifacts, complete these checks separately:

- [ ] Dispatch [Formal Verification](.github/workflows/formal-verification.yml)
  from a branch or tag that resolves to the reviewed release commit. Confirm
  the run's full `head_sha` equals the source SHA used by every package preflight.
- [ ] Confirm the run completed successfully and every Tamarin, reference
  encoder, and Kani matrix job passed. Missing, skipped, queued, cancelled,
  timed-out, or failed jobs do not satisfy this requirement; do not publish
  until the complete run passes.
- [ ] Record the run URL, run ID and attempt, full source SHA, and job results
  with the release evidence. Review the [proof scopes and assumptions](formal/README.md)
  so the evidence is not presented as proving properties outside those scopes.
- [ ] Repeat formal verification if the release source SHA changes. A passing
  run for another commit, including an earlier commit on the same branch, is
  insufficient.
