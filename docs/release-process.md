# Publishing releases

The version and reviewed source commit must agree across published artifacts.
Use the [release checklist](../RELEASE_CHECKLIST.md) for package requirements
and [trusted publishing](trusted-publishing.md) for registry setup.

1. Choose the reviewed main commit and release version. Required CI and
   Dependency Security must pass for that exact SHA.
2. Dispatch Formal Verification for that revision and complete the
   [formal checklist](../RELEASE_CHECKLIST.md#formal-verification-before-publication).
   Package preflight receipts do not attest to formal verification.
3. Dispatch each package preflight with the same version and full SHA. Its
   successful summary provides those inputs and a publication command.
4. Use that version and SHA in the matching release workflow. Preflight
   artifacts expire after seven days; rerun preflight if they are unavailable.

Release workflows verify the preflight receipt and retrieve its artifact IDs.
Rust publication compares each archive with the preflight bytes. Swift creates
the canonical version tag and binds the binary artifact checksum.

## Local Maven publication

Authenticate `gh` for `reallyme/crypto` and use a local signing key to sign and
bundle the retained JVM and Android publications. The staging step consumes
verified preflight artifacts; it does not require a local Android NDK.

```sh
MAVEN_SIGNING_KEY_ID='<gpg-key-id>' ./scripts/maven-central-bundle.local.sh <version> <source-sha>
```

With no positional arguments, the script reads the JVM package version and
current checkout SHA.
