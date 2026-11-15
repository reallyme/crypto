# CI validation ownership

The `CI` workflow plans checks from the candidate's changed paths. The policy
lane always runs. Code, protobuf, fuzz-build, and formal verification run when
their inputs change. Workflow and shared build changes trigger all four.
`CI / Required CI` verifies the plan and checks that every successful lane
reported the candidate SHA.

| Owner | Coverage |
| --- | --- |
| Release Readiness | Shared policy, Swift and Kotlin source checks, TypeScript package and browser tests |
| Code Checks | Repository tooling, Rust tests and lints, MSRV, public API checks, WASM backend checks and external vectors |
| Code Checks, FFI jobs | iOS and Android cross-compilation, native sanitizers, Miri, C ABI and release export isolation |
| Protobuf Checks | Reproducible generation and committed binding freshness |
| Fuzz and Scheduled Fuzz | Changed-input builds and weekly time-boxed execution |
| Formal Verification | Symbolic HPKE models, bounded Rust and reference encoder proofs, and independent HPKE vector checks |
| CodeQL and Dependency Security | Static analysis, runtime dependency scanning, and Gradle checksum provenance |

The TypeScript source checks build the WASM SDK, and the tarball check and
browser runner use that build. Code Checks separately exercises the browser
primitive backends and vector oracles. The Kotlin source checks build native
artifacts for their Gradle tests. CodeQL traces the Kotlin and Java compiles
with `--no-build-cache` and `--rerun-tasks`.

The shared Rust release policy checks the locked workspace, each public crate
at its declared MSRV, and dependency advisories, licenses, and sources.
The protobuf lane checks generated bindings. The Rust suite tests the
selectors and wire data those bindings expose.

## Local and release validation

Run the repository gate locally with the pinned checker.

```sh
node scripts/run_pinned_release_readiness.mjs
```

A macOS source checkout can use its freshly built FFI dylib for Swift tests.

```sh
cargo build --locked -p crypto-ffi
touch .reallyme-crypto-runtime-ffi
REALLYME_CRYPTO_SWIFTPM_RUNTIME_FFI=1 REALLYME_CRYPTO_FFI_LIBRARY_PATH="$PWD/target/debug/libcrypto_ffi.dylib" node scripts/run_pinned_release_readiness.mjs
```

Package preflights require successful Required CI for the source SHA and a
matching Dependency Security run. When path filtering skips Dependency
Security on a documentation-only main push, dispatch that workflow from the
same main commit before starting preflight. The scheduled scans continue to
check the current locks for newly reported advisories.

The [release process](release-process.md) describes how preflight evidence
and retained artifacts are used for publication.
