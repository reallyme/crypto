# CI validation ownership

Ordinary pushes and pull requests validate the reviewed source and locked
dependencies. Independent jobs run in parallel; each expensive suite has one
owner within Code Checks.

| Owner | Required coverage |
| --- | --- |
| Repository tooling, Linux and macOS | Node/Python tooling tests, actionlint and policy-pin integrity |
| Native Rust | Strict compilation/lints, native and all-feature tests, narrow/backendless features, documentation, doctests, package contents and committed external vectors |
| TypeScript and WASM | SDK source policy, Node tests and typecheck, browser SDK tests, independent vector oracles, primitive browser tests, reader WASM execution and workspace WASM compilation |
| Swift | Source policy, strict formatting/compilation, package and vector tests with the Rust FFI library loaded |
| Kotlin | Source policy, JVM tests, Android checks/packaging and vector conformance through the full Gradle check script |
| FFI release artifact | Abort-profile rejection, production export isolation, C ASan/UBSan against the inspected library, and conformance-only feature compilation |
| Native sanitizers and Miri | Rust ASan, checked UB, pointer validation and panic-boundary checks |
| Mobile, MSRV and public API jobs | Cross-target compilation, Rust 1.96 compatibility and public API compatibility |

The all-feature Rust suite owns immutable protobuf selector and wire-golden
tests. Protobuf Checks owns reproducible generation, hardening and committed
byte freshness. Both obligations remain required when protobuf changes.

The TypeScript source-policy invocation builds the SDK before its Node tests.
The browser runner consumes those same built files, avoiding a second package
build. Android native artifacts are built and checked by the Kotlin lane;
CodeQL compiles the Java/Kotlin source sets for extraction without rebuilding
unrelated JNI artifacts. Its traced compiles retain `--no-build-cache` and
`--rerun-tasks`.

## Full local and release validation

The default command continues to execute the complete suite:

```sh
node scripts/run_pinned_release_readiness.mjs
```

It runs repository tooling and all SDK source/verification policies. Release
preflights continue to select `--release-packages` with their additional package
and artifact obligations.

An unreleased macOS source checkout uses the same explicit runtime-FFI setup as
the Swift CI job, rather than downloading a binary from a different release:

```sh
cargo build --locked -p crypto-ffi
touch .reallyme-crypto-runtime-ffi
REALLYME_CRYPTO_SWIFTPM_RUNTIME_FFI=1 REALLYME_CRYPTO_FFI_LIBRARY_PATH="$PWD/target/debug/libcrypto_ffi.dylib" node scripts/run_pinned_release_readiness.mjs
```

Published binary checksums and linked-artifact release checks are unchanged.

CI uses `--ci-policy` for repository checks and the separate
`--typescript-source`, `--swift-source` and `--kotlin-source` modes in their
owning jobs. These modes are mutually exclusive. SDK modes run the same source
policy definitions and real verification commands as the full gate. Required
workflow commands and release attestations reject missing or skipped owners.

Routine CI validates exact reviewed manifests and registry checksums. Checking
whether a newer package has been published belongs to full local/release
validation. Dependency advisory, license and provenance gates remain active;
a package publication alone does not invalidate an unchanged reviewed graph.

## Cancellation and caches

A newer push supersedes older push checks for the same branch. Pull requests
are grouped by pull number. Manual/preflight/release work retains its separate
concurrency policy. A cancelled run cannot provide successful release evidence;
release attestation also requires the current main commit.

Cargo caches are partitioned by job/toolchain/target purpose, and Gradle caches
reuse dependency downloads. Validation commands still run after restoration.
Idempotent protobuf hardening preserves the timestamps of byte-identical files
so restored compiler artifacts remain useful.

Native/all-feature configurations, browser/Node runtimes and the different
sanitizers remain separate: each exercises behavior the others do not cover.
