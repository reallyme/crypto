# CI validation ownership

The `CI` workflow plans checks from the candidate's changed paths. The policy
lane always runs. Code, protobuf, and fuzz-build checks run when their inputs
change. Workflow and shared build changes trigger all automatic lanes.
`CI / Required CI` verifies the plan and checks that every successful lane
reported the candidate SHA.

Formal Verification runs only on explicit `workflow_dispatch`. Its
`"mode": "manual"` setting excludes it from automatic Required CI and automated
release attestation. The [release checklist](../RELEASE_CHECKLIST.md#formal-verification-before-publication)
requires separate review of a successful formal run for the exact release SHA
before publication.

| Owner | Coverage |
| --- | --- |
| Release Readiness | Shared policy, Swift and Kotlin source checks, TypeScript package and browser tests |
| Code Checks | Repository tooling, Rust tests and lints, MSRV, public API checks, WASM backend checks and external vectors |
| Code Checks, FFI jobs | iOS and Android cross-compilation, native sanitizers, Miri, C ABI and release export isolation |
| Protobuf Checks | Reproducible generation and committed binding freshness |
| Fuzz and Scheduled Fuzz | Changed-input builds and weekly time-boxed execution |
| Formal Verification (manual dispatch) | Symbolic HPKE models, bounded Rust and reference encoder proofs, and independent HPKE vector checks |
| CodeQL and Dependency Security | Static analysis, runtime dependency scanning, and Gradle checksum provenance |

The TypeScript source checks build the WASM SDK, and the tarball check and
browser runner use that build. Code Checks separately exercises the browser
primitive backends and vector oracles. The Kotlin source checks build native
artifacts for their Gradle tests. CodeQL traces the Kotlin and Java compiles
with `--no-build-cache` and `--rerun-tasks`.

The shared Rust release policy checks the locked workspace, each public crate
at its declared MSRV, and dependency advisories, licenses, and sources.
The protobuf lane checks generated bindings. The Rust suite tests the
selectors and wire data those bindings expose. RFC 9180 and PQ HPKE Base/PSK
corpus adapters run as ordinary native workspace tests. The external-vector
integrity job also runs these adapters on changes to `crates/hpke`, the locked
dependencies, and the vector corpora or harnesses; no weekly audit is required
to exercise them.

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

The automated preflight receipt does not attest to formal verification. Record
and review the separately dispatched formal run, including every proof job's
result and its exact source SHA, as required by the release checklist. A green
Required CI result or package preflight alone does not establish proof success.

The [release process](release-process.md) describes how preflight evidence
and retained artifacts are used for publication.

## Rust dependency maintenance

The 2026-11-17 dependency review raised 26 manifest requirements to the latest
available compatible patch releases. All three tracked lockfiles already held
the newest versions accepted by their dependency graphs; resolving them again
introduced no version or checksum changes. The workspace MSRV remains Rust
1.96.0. Strict RustSec audits of every tracked lockfile reported no
vulnerabilities, informational warnings, or yanked packages. Dependency
advisory, license, source, and ban checks passed without exceptions.

Some transitive releases cannot advance independently of their parents. The
following constraints remain in the latest published parent releases; replacing
them requires an upstream release or a separately reviewed dependency migration.

| Parent dependency | Retained dependencies | Upgrade constraint |
| --- | --- | --- |
| Arkworks 0.6 | `educe` 0.6, `itertools` 0.14, `num-bigint` 0.4, `rand` 0.8, `rand_chacha` 0.3, `rand_core` 0.6, `getrandom` 0.2, `wasi` 0.11 | Arkworks fixes these major-version families. The direct WASM `getrandom` 0.2 dependency selects the entropy backend used by this stack; replacing it with 0.4 would leave that backend unconfigured. |
| Arkworks 0.6 and `sha3-kmac` 0.3 | `digest` 0.10, `block-buffer` 0.10, `crypto-common` 0.1 | Both parents still require the older digest family. `crypto-common` 0.1.7 additionally pins `generic-array =0.14.7`, preventing even 0.14.9. |
| `sha3-kmac` 0.3 | `sha3` 0.10, `keccak` 0.1, `cpufeatures` 0.2 | KMAC's SHA-3 dependency does not accept the current SHA-3 family. |
| `slh-dsa` 0.2.0-rc.5 | `sha3` 0.11 | Its SHA-3 requirement excludes 0.12. |
| `reallyme-buffa` 0.1.2 | `hashbrown` 0.15, `foldhash` 0.1 | The protobuf runtime requires these older families. |
| `reallyme-buffa-types` 0.1.2 | `jiff` 0.2, `jiff-static` 0.2, `jiff-core` 0.1 | Its timestamp implementation does not accept the 1.0 family. |
| `hashbrown` 0.17 | `allocator-api2` 0.2 | The latest hashbrown release still requires this allocator API family. |
| `openssl` 0.10 | `foreign-types` 0.3, `foreign-types-shared` 0.1 | The OpenSSL adapter does not accept their newer major versions. |
| `wasm-bindgen-test` 0.3.80 | `minicov` 0.3.8 | An exact upstream pin excludes 0.3.9. |
| `getrandom` 0.4 | `r-efi` 6 | The UEFI backend requires major version 6 rather than 7. |
| `jni` 0.22 and `windows-sys` 0.61 | `windows-link` 0.2 | Their Windows bindings exclude the newer 0.100 family. |
| Arkworks, curve derivation, JNI, OpenSSL, zeroization, and timestamp procedural macros | `syn` 2 | Their macro implementations still require syn 2. The graph also contains syn 3 for parents that support it. |

The existing `x448` 0.14.0-pre.12, `ed448-goldilocks` 0.14.0-pre.15, and
`slh-dsa` 0.2.0-rc.5 releases remain the newest published versions in their
respective release lines. Stable successors are not yet published. Retaining
them avoids downgrades and preserves the existing algorithm implementations and
public APIs. No new prerelease dependency or advisory exception was introduced.

`cargo outdated --workspace` also reports removal candidates when it models
replacing the WASM entropy adapter with `getrandom` 0.4. Those removals are an
artifact of dropping the required 0.2 JavaScript backend, not applicable updates.
Renamed workspace dependencies can produce lookup warnings in that tool;
`cargo upgrade --dry-run --incompatible allow --pinned allow --rust-version 1.96`
and the registry metadata were also checked to cover those dependencies.

Validation passed formatting, strict all-target/all-feature Clippy, workspace
compilation on Rust 1.100 and the Rust 1.96 MSRV, native compilation, WASM
compilation, all standalone fuzz-target checks, and the complete release-readiness
gate. The all-feature Rust suite passed 1,419 tests; the native nextest run passed
1,222 tests. Each retained 24 existing ignored or skipped tests. Rust test builds
used two build jobs with debug symbols and incremental compilation disabled.
