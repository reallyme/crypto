<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Security Memory Model

## Scope

This document defines the memory-safety and secret-handling model for the
ReallyMe Crypto workspace.

Scope covers:

- Cryptographic family crates under `crates/`
- Protocol crates such as HPKE under `crates/hpke/`
- Shared typed error and boundary types under `crates/crypto/core/`
- Native Rust, WebAssembly, Swift, Kotlin/JVM, and Kotlin/Android runtime lanes
- FFI adapters that move cryptographic material across platform boundaries
- SDK packages under `packages/swift`, `packages/kotlin`,
  `packages/kotlin-android`, and `packages/ts`

Protocol crates may impose stricter rules. They must not weaken this model.

## Data Inventory

| Data class | Examples | Sensitivity | Required owner model |
| --- | --- | --- | --- |
| Root secrets | Long-lived root keys and derivation inputs | Critical | Fixed-size secret owner, `ZeroizeOnDrop`, no `Debug`/`Display` |
| Derived keys | AEAD keys, HKDF outputs, session keys, and domain-separated secrets | Critical | Fixed-size secret owner or `Zeroizing`, zeroized on drop |
| KDF inputs | Password bytes, passphrases, client secrets, salts where policy treats them as sensitive | High/Critical | Secret wrapper for caller-owned secret input; typed non-secret wrapper for salts |
| Plaintext | Decrypted sensitive payloads and protocol plaintext | High/Critical | Rust-owned values use `Zeroizing` or a destroyable owner; managed SDK byte arrays are caller-owned and best-effort clearable |
| Public crypto material | Public keys, nonces, salts, digests, ciphertext | Integrity-sensitive | Typed wrappers; not interchangeable with arbitrary bytes |
| Authentication artifacts | AEAD tags, signatures, proofs, transcript bindings | Integrity-sensitive | Typed wrappers and constant-time verification where applicable |
| Platform handles | Swift/Kotlin/WASM opaque handles to Rust-owned secrets | Critical | Explicit destroy/zeroize path where exposed; no managed string transport for secrets |

## Lifecycle Model

### 1. Ingest

- External bytes enter as untrusted input.
- Length and shape checks happen before parsing or allocation-heavy work.
- Buffer lengths, offsets, and capacities use checked arithmetic.
- Secret-bearing inputs are moved into explicit secret owner types as early as the API allows.

### 2. Operate

- Cryptographic operations run on bounded inputs with typed domain separation.
- Temporary secrets use `Zeroizing<T>` or an owner that implements `ZeroizeOnDrop`.
- Authentication failures return typed errors and must not expose backend exception text, raw input, or secret-bearing context.
- Comparisons of MACs, tags, signatures, and derived values use constant-time primitives when the value is security-sensitive.

### 3. Export

- Public outputs use typed wrappers.
- Secret outputs stay in secret owner types.
- FFI exports prefer opaque Rust-owned handles for long-lived plaintext and private material.
- If a platform lane copies sensitive bytes into Swift, Kotlin, TypeScript, JVM, Android, or browser-managed memory, the adapter must document the best-effort cleanup boundary and avoid overstating zeroization guarantees.

### 4. Clear / Drop

- Owner types zeroize on drop.
- Temporary buffers are zeroized before returning where drop timing is not enough.
- FFI, JNI, WASM, and platform FFI adapters zeroize Rust-owned temporary inputs,
  plaintexts, shared secrets, derived keys, and secret-bearing output staging
  buffers after copying to the caller-owned result or before throwing from a
  native/provider error path.
- Managed-runtime cleanup helpers overwrite the caller-owned byte array view only; they cannot clear historical runtime, provider, protobuf, debugger, crash-report, or garbage-collector copies.
- Public SDK containers that carry private keys or shared secrets must redact
  string/debug output and must not compute object hash codes from secret bytes.
- Stateful protocol code must provide explicit session teardown when secrets can outlive a single call.
- Tests that inspect secret internals must keep that access local to the test crate and avoid logging raw values.

## Implemented Controls

| Control | Status | Evidence |
| --- | --- | --- |
| Workspace panic/unwrap/debug-print denies | Implemented | Root `Cargo.toml` workspace lints |
| Member lint inheritance | Implemented | Every member `Cargo.toml` has `[lints] workspace = true` |
| Typed domain errors | Implemented | `core/src/error.rs`, primitive-specific `ErrorReason` use |
| Zeroizing secret wrappers | Implemented for secret-bearing primitives | AES/KDF/HKDF key and secret owner types |
| Runtime lane separation | Implemented as feature lanes and package matrix entries | `native`, `wasm`, `swift`, `kotlin` feature checks; backend matrix in `PROVIDER_POLICY.md` |
| Negative-vector policy | Implemented as workspace policy | `vectors/README.md`, `CONTRACT.md`, `PROVIDER_POLICY.md` |
| Managed-runtime best-effort cleanup helpers | Implemented for Swift, Kotlin, and TypeScript | `ReallyMeCryptoMemory.bestEffortClear`, `bestEffortClear(bytes)` |
| Dependency policy gate | Implemented | `deny.toml` |
| Apache-2.0 source headers | Implemented | SPDX headers on hand-written workspace files |

## Hardening Expectations

Every primitive must define:

- Allowed input sizes and maximum allocation sizes.
- Which values are secret, public, or integrity-sensitive.
- Which values must be domain-separated.
- Which errors are intentionally generic to avoid oracle behavior.
- Which runtime lanes are complete, guarded, or intentionally unavailable.
- Which negative vectors prove failure behavior.

## Primitive Security Notes

Engineering rules that apply across primitives and protocols:

### Cipher Suite Binding

- Protocol and message-format layers that compose AEAD MUST bind their cipher-suite identifier into AAD before calling generic AEAD primitives.
- Generic AEAD primitive and dispatch APIs treat `aad` as caller-provided bytes and do not mutate, prepend, or validate higher-level suite identifiers.
- Policy/verification code must reject decrypt if reconstructed protocol AAD does not match exactly.
- This prevents cross-suite confusion and downgrade-style misuse.

### HKDF Domain Separation

- Derive per-domain subkeys from root material using HKDF.
- Use explicit purpose tags and domain tags.
- Never reuse the same derived key across domains or purposes.

### Argon2id Policy

- Only fixed, code-pinned profiles are allowed (`kdf_version` mapping).
- Current profiles:
  - `V1` (kdf_version=1): 256 MiB, t=3, p=1
  - `V2` (kdf_version=2): 512 MiB, t=3, p=1
- The caller owns the complete Argon2 block matrix in a `Zeroizing<Vec<Block>>`;
  password-derived working memory is wiped before the allocation is released on
  success, typed failure, or unwind.
- Platform caps are enforced before use:
  - `MobileModern`: mem <= 512 MiB, t <= 4, p <= 4
  - `DesktopModern`: mem <= 2 GiB, t <= 6, p <= 4
- Argon2id is Rust on every lane (see `PROVIDER_POLICY.md`); it is never satisfied
  by a JCA/BouncyCastle or third-party native provider.

### PBKDF2 Work-Factor Policy

- Public PBKDF2 routes accept 100,000 through 10,000,000 iterations.
- Both bounds are validated before native, WASM, Swift, Kotlin, or TypeScript
  derivation so a compact untrusted request cannot select unbounded CPU work.
- The generic KDF protobuf branch intentionally does not execute Argon2id: its
  `iterations` field cannot represent the reviewed Argon2 `kdf_version`
  profiles. Dedicated versioned Argon2id APIs remain the supported route.

### FFI Secret Handling

- The preferred model for long-lived or high-volume plaintext, private material,
  shared secrets, passwords, and derived keys is a Rust-owned opaque handle with
  an explicit destroy path.
- Current SDK facade methods may return Swift `[UInt8]`, Kotlin `ByteArray`,
  and TypeScript `Uint8Array` values for ergonomic one-shot operations. Those
  arrays are managed-runtime copies. They are caller-owned and best-effort
  clearable, not guaranteed-zeroized storage.
- FFI/JNI/WASM adapters must zeroize Rust-owned temporary buffers after copying
  results to the platform lane. That cleanup does not erase platform-owned
  arrays, provider-internal copies, protobuf serialization buffers, or runtime
  copies made before the caller clears them.
- Executable ProtoJSON accepts only request selectors without caller-provided
  secret material. Secret-bearing selectors are rejected before serde value
  deserialization and must use the binary protobuf boundary.
- Generated protobuf `View` and `OwnedView` types that can retain sensitive or
  privacy-bearing bytes fail serde `Serialize` with a fixed error. ProtoJSON is
  produced only from owned messages at an explicit, policy-approved boundary;
  callers must not serialize or log views as a substitute for that boundary.
- Swift CryptoKit and Security.framework ECDH routes copy shared secrets through
  provider-managed `Data` or opaque shared-secret storage before the package
  creates caller-owned `[UInt8]` results. The Swift wrappers best-effort clear
  those owned arrays on validation failure, but provider-managed intermediates
  remain a managed-runtime residual risk.
- Do not pass secret-bearing values as managed strings. Avoid JSON paths for
  private keys, plaintext, passwords, shared secrets, and derived keys.
- New APIs that keep secret material alive beyond a single call should expose an
  explicit destroy/zeroize path rather than only returning managed byte arrays.

### Managed Runtime Cleanup

The SDKs expose narrow helpers for caller-owned arrays:

- Swift: `ReallyMeCryptoMemory.bestEffortClear(&bytes)`
- Kotlin/JVM and Kotlin/Android: `ReallyMeCryptoMemory.bestEffortClear(bytes)`
- TypeScript: `bestEffortClear(bytes)`

These helpers overwrite the supplied byte array view in place. The Swift helper
uses Darwin `memset_s` so the current-storage writes cannot be optimized away.
They are useful for clearing keys, passwords, plaintext, shared secrets, salts,
and derived keys as soon as application code no longer needs them. They do not
and cannot clear copies already made by ARC, JVM or Android garbage collectors,
JavaScript engines, WebAssembly marshalling, protobuf codecs, native providers,
crash reporters, debugger snapshots, swap, hibernation, or application logs.

## Residual Risks

1. Zeroization cannot remove all copies created by the OS, allocator, CPU, compiler, browser runtime, or platform managed runtimes.
2. FFI callers can copy or log sensitive bytes after receiving them; Rust-side controls cannot erase caller-owned copies.
3. Crash reporters, telemetry, swap, hibernation, and process snapshots remain deployment responsibilities.
4. Browser and mobile managed runtimes provide best-effort memory hygiene only.
5. Public-key and ciphertext wrappers prevent type confusion, but they do not by themselves prove authenticity.
6. The SDK packages in `packages/kotlin` and `packages/ts` hold secret bytes in garbage-collected arrays
   (`ByteArray`, `Uint8Array`). The JVM and JavaScript runtimes give no reliable way to zeroize or pin such memory:
   collectors copy and compact objects freely, so overwriting an array clears one copy at best. This is an accepted
   platform limitation, not an oversight. Deployments needing stronger key hygiene on those platforms must keep
   long-lived secrets in platform key stores (for example Android Keystore) or behind the Rust C ABI's owned buffers
   rather than in language-level arrays. The Swift package has the same property for Swift-managed arrays, with
   CryptoKit `SymmetricKey` and the Secure Enclave as the stronger alternatives.
7. Typed unsupported-algorithm behavior is a deliberate release control, not a
   memory-safety control. It prevents silent provider substitution, but callers
   still need to choose algorithms whose package lane is supported for their
   deployment.

## Mandatory Operational Controls

1. Disable raw request, plaintext, key, and error-context logging in applications that use this workspace.
2. Keep crash and diagnostic upload policies aligned with the sensitivity of plaintext and secret material.
3. Run the full workspace validation gate before merging crypto changes.
4. Require positive and negative vectors for every new primitive, backend, or security hardening change.
5. Treat FFI destroy/zeroize paths as part of the API contract, not cleanup polish.

## Audit Evidence

Required local gate:

```sh
cargo fmt --check
cargo check --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace --no-default-features --features native
cargo check --workspace --no-default-features --features native
cargo check --workspace --no-default-features --features wasm
node scripts/generate_provider_matrix.mjs --check
node scripts/check_release_readiness.mjs
cargo deny check
```
