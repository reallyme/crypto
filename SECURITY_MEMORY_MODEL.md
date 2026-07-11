<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Security Memory Model

## Scope

This document defines the baseline memory-safety and secret-handling model for the ReallyMe crypto workspace.

Scope covers:

- Primitive crates under `crates/crypto/primitives/`
- Protocol crates under `crates/crypto/protocols/`
- Shared typed error and boundary types under `crates/crypto/core/`
- Native Rust, WebAssembly, Swift, Kotlin/JVM, and Kotlin/Android runtime lanes
- FFI adapters that move cryptographic material across platform boundaries
- SDK packages under `packages/swift`, `packages/kotlin`, and `packages/ts`

Protocol crates may impose stricter rules. They must not weaken this model.

## Data Inventory

| Data class | Examples | Sensitivity | Required owner model |
| --- | --- | --- | --- |
| Root secrets | Long-lived root keys and derivation inputs | Critical | Fixed-size secret owner, `ZeroizeOnDrop`, no `Debug`/`Display` |
| Derived keys | AEAD keys, HKDF outputs, session keys, and domain-separated secrets | Critical | Fixed-size secret owner or `Zeroizing`, zeroized on drop |
| KDF inputs | Password bytes, passphrases, client secrets, salts where policy treats them as sensitive | High/Critical | Secret wrapper for caller-owned secret input; typed non-secret wrapper for salts |
| Plaintext | Decrypted sensitive payloads and protocol plaintext | High/Critical | Zeroizing owner with explicit FFI destroy path |
| Public crypto material | Public keys, nonces, salts, digests, ciphertext | Integrity-sensitive | Typed wrappers; not interchangeable with arbitrary bytes |
| Authentication artifacts | AEAD tags, signatures, proofs, transcript bindings | Integrity-sensitive | Typed wrappers and constant-time verification where applicable |
| Platform handles | Swift/Kotlin/WASM opaque handles to Rust-owned secrets | Critical | Explicit destroy/zeroize path; no managed string transport for secrets |

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
- FFI exports prefer opaque Rust-owned handles for plaintext and private material.
- If a platform lane must copy sensitive bytes into platform memory, the adapter must document why and provide a destroy path.

### 4. Clear / Drop

- Owner types zeroize on drop.
- Temporary buffers are zeroized before returning where drop timing is not enough.
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

- Cipher suite identifier MUST be bound into AAD for all AEAD operations.
- Policy/verification code must reject decrypt if reconstructed AAD does not match exactly.
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
- Platform caps are enforced before use:
  - `MobileModern`: mem <= 512 MiB, t <= 4, p <= 4
  - `DesktopModern`: mem <= 2 GiB, t <= 6, p <= 4
- Argon2id is Rust on every lane (see `PROVIDER_POLICY.md`); it is never satisfied
  by a JCA/BouncyCastle or third-party native provider.

### FFI Secret Handling

- Decrypted plaintext must remain Rust-owned behind opaque handles.
- FFI should expose:
  - decrypt -> handle
  - read(handle, out_buf) -> bytes_written
  - destroy(handle)
- Avoid passing plaintext as Swift/Kotlin managed strings/arrays where possible.
- Always provide explicit destroy paths and zeroize secret buffers on drop.

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
