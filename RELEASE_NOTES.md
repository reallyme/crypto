<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Release Notes

## 0.3.1

### Compatibility notice

`0.3.0` already exported
`MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384`, but incorrectly assigned
HPKE HKDF-SHA384 to it. `0.3.1` corrects that existing constant to the draft's
HPKE SHAKE256 KDF (`0x0011`). This changes derived HPKE traffic state and
ciphertext compatibility for callers that used the `0.3.0` constant. Such
deployments must coordinate the upgrade; historical data can be opened by
constructing the former explicit `(MLKEM1024-P384, HKDF-SHA384, AES-256-GCM)`
triple. The other two MLS profile aliases listed below are new in `0.3.1`.

- Adds a split HPKE PSK sender setup for OpenMLS targeted messages. Sender
  setup returns the encapsulated key and an opaque, non-exportable context so
  callers can bind the KEM output into AAD before sealing; single-shot PSK seal
  and open now use the same sender and receiver context implementation paths.
- Adds deterministic HPKE keypair derivation from non-empty arbitrary-length
  IKM by delegating to each KEM's registered `DeriveKeyPair` procedure,
  removing adapter-owned MLS secret normalization. A fixed
  OpenMLS/libcrux X-Wing draft-06 compatibility vector locks the deployed
  arbitrary-IKM private key and complete public-key fingerprint. Raw Rust
  callers retain the KEM-defined non-empty input contract; operation and
  serialized boundaries require at least 32 bytes of high-entropy IKM.
- Adds exact MLS draft-profile aliases for the 192-bit ML-KEM-1024/P-384,
  256-bit ML-KEM-1024/ML-DSA-87, and 192-bit MLKEM1024-P384/P-384 profiles.
  `SHA384` in these names is the MLS transcript hash; each alias selects the
  registered HPKE SHAKE256 KDF (`0x0011`), not HPKE HKDF-SHA384.
  Deterministic Base seal and split PSK setup coverage for all three profiles
  is available only through the `test-vectors` feature.
- Makes the root Rust HPKE error boundary explicit with `*_operation` aliases
  returning `OperationError` and `*_raw` aliases returning `HpkeError` directly
  for protocol adapters.
- Adds operation-layer deterministic Base seal and sender-export APIs behind
  `test-vectors`, preserving secret-material policy binding and typed operation
  errors while producing stable OpenMLS conformance data.
- Adds suite-generic PSK receiver setup and live receiver contexts alongside
  sender contexts. New setup APIs require validated `HpkePskRef` and
  `HpkePskIdRef` values; published single-shot request structs remain
  source-compatible for the patch release.
- Routes protobuf HPKE key derivation through arbitrary-length IKM semantics and
  regenerates hardened Rust, Swift, Kotlin/Java, and TypeScript bindings.
  Serialized operation-contract and C ABI tests now cover the ML-KEM-1024,
  MLKEM1024-P384, and X-Wing HPKE suites, including negative boundaries.

## 0.3.0

- Establishes the protobuf schema as the source of truth for executable
  structured requests, responses, algorithm identifiers, and wire errors.
  Rust, Swift, Kotlin, and TypeScript adapters process generated
  `CryptoOperationRequest` messages and return generated
  `CryptoOperationResponse` bytes through one operation contract.
- Gives each primitive and protocol family a single semantic owner. Native,
  JNI, FFI, and WASM adapters validate their boundary and delegate to that
  owner; provider selection is explicit, generated from the reviewed manifest,
  and fails closed without ambient or silent fallback.
- Ships package-owned Rust WASM implementations for the Rust-routed algorithm
  lanes. Browser and Node consumers receive the generated WASM artifact in the
  npm package and use it only through the typed TypeScript provider facade.
- Hardens secret-bearing generated Rust messages with redacted debug output,
  drop-time zeroization, disabled serde serialization for sensitive generated
  views, bounded protobuf and ProtoJSON decoding, and typed errors that do not
  contain raw input or backend exception text. Executable ProtoJSON accepts
  only the eight request selectors without caller-provided key material or
  PSKs; binary protobuf remains the complete operation transport.
- Publishes dedicated release paths for crates.io, npm, SwiftPM binary
  artifacts, JVM Maven artifacts, and the Android AAR. Each workflow verifies
  the package assembled from the tagged commit before publication.
- This is a breaking Rust API release relative to `0.2.x`. Structured callers
  must construct a generated `CryptoOperationRequest` branch and use
  `operation_contract::process_operation_response` or the SDK
  `processOperationResponse` helper.
- Removes compatibility-only Rust surfaces that had no workspace production
  callers: permissive P-256 and secp256k1 DER parsers, the
  `messaging-dispatch` feature alias, no-op dispatch feature aliases, and the
  `constant_time` and `operation_response` forwarding modules. Use the strict
  signature converters, `messaging-primitives`, real algorithm features,
  `operations::constant_time`, and `operation_contract`, respectively.
- AES-KW callers now pass plaintext and wrapped-key slices directly to
  `wrap_key*` and `unwrap_key*`. `AesKwKeyData::from_slice` and
  `AesKwWrappedKey::from_slice` are removed, and plaintext ownership transfer
  uses `AesKwKeyData::into_zeroizing` instead of the unprotected
  `AesKwKeyData::into_vec` return.
- The Rust release graph now resolves the ReallyMe Codec `0.2.x`
  compatibility line exclusively from crates.io. The workspace and fuzz
  lockfiles record registry sources and reviewed checksums for the transitive
  base64url, JCS, multibase, multicodec, multikey, and PEM crates; release
  validation no longer depends on an adjacent Codec checkout.
- ReallyMe Codec `0.2.0` is a breaking pre-1.0 compatibility line relative to
  `0.1.x`. Consumers extending the Crypto JWK, multikey, canonicalization, or
  PEM surfaces must update against Codec `0.2.x` rather than assuming `0.1.x`
  source compatibility.
- TypeScript KDF facade parameters now use family-specific selector unions.
  PBKDF2, HKDF, JWA Concat KDF, KMAC, and versioned Argon2id remain distinct
  compile-time routes instead of accepting selectors that can only be rejected
  at runtime.
- Swift caller-owned byte cleanup uses Darwin `memset_s` to prevent elision of
  the current-storage overwrite. The development-only dynamic-library loader
  now requires an absolute path, and the non-interactive Secure Enclave ECDH
  access policy is explicit in the public documentation.
- The npm registry record for `@reallyme/crypto@0.3.0` reports 84 packaged
  files, an unpacked size of 3,724,373 bytes, shasum
  `40b595f91620c7c118a5e0e9ecc48f6fee7e1719`, and integrity
  `sha512-rbRI0tRUdoyFck8cBP6HSpvQN5bCOvpwJWTX0QHbrchQniIf8UGlF+Vy2ecBaR3RHDitWsfyQEaC6AejHG8pBA==`.

## 0.2.1

- Adds KMAC256 and extends AES-KW from AES-256 to AES-128/192/256 across the
  supported Rust and SDK provider lanes, with generated cross-lane
  conformance vectors.
- Hardens the existing ML-KEM-512/768/1024 WASM bridges by catching provider
  exceptions, validating returned lengths, and clearing transient JavaScript
  secret buffers.
- Enforces independent output ownership at TypeScript provider boundaries,
  rejects all FFI input/output and cross-output aliases before writes, and
  keeps PBKDF2 and AES-KW plaintext outputs in zeroizing Rust owners.
- Pins platform-provider routing to the audited provider manifest and fails
  closed when a required Rust, WASM, JCA/JCE, or native provider is
  unavailable. Non-Rust routes are checked to remain isolated from Rust
  bridges.
- Extends the generated Crypto protobuf and strict Buffa proto-JSON surface
  for the new operations and algorithm selectors. Every public package
  algorithm now has exactly one typed selector. Family enums use sparse,
  documented subfamily bands and ten-value spacing within related groups.
  Post-quantum and hybrid algorithms use values at `1000+`; superseded dense
  values are reserved so they cannot be silently reinterpreted. Assignments
  are immutable after this release and remain distinct from IANA registry
  values.

## 0.2.0

- ReallyMe Crypto now treats the canonical SDK contract as the combination of
  protobuf messages and enums, provider manifest policy, typed errors,
  algorithm identifiers, and cross-language conformance vectors.
- The legacy `reallyme.codec.v1` protobuf/package surface was removed from
  this repository because Codec is now consumed from the standalone
  ReallyMe Codec packages. This is a package and repository surface removal,
  not a `reallyme.crypto.v1` wire break; the Crypto protobuf changes in this
  release are additive. The `reallyme.codec.v1` package name is permanently retired in this repository and must not be reused here.
