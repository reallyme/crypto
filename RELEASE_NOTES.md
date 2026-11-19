# Release Notes

## 0.4.3

- Adds Rust-only incremental SHA-256 and SHA3-256 with fallible updates and
  consuming finalization. One-shot digest bytes are unchanged. There are no
  incremental Swift, Kotlin, TypeScript, C ABI or WASM entry points.
- Aligns optional JWK `alg`, `use` and `kid` null handling across SDKs and accepts
  standard uncompressed P-curve verification keys in TypeScript.
- Kotlin HPKE, post-quantum operations and software P-curve ECDH use Rust JNI.
  Load the native provider before using them; there is no BouncyCastle fallback.
- Removes Kotlin's public deterministic encapsulation test helper; use the
  randomized production API.
- Requires canonical ECDSA DER and standard SEC1 encodings across supported
  verification/agreement routes. Compact `0x05` and hybrid keys are rejected.

## 0.4.2

- Adds bounded Rust and symbolic HPKE verification harnesses. See
  [formal verification](formal/README.md) for commands and scope limits.

## 0.4.1

- Fixes Swift Build compatibility when linking Crypto alongside CSecp256k1.

## 0.4.0

- Rust now returns canonical `CryptoErrorReason` values instead of
  per-operation variants. SDK facades retain their typed errors.
- Preserves the published protobuf field numbers and encodings.
- Deprecated `generate_x25519_keypair` and `generate_secp256k1_keypair` now
  return `Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError>`. Handle failures
  with `?` or an explicit match; `try_generate_*` remains preferred.
- Adds protected prime-group and RSA representative operations and guarded
  secret storage in generated Rust messages.

## 0.3.17

- Makes HPKE sender and receiver contexts `Send` for single-owner transfer
  between threads. They remain non-`Sync`, non-cloneable and non-serializable.
- Adds `P256Sha256Digest` and explicit P-256 message/digest signing and
  verification APIs. Existing entry points are deprecated but remain compatible.
- Android uses compile SDK 37 and Android Gradle Plugin 9.5.1; minimum API 26
  and existing wire formats are unchanged.

## 0.3.16

- Updates `ctutils`, HPKE and WASM bindings, including upstream lifetime and
  argument-release fixes. Rust MSRV remains 1.96.

## 0.3.15

- Updates `crypto-bigint` and `ctutils` for `RUSTSEC-2026-0387` and
  `RUSTSEC-2026-0385`. Refresh application Cargo lockfiles to select the fixes.

## 0.3.14

- Android hardware-backed P-256 key inspection checks every required purpose
  before accepting an existing Keystore key.

## 0.3.13

- Adds strict P-256 low-S normalization for DER and 64-byte `r || s` signatures
  across Rust, C, Swift, Kotlin, Android and TypeScript.
- Applies normalization to Secure Enclave and Android Keystore signing results.
  External biometric signing flows can normalize completed results explicitly.

## 0.3.11

- Packages Swift FFI as a dynamic XCFramework. Applications integrating it
  directly must embed and sign it.

## 0.3.10

- Adds Rust BN254 Poseidon2 hashing behind `poseidon2`, with a 515-byte input
  limit, and explicit P-256 prehashed ECDSA helpers.
- Requires Swift 6.3+ and uses typed Swift throws.
- Rejects noncanonical, low-order and non-prime-subgroup Ed25519 keys in
  verification and public-key envelopes. Previously accepted keys can now fail.
- **SDK migration:** MAC verification in Swift, Kotlin and TypeScript returns
  no value on success and throws on failure. Replace boolean branching with
  typed error handling.
- Requires canonical X25519 field elements in public-key encode/decode and
  JWK/multikey identities. RFC 7748 agreement retains its input rules.
- Requires at least 32 bytes of secret IKM for raw HPKE derivation. Callers must
  supply at least 256 bits of entropy; length alone cannot establish that.
- Adds caller-owned Secure Enclave key references and Android hardware ECDH
  completion. Tightens TypeScript provider identity and protobuf input bounds.
- Accepts optional matching JWK metadata, public `kid`, `x-*` extensions and
  set-level JWKS metadata; conflicting key use and private members remain invalid.

## 0.3.9

- Adds MLS profiles for ML-KEM-768/ML-DSA-65 and X-Wing/Ed25519 using
  HPKE HKDF-SHA384 and AES-256-GCM.

## 0.3.8

- Allows HPKE HKDF contexts larger than 64 KiB for MLS Welcomes. SHAKE context
  limits remain enforced.

## 0.3.7

- Offers project-owned code under MIT or Apache-2.0. Third-party licenses remain
  unchanged. Improves secret-buffer cleanup, FFI validation and public-key import.

## 0.3.5

- Replaces yanked `chacha20` 0.10.1 with 0.10.2 and updates cryptographic
  dependencies. Refresh application lockfiles when upgrading.

## 0.3.3

- Corrects the three MLS draft-profile aliases from HPKE SHAKE256 to draft-06
  HKDF-SHA384 (`0x0002`). This changes traffic keys and ciphertexts relative to
  0.3.1/0.3.2: upgrade all participants together.
- For legacy data, explicitly select `HPKE_MLKEM1024_SHAKE256_AES256GCM` or
  `HPKE_MLKEM1024P384_SHAKE256_AES256GCM` rather than an MLS alias.

## 0.3.2

- Adds individual HPKE KEM/KDF/AEAD features and the narrow `hpke-openmls`
  aggregate. Its original SHAKE256 MLS mapping is superseded in 0.3.3.
- Exact-pins workspace crate dependencies to the same release version.

## 0.3.1

- Adds suite-generic live PSK sender/receiver contexts and arbitrary-length
  HPKE key derivation, plus MLS profile aliases.
- Changes `MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384` from 0.3.0's HKDF-SHA384
  to SHAKE256. This is not ciphertext-compatible with 0.3.0; use an explicit
  suite for historical data. Version 0.3.3 restores the draft-06 HKDF-SHA384 map.

## 0.3.0

- Adds `CryptoOperationRequest`/`CryptoOperationResponse` processing across
  Rust and SDKs. Structured callers use `operation_contract::process_operation_response`
  or the SDK's `processOperationResponse`. Secret-bearing requests are binary-only.
- Removes permissive DER parsers, `messaging-dispatch`, no-op dispatch feature
  aliases, and the `constant_time`/`operation_response` forwarding modules.
  Use strict converters, `messaging-primitives`, real algorithm features,
  `operations::constant_time` and `operation_contract`.
- AES-KW callers pass slices directly to `wrap_key*` and `unwrap_key*`.
  Replace removed `AesKwKeyData::into_vec` with `into_zeroizing`.
- TypeScript KDF methods use family-specific selectors. Swift's development
  library loader requires an absolute path.

## 0.2.1

- Adds KMAC256 and AES-128/192-KW alongside AES-256-KW.
- Assigns permanent sparse protobuf algorithm identifiers and reserves retired
  assignments. These are distinct from external registry identifiers.

## 0.2.0

- The legacy `reallyme.codec.v1` protobuf/package surface was removed in favor
  of the standalone Codec packages. This is not a `reallyme.crypto.v1` wire break.
  The old package name is permanently retired in this repository.
