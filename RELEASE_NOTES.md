# Release Notes

## 0.4.6

- Updates Codec dependencies to 0.4.6 across Rust, Swift, Kotlin, Android and
  TypeScript.
- Updates build tools and patches vulnerable build dependencies. Gradle plugin
  classpaths are locked, and build-tool advisories block CI.
- Android now resolves Kotlin stdlib 2.4.21 through Codec. Kotlin 2.2 consumers
  need a newer compiler.

## 0.4.5

- Updates Codec dependencies to 0.4.5 across Rust, Swift, Kotlin, Android and
  TypeScript.

## 0.4.4

- Requires Rust 1.100.0 for Buffa 0.1.3. Generated owned views use
  non-cloneable clearing storage.
- Adds incremental SHA-256 and SHA3-256 for Rust only; there are no incremental
  Swift, Kotlin, TypeScript, C ABI or WASM entry points.
- Optional JWK `alg`, `use` and `kid` accept null as absent across SDKs.
- TypeScript accepts standard uncompressed P-curve verification keys.
- Kotlin HPKE, post-quantum operations and software P-curve ECDH require Rust
  JNI. Load the native provider first; there is no BouncyCastle fallback.
- Removes Kotlin's public deterministic encapsulation test helper.
- Requires canonical ECDSA DER and standard SEC1 encodings. Compact `0x05`
  and hybrid keys are rejected.

## 0.4.1

- Fixes Swift linking alongside CSecp256k1.

## 0.4.0

- Rust operations return canonical `CryptoErrorReason` values. SDK facades
  retain their typed errors. Preserves the published protobuf field numbers.
- Deprecated `generate_x25519_keypair` and `generate_secp256k1_keypair` now
  return `Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError>`. Handle failures
  with `?` or an explicit match; `try_generate_*` remains preferred.

## 0.3.17

- Makes HPKE sender and receiver contexts `Send`; they remain non-`Sync`.
- Adds explicit P-256 message/digest signing APIs and `P256Sha256Digest`.
- Android builds require Android Gradle Plugin 9.5.1 and compile SDK 37;
  minimum API 26 and existing wire formats are unchanged.

## 0.3.15

- Updates `crypto-bigint` and `ctutils` for `RUSTSEC-2026-0387` and
  `RUSTSEC-2026-0385`. Refresh application Cargo lockfiles to select the fixes.

## 0.3.14

- Rejects Android Keystore P-256 keys missing a required purpose.

## 0.3.13

- Normalizes canonical P-256 DER or 64-byte `r || s` signatures to low-S.
  External biometric signing flows can normalize completed results explicitly.

## 0.3.11

- Swift FFI is a dynamic XCFramework. Applications integrating it directly
  must embed and sign it.

## 0.3.10

- Requires Swift 6.3+ and uses typed Swift throws.
- MAC verification in Swift, Kotlin and TypeScript returns no value on success
  and throws on failure. Replace boolean branching with typed error handling.
- Rejects noncanonical, low-order and non-prime-subgroup Ed25519 keys.
- Requires canonical X25519 field encodings in JWK/multikey identities;
  RFC 7748 agreement retains its input rules.
- HPKE derivation requires at least 32 bytes of caller-supplied high-entropy IKM.
- JWK import accepts matching optional metadata and `x-*` extensions while
  rejecting conflicting key use and private-key members.

## 0.3.7

- Offers project-owned code under MIT or Apache-2.0. Third-party licenses
  remain unchanged.

## 0.3.5

- Replaces yanked `chacha20` 0.10.1 with 0.10.2. Refresh application lockfiles.

## 0.3.3

- Restores HPKE HKDF-SHA384 (`0x0002`) for the three MLS draft-profile aliases.
  Versions 0.3.1 and 0.3.2 used SHAKE256, producing different traffic keys and
  ciphertexts. Upgrade all participants together.
- For legacy data, explicitly select `HPKE_MLKEM1024_SHAKE256_AES256GCM` or
  `HPKE_MLKEM1024P384_SHAKE256_AES256GCM` rather than an MLS alias.

## 0.3.0

- Structured callers use `operation_contract::process_operation_response` or
  SDK `processOperationResponse`. Secret-bearing requests are binary-only.
- Removes `messaging-dispatch`, no-op dispatch features, and the `constant_time`
  and `operation_response` forwarding modules. Select `messaging-primitives`,
  real algorithm features, `operations::constant_time` and `operation_contract`.
- AES-KW callers pass slices to `wrap_key*` and `unwrap_key*`; replace
  `AesKwKeyData::into_vec` with `into_zeroizing`.
- TypeScript KDF methods use family-specific selectors. Swift's development
  library loader requires an absolute path.

## 0.2.0

- The legacy `reallyme.codec.v1` protobuf/package surface moved to Codec.
  This is not a `reallyme.crypto.v1` wire break; the old package is retired.
