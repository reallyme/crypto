<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Provider Policy

This policy defines the provider order for every public package algorithm. A
facade may use only the provider listed for its lane. If that provider is
unavailable on the supported platform floor or cannot satisfy the vector
contract, the facade returns a typed `unsupportedAlgorithm` or provider error.
It never silently selects a different provider or falls back after a provider
failure.

Provider policy is one part of the canonical Crypto contract, alongside the
proto-first operation schema, typed error taxonomy, package facade types, and
shared positive and negative conformance vectors. Rust is the reference and
shared implementation for selected primitives. Swift, Kotlin, Android, and
TypeScript may route to approved platform providers only when tests prove the
same contract.

## Selection Principle

The provider for each algorithm is chosen by one rule, applied per lane:

**Prefer the platform-native provider when the primitive is mature, standard, and
OS-supported, or when it carries hardware/key-residency benefits — and prefer
ReallyMe's Rust implementation (FFI on Swift/Kotlin, WASM on TypeScript) when the
primitive is specialized, post-quantum, memory-hard, protocol-composed, or easy
to get subtly wrong.**

Use the platform-native provider when *all* of the following hold:

- it is exposed by the OS or a first-tier platform API — CryptoKit,
  Security.framework, JCA/JCE, Android Keystore, Node `crypto`/WebCrypto, or a
  vetted `@noble/*` package on TypeScript;
- either the primitive is mature and widely implemented there (SHA-2, HMAC, HKDF, PBKDF2,
  AES-GCM, P-256 ECDH/ECDSA, X25519/Ed25519 where provider behaviour is stable)
  **or** it grants hardware/key-residency benefits (Secure Enclave, Keychain,
  Android Keystore, AES-NI, platform RNG);
- the output contract can be made byte-stable across every lane and is proven so
  by the shared conformance vectors.

Use ReallyMe Rust (FFI/JNI/WASM) when *any* of the following hold:

- the platform has no serious native provider for it;
- the best available implementation is already the audited Rust crate;
- cross-lane byte identity matters more than platform integration;
- the primitive is newer, post-quantum, memory-hard, protocol-composed, or
  otherwise error-prone — ML-KEM, ML-DSA, SLH-DSA, X-Wing, HPKE, AES-256-GCM-SIV,
  XChaCha20-Poly1305, and Argon2id;
- the only native option would add a third-party Swift or Kotlin dependency with
  less review than the selected Rust crate. Provider locality does not override
  implementation assurance.

Every provider route must implement identical input validation and
normalization, output encodings, typed failure semantics, and edge-case
behavior. A native provider is interchangeable only when shared vectors,
negative tests, and, where practical, differential tests against the
Rust/reference path prove that contract. For security-sensitive composition,
canonical serialization, deterministic signatures, post-quantum primitives,
memory-hard KDFs, and algorithms with ambiguous or provider-specific platform
behavior, keep execution in ReallyMe Rust unless an exception is explicitly
encoded in this policy and covered by tests.

Two policies are mandatory:

- **Argon2id is Rust on every lane.** CryptoKit/Security do not provide it,
  JCA/JCE does not provide it, and BouncyCastle's Argon2 is less reviewed than
  the workspace crate. Swift uses the Rust C ABI, Kotlin uses Rust via JNI, and
  TypeScript uses Rust via WASM. A facade must **not** satisfy Argon2id with a
  JCA/BouncyCastle or third-party Swift Argon2 provider.
- **No silent fallback, in either direction.** Each algorithm and lane selects
  one provider route. Provider lookup, authentication, verification, or
  operational failure is surfaced as the lane's typed error and is never
  retried through a different provider.

The per-family rationale below records how this rule lands for each group; the
hand-written Algorithm Policy table and generated Platform Backend Matrix are
independently checked against every package algorithm identifier.

## Family Rationale (what we do and why)

| Family | Swift | Kotlin/JVM/Android | TypeScript | Why |
|---|---|---|---|---|
| SHA-2 / SHA-3 / HMAC / HKDF / JWA Concat KDF / PBKDF2 | CryptoKit / Digest | JCA/JCE, BouncyCastle for SHA-3 | `@noble/hashes` | Mature, byte-stable primitives. Platform-native where exposed by package facades. |
| AES-128/192/256-GCM | CryptoKit | bundled BouncyCastle | ReallyMe WASM/Rust | Mature AEAD with hardware acceleration on native lanes. Kotlin pins the bundled provider so ambient provider order cannot change authentication semantics. TypeScript has no stable synchronous native AEAD, so it uses Rust WASM. |
| AES-128/192/256-KW (RFC 3394) | ReallyMe Rust C ABI | BouncyCastle | ReallyMe WASM/Rust | Deterministic key-wrap; byte-identical regardless of provider. Every facade enforces the exact RFC 3394 `n + 8` wrap and `n - 8` unwrap lengths. Kotlin routes through the bundled BouncyCastle provider directly to avoid Android provider-slot ambiguity. |
| P-256/384/521 ECDH / X25519 | CryptoKit | BouncyCastle / JCA | `@noble/curves` | Standard EC with stable provider behaviour; no determinism constraint on ECDH. All lanes fail closed on a non-contributory shared secret: P-256/384/521 reject an all-zero ECDH output and X25519 enforces the RFC 7748 contributory check, so a degenerate low-order / small-subgroup agreement returns a typed error rather than a predictable secret. This is intentional policy; a Wycheproof `valid` case whose shared secret is all-zero is therefore expected to be rejected. Native. |
| P-256/384/521 ECDSA sign, Ed25519 sign | ReallyMe Rust C ABI; P-256 also has a Secure Enclave handle-backed signing API | BouncyCastle deterministic ECDSA / Ed25519; Android P-256 also has an API 31+ Keystore / StrongBox handle route | `@noble/curves` | Raw signing must be deterministic (RFC 6979 / RFC 8032) and byte-identical across lanes, so Rust/BC deterministic signers are chosen for byte identity. Hardware-backed signing is a separate non-exportable-key route and is not expected to reproduce deterministic vectors. |
| secp256k1 ECDSA / BIP-340 Schnorr | `CSecp256k1` (Bitcoin Core libsecp256k1) | libsecp256k1 via `secp256k1-kmp` (JNI) | `@noble/curves` | The constant-time reference implementation is the same C library on native lanes; hand-rolled EC on secret scalars is a timing side-channel and is forbidden. |
| RSA verify (PKCS1v15 / PSS) | ReallyMe Rust C ABI | bundled BouncyCastle | ReallyMe WASM/Rust | Verification only. Kotlin pins signature and key parsing to the bundled provider so ambient JCA order cannot alter PSS or DER behavior. |
| Argon2id | ReallyMe Rust C ABI | ReallyMe Rust JNI through explicit provider load | ReallyMe WASM/Rust | Memory-hard KDF with **no** OS-native provider on any lane; one vetted Rust implementation everywhere. Never JCA/BC/third-party. |
| ML-KEM / ML-DSA / SLH-DSA / X-Wing / HPKE | ReallyMe Rust C ABI | BouncyCastle (explicit, KAT-proven) or Rust | ReallyMe WASM/Rust | Post-quantum / protocol-composed; error-prone to hand-assemble. Rust by default; BouncyCastle only when explicitly selected and locked to the shared KATs. |
| AES-256-GCM-SIV / XChaCha20-Poly1305 | ReallyMe Rust C ABI through provider-aware API | ReallyMe Rust JNI through explicit provider load | ReallyMe WASM/Rust | Newer nonce-misuse-resistant / extended-nonce AEADs with no first-tier native provider; Rust everywhere. Never a third-party native package. |

## Lane Hierarchies

Swift provider order:

1. CryptoKit or Security.framework, only when the API is available on the
   package floor and the bytes match the shared vectors.
2. `CSecp256k1`, only for secp256k1 operations.
3. A vetted Swift package already named in `ProviderCatalog.swift`, only when
   the facade has an explicit wrapper and shared-vector coverage.
4. ReallyMe Rust C ABI, only through provider-aware APIs that require a loaded
   ABI library.
5. Typed `unsupportedAlgorithm`.

Kotlin/JVM provider order:

1. JCA/JCE, only when provider behavior is byte-stable and the manifest route
   explicitly names it.
2. The bundled BouncyCastle instance only for algorithms whose manifest route
   explicitly names BouncyCastle.
3. ReallyMe Rust C ABI or JNI, only through explicit provider-aware APIs.
4. Typed `unsupportedAlgorithm`.

Kotlin/Android provider order:

1. The Android platform provider or Conscrypt, only when behavior is available
   on the package floor, byte-stable, and explicitly named by the manifest
   route.
2. The bundled BouncyCastle instance only for algorithms whose manifest route
   explicitly names BouncyCastle.
3. ReallyMe Rust C ABI or JNI, only through explicit provider-aware APIs.
4. Typed `unsupportedAlgorithm`.

Swift P-256 ECDH and P-256 ECDSA signing also expose separate Secure Enclave /
Keychain handle APIs for applications that need non-exportable private-key
residency or user-presence signing. The raw-byte ECDH facade still uses
CryptoKit, and the deterministic raw-byte ECDSA facade still uses ReallyMe Rust
C ABI; both remain distinct from the handle-backed APIs.

The Android AAR exposes P-256 signing and ECDH through the separate
`ReallyMeAndroidPlatformKeys` handle API. It hashes application tags into
purpose-separated aliases, requests TEE or StrongBox residency without
downgrade, verifies exact TEE or StrongBox residency through `KeyInfo`, and
rejects software-backed or indeterminate-security-level keys. The complete
platform-key API requires Android API 31. A requested StrongBox residency never
downgrades to TEE.
The raw-byte Kotlin APIs remain BouncyCastle routes and never fall back to
Android Keystore.

TypeScript provider order:

1. Audited synchronous JavaScript providers, currently pinned `@noble/curves`
   and `@noble/hashes`.
2. ReallyMe WASM/Rust, only through an explicit WASM provider wrapper.
3. Typed `unsupportedAlgorithm`.

WebCrypto is not a provider for the synchronous TypeScript facade because it
would force an incompatible asynchronous API shape. The TypeScript package
keeps hand-written validation for enum membership, byte lengths, buffer shape,
and provider result shape.

## Algorithm Policy

This table covers algorithms exposed by the cross-language package facades.
Standalone Rust-only primitives, including the direct X448 crate and the X448
component used internally by HPKE, are outside the package provider manifest.

| Algorithm identifier | Swift provider | Kotlin/JVM provider | Kotlin/Android provider | TypeScript provider |
|---|---|---|---|---|
| `Ed25519` | ReallyMe Rust C ABI through provider-aware facade overload | BouncyCastle | BouncyCastle | `@noble/curves` |
| `ECDSA-P256-SHA256` | ReallyMe Rust C ABI through provider-aware API for deterministic DER/SHA-256 signatures; Security.framework / Secure Enclave through handle-backed signing API | BouncyCastle deterministic ECDSA | BouncyCastle deterministic ECDSA; Android Keystore / StrongBox through `ReallyMeAndroidPlatformKeys` on API 31+ | `@noble/curves` with `@noble/hashes` SHA-256 prehash |
| `ECDSA-P384-SHA384` | ReallyMe Rust C ABI through provider-aware API for deterministic DER/SHA-384 signatures | BouncyCastle deterministic ECDSA | BouncyCastle deterministic ECDSA | `@noble/curves` with `@noble/hashes` SHA-384 prehash |
| `ECDSA-P521-SHA512` | ReallyMe Rust C ABI through provider-aware API for deterministic DER/SHA-512 signatures | BouncyCastle deterministic ECDSA | BouncyCastle deterministic ECDSA | `@noble/curves` with `@noble/hashes` SHA-512 prehash |
| `ECDSA-secp256k1-SHA256` | `CSecp256k1` with CryptoKit SHA-256 prehash | Bitcoin Core libsecp256k1 via `secp256k1-kmp` (JNI) | Bitcoin Core libsecp256k1 via `secp256k1-kmp` (JNI) | `@noble/curves` with `@noble/hashes` SHA-256 prehash |
| `BIP340-Schnorr-secp256k1-SHA256` | ReallyMe Rust C ABI through provider-aware API with explicit `auxRand32` | Bitcoin Core libsecp256k1 via `secp256k1-kmp` (JNI) through `ReallyMeCrypto.signBip340Schnorr` | Bitcoin Core libsecp256k1 via `secp256k1-kmp` (JNI) through `ReallyMeCrypto.signBip340Schnorr` | `@noble/curves` through `ReallyMeCrypto.signBip340Schnorr` with explicit `auxRand32` |
| `RSA-PKCS1v15-SHA1` | ReallyMe Rust C ABI through provider-aware verify API | bundled BouncyCastle | bundled BouncyCastle | ReallyMe Rust WASM verify API |
| `RSA-PKCS1v15-SHA256` | ReallyMe Rust C ABI through provider-aware verify API | bundled BouncyCastle | bundled BouncyCastle | ReallyMe Rust WASM verify API |
| `RSA-PKCS1v15-SHA384` | ReallyMe Rust C ABI through provider-aware verify API | bundled BouncyCastle | bundled BouncyCastle | ReallyMe Rust WASM verify API |
| `RSA-PKCS1v15-SHA512` | ReallyMe Rust C ABI through provider-aware verify API | bundled BouncyCastle | bundled BouncyCastle | ReallyMe Rust WASM verify API |
| `RSA-PSS-SHA1-MGF1-SHA1` | ReallyMe Rust C ABI through provider-aware verify API | bundled BouncyCastle | bundled BouncyCastle | ReallyMe Rust WASM verify API |
| `RSA-PSS-SHA256-MGF1-SHA256` | ReallyMe Rust C ABI through provider-aware verify API | bundled BouncyCastle | bundled BouncyCastle | ReallyMe Rust WASM verify API |
| `RSA-PSS-SHA384-MGF1-SHA384` | ReallyMe Rust C ABI through provider-aware verify API | bundled BouncyCastle | bundled BouncyCastle | ReallyMe Rust WASM verify API |
| `RSA-PSS-SHA512-MGF1-SHA512` | ReallyMe Rust C ABI through provider-aware verify API | bundled BouncyCastle | bundled BouncyCastle | ReallyMe Rust WASM verify API |
| `ML-DSA-44` | ReallyMe Rust C ABI through provider-aware API | BouncyCastle | BouncyCastle | ReallyMe WASM/Rust |
| `ML-DSA-65` | ReallyMe Rust C ABI through provider-aware API | BouncyCastle | BouncyCastle | ReallyMe WASM/Rust |
| `ML-DSA-87` | ReallyMe Rust C ABI through provider-aware API | BouncyCastle | BouncyCastle | ReallyMe WASM/Rust |
| `SLH-DSA-SHA2-128s` | ReallyMe Rust C ABI through provider-aware API | BouncyCastle | BouncyCastle | ReallyMe WASM/Rust |
| `X25519` | CryptoKit | BouncyCastle | BouncyCastle | `@noble/curves` |
| `P-256-ECDH` | CryptoKit; Secure Enclave / Keychain through handle-backed API | BouncyCastle | BouncyCastle; Android Keystore / StrongBox through `ReallyMeAndroidPlatformKeys` on API 31+ | `@noble/curves` |
| `P-384-ECDH` | CryptoKit | BouncyCastle | BouncyCastle | `@noble/curves` |
| `P-521-ECDH` | CryptoKit | BouncyCastle | BouncyCastle | `@noble/curves` |
| `ML-KEM-512` | ReallyMe Rust C ABI through provider-aware API | BouncyCastle | BouncyCastle | ReallyMe WASM/Rust |
| `ML-KEM-768` | ReallyMe Rust C ABI through provider-aware API | BouncyCastle | BouncyCastle | ReallyMe WASM/Rust |
| `ML-KEM-1024` | ReallyMe Rust C ABI through provider-aware API | BouncyCastle | BouncyCastle | ReallyMe WASM/Rust |
| `X-Wing-768` | ReallyMe Rust C ABI through provider-aware API | BouncyCastle | BouncyCastle | ReallyMe WASM/Rust |
| `AES-128-GCM` | CryptoKit | bundled BouncyCastle | bundled BouncyCastle | ReallyMe WASM/Rust |
| `AES-192-GCM` | CryptoKit | bundled BouncyCastle | bundled BouncyCastle | ReallyMe WASM/Rust |
| `AES-256-GCM` | CryptoKit | bundled BouncyCastle | bundled BouncyCastle | ReallyMe WASM/Rust |
| `AES-256-GCM-SIV` | ReallyMe Rust C ABI through provider-aware API — never a native/third-party package | ReallyMe Rust JNI through explicit provider load | ReallyMe Rust JNI through explicit provider load | ReallyMe WASM/Rust |
| `ChaCha20-Poly1305` | CryptoKit | ReallyMe Rust JNI through explicit provider load | ReallyMe Rust JNI through explicit provider load | ReallyMe WASM/Rust |
| `XChaCha20-Poly1305` | ReallyMe Rust C ABI through provider-aware API — never a native/third-party package | ReallyMe Rust JNI through explicit provider load | ReallyMe Rust JNI through explicit provider load | ReallyMe WASM/Rust |
| `SHA2-256` | CryptoKit | JCA/JCE | JCA/JCE | `@noble/hashes` |
| `SHA2-384` | CryptoKit | JCA/JCE | JCA/JCE | `@noble/hashes` |
| `SHA2-512` | CryptoKit | JCA/JCE | JCA/JCE | `@noble/hashes` |
| `SHA3-224` | Digest | BouncyCastle | BouncyCastle | `@noble/hashes` |
| `SHA3-256` | Digest | BouncyCastle | BouncyCastle | `@noble/hashes` |
| `SHA3-384` | Digest | BouncyCastle | BouncyCastle | `@noble/hashes` |
| `SHA3-512` | Digest | BouncyCastle | BouncyCastle | `@noble/hashes` |
| `HMAC-SHA-256` | CryptoKit | JCA/JCE | JCA/JCE | `@noble/hashes` |
| `HMAC-SHA-384` | CryptoKit | JCA/JCE | JCA/JCE | `@noble/hashes` |
| `HMAC-SHA-512` | CryptoKit | JCA/JCE | JCA/JCE | `@noble/hashes` |
| `HKDF-SHA256` | CryptoKit | BouncyCastle | BouncyCastle | `@noble/hashes` |
| `HKDF-SHA384` | CryptoKit | BouncyCastle | BouncyCastle | `@noble/hashes` |
| `Argon2id` | ReallyMe Rust C ABI through provider-aware API | ReallyMe Rust JNI through explicit provider load — never JCA/JCE/BouncyCastle | ReallyMe Rust JNI through explicit provider load — never Android provider/BouncyCastle | ReallyMe WASM/Rust |
| `PBKDF2-HMAC-SHA-256` | CryptoKit HMAC | BouncyCastle | BouncyCastle | `@noble/hashes` |
| `PBKDF2-HMAC-SHA-512` | CryptoKit HMAC | BouncyCastle | BouncyCastle | `@noble/hashes` |
| `JWA-CONCAT-KDF-SHA256` | CryptoKit | JCA/JCE | JCA/JCE | `@noble/hashes` |
| `KMAC256` | ReallyMe Rust C ABI through provider-aware API | ReallyMe Rust JNI through explicit provider load | ReallyMe Rust JNI through explicit provider load | ReallyMe WASM/Rust |
| `AES-128-KW` | ReallyMe Rust C ABI through provider-aware API | BouncyCastle | BouncyCastle | ReallyMe WASM/Rust |
| `AES-192-KW` | ReallyMe Rust C ABI through provider-aware API | BouncyCastle | BouncyCastle | ReallyMe WASM/Rust |
| `AES-256-KW` | ReallyMe Rust C ABI through provider-aware API | BouncyCastle | BouncyCastle | ReallyMe WASM/Rust |
| `DHKEM-P256-HKDF-SHA256-HKDF-SHA256-AES-256-GCM` | ReallyMe Rust C ABI through provider-aware API | BouncyCastle | BouncyCastle | ReallyMe WASM/Rust |
| `DHKEM-X25519-HKDF-SHA256-HKDF-SHA256-CHACHA20-POLY1305` | ReallyMe Rust C ABI through provider-aware API | BouncyCastle | BouncyCastle | ReallyMe WASM/Rust |

## Policy Tests

Provider policy is enforced in `crates/conformance/tests/vectors`:

- every package algorithm identifier must appear in this policy;
- Swift, Kotlin/JVM, Kotlin/Android, and TypeScript lane hierarchies must remain
  present;
- TypeScript must remain synchronous and WebCrypto-free at the facade boundary;
- Kotlin/JVM and Kotlin/Android must remain separate policy lanes;
- package catalogs must name explicit providers.

`scripts/check_provider_routing.mjs` is the CI-facing manifest validator. It
treats `provider_manifest.json` as the approved source of truth and fails when
Swift, Kotlin, TypeScript, Rust dispatch/adapter markers, WASM provider exports,
failure tests, or the generated provider matrix drift from the manifest. Adding
or changing an algorithm requires updating the manifest, facade route,
conformance vectors, and unsupported-provider coverage together. For a lane
marked `usesRust: false`, the validator also resolves the declared package API
owner and rejects a source implementation that depends on that lane's Rust
bridge. The manifest is a release-time routing contract; typed SDK facade
dispatch remains the runtime selector.

## Platform Backend Matrix

> Generated from `provider_manifest.json` by `scripts/generate_provider_matrix.mjs`.
> Do not hand-edit the table between the markers; update the manifest and
> regenerate with `node scripts/generate_provider_matrix.mjs`.

This matrix is the machine-checked, per-algorithm view of the policy above.
Swift, Kotlin/JVM, Kotlin/Android, and TypeScript/WASM are separate lanes. Each
lane either names the provider it routes to or records typed
unsupported-algorithm behavior. Silent fallback is not allowed.

TypeScript remains synchronous; WebCrypto is not a package
provider because it would force async facade signatures. Kotlin/JVM and
Kotlin/Android stay separate even when both lanes route through the
same BouncyCastle-backed implementation.

<!-- BEGIN GENERATED PROVIDER MATRIX -->
| Algorithm | Family | Swift | Kotlin/JVM | Kotlin/Android | TypeScript/WASM |
|---|---|---|---|---|---|
| `Ed25519` | signature | Provider-aware<br>ReallyMeRustCAbiEd25519<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeEd25519<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeEd25519<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeEd25519<br>Providers: @noble/curves<br>Rust: no<br>Fallback: typed provider failure |
| `ECDSA-P256-SHA256` | signature | Provider-aware<br>ReallyMeRustCAbiP256Ecdsa and ReallyMeP256SecureEnclaveEcdsa<br>Providers: ReallyMe Rust C ABI + Secure Enclave/Keychain<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeP256Ecdsa<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeP256Ecdsa and ReallyMeAndroidPlatformKeys<br>Providers: BouncyCastle + Android Keystore + StrongBox<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeP256Ecdsa<br>Providers: @noble/curves + @noble/hashes<br>Rust: no<br>Fallback: typed provider failure |
| `ECDSA-P384-SHA384` | signature | Provider-aware<br>ReallyMeRustCAbiP384Ecdsa<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeP384Ecdsa<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeP384Ecdsa<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeP384Ecdsa<br>Providers: @noble/curves + @noble/hashes<br>Rust: no<br>Fallback: typed provider failure |
| `ECDSA-P521-SHA512` | signature | Provider-aware<br>ReallyMeRustCAbiP521Ecdsa<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeP521Ecdsa<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeP521Ecdsa<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeP521Ecdsa<br>Providers: @noble/curves + @noble/hashes<br>Rust: no<br>Fallback: typed provider failure |
| `ECDSA-secp256k1-SHA256` | signature | Supported<br>ReallyMeSecp256k1<br>Providers: CSecp256k1 + CryptoKit<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeSecp256k1<br>Providers: Bitcoin Core libsecp256k1<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeSecp256k1<br>Providers: Bitcoin Core libsecp256k1<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeSecp256k1<br>Providers: @noble/curves + @noble/hashes<br>Rust: no<br>Fallback: typed provider failure |
| `BIP340-Schnorr-secp256k1-SHA256` | signature | Provider-aware<br>ReallyMeCrypto.sign with explicit auxRand32 + rustCAbiLibrary<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeCrypto.signBip340Schnorr with explicit auxRand32<br>Providers: Bitcoin Core libsecp256k1<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeCrypto.signBip340Schnorr with explicit auxRand32<br>Providers: Bitcoin Core libsecp256k1<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeCrypto.signBip340Schnorr with explicit auxRand32<br>Providers: @noble/curves<br>Rust: no<br>Fallback: typed provider failure |
| `RSA-PKCS1v15-SHA1` | signature | Provider-aware<br>ReallyMeRustCAbiRsa verify<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeRsa verify<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `RSA-PKCS1v15-SHA256` | signature | Provider-aware<br>ReallyMeRustCAbiRsa verify<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeRsa verify<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `RSA-PKCS1v15-SHA384` | signature | Provider-aware<br>ReallyMeRustCAbiRsa verify<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeRsa verify<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `RSA-PKCS1v15-SHA512` | signature | Provider-aware<br>ReallyMeRustCAbiRsa verify<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeRsa verify<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `RSA-PSS-SHA1-MGF1-SHA1` | signature | Provider-aware<br>ReallyMeRustCAbiRsa verify<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeRsa verify<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `RSA-PSS-SHA256-MGF1-SHA256` | signature | Provider-aware<br>ReallyMeRustCAbiRsa verify<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeRsa verify<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `RSA-PSS-SHA384-MGF1-SHA384` | signature | Provider-aware<br>ReallyMeRustCAbiRsa verify<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeRsa verify<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `RSA-PSS-SHA512-MGF1-SHA512` | signature | Provider-aware<br>ReallyMeRustCAbiRsa verify<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeRsa verify<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `ML-DSA-44` | signature | Provider-aware<br>ReallyMeRustCAbiMlDsa<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeCrypto ML-DSA keygen/sign/verify<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeCrypto ML-DSA keygen/sign/verify<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeMlDsa<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `ML-DSA-65` | signature | Provider-aware<br>ReallyMeRustCAbiMlDsa<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeCrypto ML-DSA keygen/sign/verify<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeCrypto ML-DSA keygen/sign/verify<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeMlDsa<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `ML-DSA-87` | signature | Provider-aware<br>ReallyMeRustCAbiMlDsa<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeCrypto ML-DSA keygen/sign/verify<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeCrypto ML-DSA keygen/sign/verify<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeMlDsa<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `SLH-DSA-SHA2-128s` | signature | Provider-aware<br>ReallyMeRustCAbiSlhDsa<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeSlhDsa<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeSlhDsa<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeSlhDsa<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `X25519` | key_agreement | Supported<br>ReallyMeX25519<br>Providers: CryptoKit<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeX25519<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeX25519<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeX25519<br>Providers: @noble/curves<br>Rust: no<br>Fallback: typed provider failure |
| `P-256-ECDH` | key_agreement | Supported<br>ReallyMeP256Ecdh and ReallyMeP256SecureEnclaveEcdh<br>Providers: CryptoKit + Secure Enclave/Keychain<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeP256Ecdh<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeP256Ecdh and ReallyMeAndroidPlatformKeys<br>Providers: BouncyCastle + Android Keystore + StrongBox<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeP256Ecdh<br>Providers: @noble/curves<br>Rust: no<br>Fallback: typed provider failure |
| `P-384-ECDH` | key_agreement | Supported<br>ReallyMeP384Ecdh<br>Providers: CryptoKit<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeP384Ecdh<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeP384Ecdh<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeP384Ecdh<br>Providers: @noble/curves<br>Rust: no<br>Fallback: typed provider failure |
| `P-521-ECDH` | key_agreement | Supported<br>ReallyMeP521Ecdh<br>Providers: CryptoKit<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeP521Ecdh<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeP521Ecdh<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeP521Ecdh<br>Providers: @noble/curves<br>Rust: no<br>Fallback: typed provider failure |
| `ML-KEM-512` | kem | Provider-aware<br>ReallyMeRustCAbiMlKem<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeMlKem<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeMlKem<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeMlKem<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `ML-KEM-768` | kem | Provider-aware<br>ReallyMeRustCAbiMlKem<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeMlKem<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeMlKem<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeMlKem<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `ML-KEM-1024` | kem | Provider-aware<br>ReallyMeRustCAbiMlKem<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeMlKem<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeMlKem<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeMlKem<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `X-Wing-768` | kem | Provider-aware<br>ReallyMeRustCAbiXWing<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeXWing<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeXWing<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeXWing<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `DHKEM-P256-HKDF-SHA256-HKDF-SHA256-AES-256-GCM` | hpke | Provider-aware<br>ReallyMeRustCAbiHpke<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeHpke<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeHpke<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeHpke<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `DHKEM-X25519-HKDF-SHA256-HKDF-SHA256-CHACHA20-POLY1305` | hpke | Provider-aware<br>ReallyMeRustCAbiHpke<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeHpke<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeHpke<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeHpke<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `AES-128-GCM` | aead | Supported<br>ReallyMeAesGcm<br>Providers: CryptoKit<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeAesGcm<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeAesGcm<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeAead<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `AES-192-GCM` | aead | Supported<br>ReallyMeAesGcm<br>Providers: CryptoKit<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeAesGcm<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeAesGcm<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeAead<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `AES-256-GCM` | aead | Supported<br>ReallyMeAesGcm<br>Providers: CryptoKit<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeAesGcm<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeAesGcm<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeAead<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `AES-256-GCM-SIV` | aead | Provider-aware<br>ReallyMeRustCAbiAead<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Provider-aware<br>ReallyMeRustNativeProvider + ReallyMeRustAead<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Provider-aware<br>ReallyMeRustNativeProvider + ReallyMeRustAead<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeAead<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `ChaCha20-Poly1305` | aead | Supported<br>ReallyMeChaCha20Poly1305<br>Providers: CryptoKit<br>Rust: no<br>Fallback: typed provider failure | Provider-aware<br>ReallyMeRustNativeProvider + ReallyMeRustAead<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Provider-aware<br>ReallyMeRustNativeProvider + ReallyMeRustAead<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeAead<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `XChaCha20-Poly1305` | aead | Provider-aware<br>ReallyMeRustCAbiAead<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Provider-aware<br>ReallyMeRustNativeProvider + ReallyMeRustAead<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Provider-aware<br>ReallyMeRustNativeProvider + ReallyMeRustAead<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeAead<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `SHA2-256` | hash | Supported<br>ReallyMeDigest.sha2_*<br>Providers: CryptoKit<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeDigest.sha2_*<br>Providers: JCA/JCE<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeDigest.sha2_*<br>Providers: JCA/JCE<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeDigest.sha2_*<br>Providers: @noble/hashes<br>Rust: no<br>Fallback: typed provider failure |
| `SHA2-384` | hash | Supported<br>ReallyMeDigest.sha2_*<br>Providers: CryptoKit<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeDigest.sha2_*<br>Providers: JCA/JCE<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeDigest.sha2_*<br>Providers: JCA/JCE<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeDigest.sha2_*<br>Providers: @noble/hashes<br>Rust: no<br>Fallback: typed provider failure |
| `SHA2-512` | hash | Supported<br>ReallyMeDigest.sha2_*<br>Providers: CryptoKit<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeDigest.sha2_*<br>Providers: JCA/JCE<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeDigest.sha2_*<br>Providers: JCA/JCE<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeDigest.sha2_*<br>Providers: @noble/hashes<br>Rust: no<br>Fallback: typed provider failure |
| `SHA3-224` | hash | Supported<br>ReallyMeDigest.sha3_*<br>Providers: Digest<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeDigest.sha3_*<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeDigest.sha3_*<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeDigest.sha3_*<br>Providers: @noble/hashes<br>Rust: no<br>Fallback: typed provider failure |
| `SHA3-256` | hash | Supported<br>ReallyMeDigest.sha3_*<br>Providers: Digest<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeDigest.sha3_*<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeDigest.sha3_*<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeDigest.sha3_*<br>Providers: @noble/hashes<br>Rust: no<br>Fallback: typed provider failure |
| `SHA3-384` | hash | Supported<br>ReallyMeDigest.sha3_*<br>Providers: Digest<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeDigest.sha3_*<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeDigest.sha3_*<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeDigest.sha3_*<br>Providers: @noble/hashes<br>Rust: no<br>Fallback: typed provider failure |
| `SHA3-512` | hash | Supported<br>ReallyMeDigest.sha3_*<br>Providers: Digest<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeDigest.sha3_*<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeDigest.sha3_*<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeDigest.sha3_*<br>Providers: @noble/hashes<br>Rust: no<br>Fallback: typed provider failure |
| `HMAC-SHA-256` | mac | Supported<br>ReallyMeHmac.authenticateSha*<br>Providers: CryptoKit<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeHmac.authenticateSha*<br>Providers: JCA/JCE<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeHmac.authenticateSha*<br>Providers: JCA/JCE<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeHmac.authenticateSha*<br>Providers: @noble/hashes<br>Rust: no<br>Fallback: typed provider failure |
| `HMAC-SHA-384` | mac | Supported<br>ReallyMeHmac.authenticateSha*<br>Providers: CryptoKit<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeHmac.authenticateSha*<br>Providers: JCA/JCE<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeHmac.authenticateSha*<br>Providers: JCA/JCE<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeHmac.authenticateSha*<br>Providers: @noble/hashes<br>Rust: no<br>Fallback: typed provider failure |
| `HMAC-SHA-512` | mac | Supported<br>ReallyMeHmac.authenticateSha*<br>Providers: CryptoKit<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeHmac.authenticateSha*<br>Providers: JCA/JCE<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeHmac.authenticateSha*<br>Providers: JCA/JCE<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeHmac.authenticateSha*<br>Providers: @noble/hashes<br>Rust: no<br>Fallback: typed provider failure |
| `HKDF-SHA256` | kdf | Supported<br>ReallyMeHkdf.deriveSha256<br>Providers: CryptoKit<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeHkdf.deriveSha256<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeHkdf.deriveSha256<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeHkdf.deriveSha256<br>Providers: @noble/hashes<br>Rust: no<br>Fallback: typed provider failure |
| `HKDF-SHA384` | kdf | Supported<br>ReallyMeHkdf.deriveSha384<br>Providers: CryptoKit<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeHkdf.deriveSha384<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeHkdf.deriveSha384<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeHkdf.deriveSha384<br>Providers: @noble/hashes<br>Rust: no<br>Fallback: typed provider failure |
| `Argon2id` | kdf | Provider-aware<br>ReallyMeRustCAbiArgon2id<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Provider-aware<br>ReallyMeRustNativeProvider + ReallyMeArgon2id<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Provider-aware<br>ReallyMeRustNativeProvider + ReallyMeArgon2id<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeArgon2id<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `PBKDF2-HMAC-SHA-256` | kdf | Supported<br>ReallyMePbkdf2.deriveHmacSha*<br>Providers: CryptoKit<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMePbkdf2.deriveHmacSha*<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMePbkdf2.deriveHmacSha*<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMePbkdf2.deriveHmacSha*<br>Providers: @noble/hashes<br>Rust: no<br>Fallback: typed provider failure |
| `PBKDF2-HMAC-SHA-512` | kdf | Supported<br>ReallyMePbkdf2.deriveHmacSha*<br>Providers: CryptoKit<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMePbkdf2.deriveHmacSha*<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMePbkdf2.deriveHmacSha*<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMePbkdf2.deriveHmacSha*<br>Providers: @noble/hashes<br>Rust: no<br>Fallback: typed provider failure |
| `JWA-CONCAT-KDF-SHA256` | kdf | Supported<br>ReallyMeJwaConcatKdf<br>Providers: CryptoKit<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeJwaConcatKdf<br>Providers: JCA/JCE<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeJwaConcatKdf<br>Providers: JCA/JCE<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeJwaConcatKdf<br>Providers: @noble/hashes<br>Rust: no<br>Fallback: typed provider failure |
| `KMAC256` | kdf | Provider-aware<br>ReallyMeRustCAbiKmac<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Provider-aware<br>ReallyMeRustNativeProvider + ReallyMeKmac<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Provider-aware<br>ReallyMeRustNativeProvider + ReallyMeKmac<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeKmac<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `AES-128-KW` | key_wrap | Provider-aware<br>ReallyMeRustCAbiAesKw<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeAesKw<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeAesKw<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeAesKw<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `AES-192-KW` | key_wrap | Provider-aware<br>ReallyMeRustCAbiAesKw<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeAesKw<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeAesKw<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeAesKw<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `AES-256-KW` | key_wrap | Provider-aware<br>ReallyMeRustCAbiAesKw<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeAesKw<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeAesKw<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeAesKw<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
<!-- END GENERATED PROVIDER MATRIX -->
