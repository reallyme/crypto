<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Provider Policy

This file records the provider order for each public package algorithm
identifier. The rule is intentionally strict: a package facade may use only the
provider listed for that lane. If that provider is unavailable, unavailable on
the platform floor, or cannot satisfy the vector contract, the facade returns
the lane's typed `unsupportedAlgorithm` error. It must not silently fall back to
a different provider.

## Selection Principle

The provider for each algorithm is chosen by one rule, applied per lane:

**Prefer the platform-native provider when the primitive is old, standard, and
OS-supported, or when it carries hardware/key-residency benefits — and prefer
ReallyMe's Rust implementation (FFI on Swift/Kotlin, WASM on TypeScript) when the
primitive is specialized, post-quantum, memory-hard, protocol-composed, or easy
to get subtly wrong.**

Use the platform-native provider when *all* of the following hold:

- it is exposed by the OS or a first-tier platform API — CryptoKit,
  Security.framework, JCA/JCE, Android Keystore, Node `crypto`/WebCrypto, or a
  vetted `@noble/*` package on TypeScript;
- either the primitive is standard and boring there (SHA-2, HMAC, HKDF, PBKDF2,
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
  XChaCha20-Poly1305, Argon2id, and the multibase/multicodec/multikey codecs;
- the only "native" option would be a third-party Swift/Kotlin package with less
  review than the Rust crate. **Reaching for a random package purely to be
  "native" is worse than using one vetted Rust implementation everywhere and is
  not permitted.**

Two consequences worth stating explicitly, because they are load-bearing:

- **Argon2id is Rust on every lane.** CryptoKit/Security do not provide it,
  JCA/JCE does not provide it, and BouncyCastle's Argon2 is less reviewed than
  the workspace crate. Swift uses the Rust C ABI, Kotlin uses Rust via JNI, and
  TypeScript uses Rust via WASM. A facade must **not** satisfy Argon2id with a
  JCA/BouncyCastle or third-party Swift Argon2 provider.
- **No silent fallback, in either direction.** Where a lane lists an ordered
  pair (e.g. `JCA/JCE -> BouncyCastle`), the selection is resolved only on
  algorithm *availability* at provider-lookup time; the chosen provider then
  performs the whole operation. An authentication or verification failure is
  surfaced as the lane's typed error, never retried against another provider.

The per-family rationale below records how this rule lands for each group; the
algorithm table after it is the precise, test-enforced contract.

## Family Rationale (what we do and why)

| Family | Swift | Kotlin/JVM/Android | TypeScript | Why |
|---|---|---|---|---|
| SHA-2 / SHA-3 / HMAC / HKDF / PBKDF2 | CryptoKit / Digest | JCA/JCE, BouncyCastle for SHA-3 | `@noble/hashes` | Old, standard, OS-supported; byte-stable everywhere. Platform-native. |
| AES-256-GCM | CryptoKit | JCA/JCE → BouncyCastle | ReallyMe WASM/Rust | Boring AEAD with AES-NI benefit on native lanes; TS has no stable sync native AEAD, so Rust WASM. |
| AES-256-KW (RFC 3394) | ReallyMe Rust C ABI | JCA/JCE → BouncyCastle | ReallyMe WASM/Rust | Deterministic key-wrap; byte-identical regardless of provider. Native where mature, Rust where cleaner. |
| P-256 ECDH / X25519 | CryptoKit | BouncyCastle / JCA | `@noble/curves` | Standard EC with stable provider behaviour; no determinism constraint on ECDH. Native. |
| P-256/384/521 ECDSA sign, Ed25519 sign | ReallyMe Rust C ABI | BouncyCastle deterministic ECDSA / Ed25519 | `@noble/curves` | Signing must be deterministic (RFC 6979 / RFC 8032) and byte-identical across lanes; platform signers use random k or vary, so Rust/BC deterministic signers are chosen for byte identity. |
| secp256k1 ECDSA / BIP-340 Schnorr | `CSecp256k1` (Bitcoin Core libsecp256k1) | libsecp256k1 via `secp256k1-kmp` (JNI) | `@noble/curves` | The constant-time reference implementation is the same C library on native lanes; hand-rolled EC on secret scalars is a timing side-channel and is forbidden. |
| RSA verify (PKCS1v15 / PSS) | ReallyMe Rust C ABI | JCA/JCE → BouncyCastle | ReallyMe WASM/Rust | Verification only; standard and boring on JVM, Rust on Swift/TS through shared backend lanes. |
| Argon2id | ReallyMe Rust C ABI | ReallyMe Rust JNI through explicit provider load | ReallyMe WASM/Rust | Memory-hard KDF with **no** OS-native provider on any lane; one vetted Rust implementation everywhere. Never JCA/BC/third-party. |
| ML-KEM / ML-DSA / SLH-DSA / X-Wing / HPKE | ReallyMe Rust C ABI | BouncyCastle (explicit, KAT-proven) or Rust | ReallyMe WASM/Rust | Post-quantum / protocol-composed; error-prone to hand-assemble. Rust by default; BouncyCastle only when explicitly selected and locked to the shared KATs. |
| AES-256-GCM-SIV / XChaCha20-Poly1305 | ReallyMe Rust C ABI through provider-aware API | ReallyMe Rust JNI through explicit provider load | ReallyMe WASM/Rust | Newer nonce-misuse-resistant / extended-nonce AEADs with no first-tier native provider; Rust everywhere. Never a third-party native package. |
| Multibase / multicodec / multikey codecs | Swift table code (tiny, pure) | Kotlin/JDK table code (tiny, pure) | ReallyMe WASM/Rust or tiny pure TS | Pure table/encoding logic: native only when it is small, self-contained, and covered by shared vectors; otherwise the shared Rust codec. |

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

1. JCA/JCE, only when provider behavior is byte-stable under the test floor.
2. BouncyCastle, when JCA/JCE differs across JVMs or Android, or when the
   primitive is not reliably present in the platform provider.
3. ReallyMe Rust C ABI or JNI, only through explicit provider-aware APIs.
4. Typed `unsupportedAlgorithm`.

Kotlin/Android provider order:

1. The Android platform provider or Conscrypt, only when behavior is available
   on the package floor and byte-stable.
2. BouncyCastle for v0.1.1 when JVM and Android providers would otherwise
   diverge.
3. ReallyMe Rust C ABI or JNI, only through explicit provider-aware APIs.
4. Typed `unsupportedAlgorithm`.

Android Keystore key residency is not part of this policy. It needs a separate
key-handle contract before a facade can select it.

TypeScript provider order:

1. Audited synchronous JavaScript providers, currently pinned `@noble/curves`
   and `@noble/hashes`.
2. Node `crypto`, only if a future synchronous wrapper is byte-stable and does
   not change the public facade shape.
3. ReallyMe WASM/Rust, only through an explicit WASM provider wrapper.
4. Typed `unsupportedAlgorithm`.

WebCrypto is not part of v0.1.1 because it is async-only and would force an API
shape change. The TypeScript package keeps hand-written validation for enum
membership, byte lengths, buffer shape, and provider result shape.

## Algorithm Policy

| Algorithm identifier | Swift provider | Kotlin/JVM provider | Kotlin/Android provider | TypeScript provider |
|---|---|---|---|---|
| `Ed25519` | ReallyMe Rust C ABI through provider-aware facade overload | BouncyCastle | BouncyCastle | `@noble/curves` |
| `ECDSA-P256-SHA256` | ReallyMe Rust C ABI through provider-aware API for deterministic DER/SHA-256 signatures | BouncyCastle deterministic ECDSA | BouncyCastle deterministic ECDSA | `@noble/curves` with `@noble/hashes` SHA-256 prehash |
| `ECDSA-P384-SHA384` | ReallyMe Rust C ABI through provider-aware API for deterministic DER/SHA-384 signatures | BouncyCastle deterministic ECDSA | BouncyCastle deterministic ECDSA | `@noble/curves` with `@noble/hashes` SHA-384 prehash |
| `ECDSA-P521-SHA512` | ReallyMe Rust C ABI through provider-aware API for deterministic DER/SHA-512 signatures | BouncyCastle deterministic ECDSA | BouncyCastle deterministic ECDSA | `@noble/curves` with `@noble/hashes` SHA-512 prehash |
| `ECDSA-secp256k1-SHA256` | `CSecp256k1` with CryptoKit SHA-256 prehash | Bitcoin Core libsecp256k1 via `secp256k1-kmp` (JNI) | Bitcoin Core libsecp256k1 via `secp256k1-kmp` (JNI) | `@noble/curves` with `@noble/hashes` SHA-256 prehash |
| `BIP340-Schnorr-secp256k1-SHA256` | ReallyMe Rust C ABI through provider-aware API with explicit `auxRand32` | Bitcoin Core libsecp256k1 via `secp256k1-kmp` (JNI) through `ReallyMeCrypto.signBip340Schnorr` | Bitcoin Core libsecp256k1 via `secp256k1-kmp` (JNI) through `ReallyMeCrypto.signBip340Schnorr` | `@noble/curves` through `ReallyMeCrypto.signBip340Schnorr` with explicit `auxRand32` |
| `RSA-PKCS1v15-SHA1` | ReallyMe Rust C ABI through provider-aware verify API | JCA/JCE -> BouncyCastle | JCA/JCE -> BouncyCastle | ReallyMe Rust WASM verify API |
| `RSA-PKCS1v15-SHA256` | ReallyMe Rust C ABI through provider-aware verify API | JCA/JCE -> BouncyCastle | JCA/JCE -> BouncyCastle | ReallyMe Rust WASM verify API |
| `RSA-PKCS1v15-SHA384` | ReallyMe Rust C ABI through provider-aware verify API | JCA/JCE -> BouncyCastle | JCA/JCE -> BouncyCastle | ReallyMe Rust WASM verify API |
| `RSA-PKCS1v15-SHA512` | ReallyMe Rust C ABI through provider-aware verify API | JCA/JCE -> BouncyCastle | JCA/JCE -> BouncyCastle | ReallyMe Rust WASM verify API |
| `RSA-PSS-SHA1-MGF1-SHA1` | ReallyMe Rust C ABI through provider-aware verify API | JCA/JCE -> BouncyCastle | JCA/JCE -> BouncyCastle | ReallyMe Rust WASM verify API |
| `RSA-PSS-SHA256-MGF1-SHA256` | ReallyMe Rust C ABI through provider-aware verify API | JCA/JCE -> BouncyCastle | JCA/JCE -> BouncyCastle | ReallyMe Rust WASM verify API |
| `RSA-PSS-SHA384-MGF1-SHA384` | ReallyMe Rust C ABI through provider-aware verify API | JCA/JCE -> BouncyCastle | JCA/JCE -> BouncyCastle | ReallyMe Rust WASM verify API |
| `RSA-PSS-SHA512-MGF1-SHA512` | ReallyMe Rust C ABI through provider-aware verify API | JCA/JCE -> BouncyCastle | JCA/JCE -> BouncyCastle | ReallyMe Rust WASM verify API |
| `ML-DSA-44` | ReallyMe Rust C ABI through provider-aware API | BouncyCastle | BouncyCastle | ReallyMe WASM/Rust |
| `ML-DSA-65` | ReallyMe Rust C ABI through provider-aware API | BouncyCastle | BouncyCastle | ReallyMe WASM/Rust |
| `ML-DSA-87` | ReallyMe Rust C ABI through provider-aware API | BouncyCastle | BouncyCastle | ReallyMe WASM/Rust |
| `SLH-DSA-SHA2-128s` | ReallyMe Rust C ABI through provider-aware API | BouncyCastle | BouncyCastle | ReallyMe WASM/Rust |
| `X25519` | CryptoKit | BouncyCastle | BouncyCastle | `@noble/curves` |
| `P-256-ECDH` | CryptoKit | BouncyCastle | BouncyCastle | `@noble/curves` |
| `ML-KEM-512` | ReallyMe Rust C ABI through provider-aware API | BouncyCastle | BouncyCastle | ReallyMe WASM/Rust |
| `ML-KEM-768` | ReallyMe Rust C ABI through provider-aware API | BouncyCastle | BouncyCastle | ReallyMe WASM/Rust |
| `ML-KEM-1024` | ReallyMe Rust C ABI through provider-aware API | BouncyCastle | BouncyCastle | ReallyMe WASM/Rust |
| `X-Wing-768` | ReallyMe Rust C ABI through provider-aware API | BouncyCastle | BouncyCastle | ReallyMe WASM/Rust |
| `X-Wing-1024` | ReallyMe Rust C ABI through provider-aware API | BouncyCastle | BouncyCastle | ReallyMe WASM/Rust |
| `AES-256-GCM` | CryptoKit | JCA/JCE -> BouncyCastle | JCA/JCE -> BouncyCastle | ReallyMe WASM/Rust |
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
| `HMAC-SHA-512` | CryptoKit | JCA/JCE | JCA/JCE | `@noble/hashes` |
| `HKDF-SHA256` | CryptoKit | BouncyCastle | BouncyCastle | `@noble/hashes` |
| `Argon2id` | ReallyMe Rust C ABI through provider-aware API | ReallyMe Rust JNI through explicit provider load — never JCA/JCE/BouncyCastle | ReallyMe Rust JNI through explicit provider load — never Android provider/BouncyCastle | ReallyMe WASM/Rust |
| `PBKDF2-HMAC-SHA-256` | CryptoKit HMAC | BouncyCastle | BouncyCastle | `@noble/hashes` |
| `PBKDF2-HMAC-SHA-512` | CryptoKit HMAC | BouncyCastle | BouncyCastle | `@noble/hashes` |
| `AES-256-KW` | ReallyMe Rust C ABI through provider-aware API | JCA/JCE -> BouncyCastle | JCA/JCE -> BouncyCastle | ReallyMe WASM/Rust |
| `Multicodec/multikey public-key codecs` | Swift table-backed multibase/base58btc wrapper | Kotlin/JDK table-backed multibase/base58btc wrapper | Kotlin/JDK table-backed multibase/base58btc wrapper | ReallyMe WASM/Rust |
| `DHKEM-P256-HKDF-SHA256-HKDF-SHA256-AES-256-GCM` | ReallyMe Rust C ABI through provider-aware API | BouncyCastle | BouncyCastle | ReallyMe WASM/Rust |
| `DHKEM-X25519-HKDF-SHA256-HKDF-SHA256-CHACHA20-POLY1305` | ReallyMe Rust C ABI through provider-aware API | BouncyCastle | BouncyCastle | ReallyMe WASM/Rust |

## Policy Tests

Provider policy is enforced in `crates/conformance/vectors/tests/vectors`:

- every package algorithm identifier must appear in this policy;
- Swift, Kotlin/JVM, Kotlin/Android, and TypeScript lane hierarchies must remain
  present;
- TypeScript must remain sync-first and WebCrypto-free for v0.1.1;
- Kotlin/JVM and Kotlin/Android must remain separate policy lanes;
- package catalogs must name explicit providers.

## Platform Backend Matrix

> Generated from `provider_manifest.json` by `scripts/generate_provider_matrix.mjs`.
> Do not hand-edit the table between the markers; update the manifest and
> regenerate with `node scripts/generate_provider_matrix.mjs`.

This matrix is the machine-checked, per-algorithm view of the policy above.
Swift, Kotlin/JVM, Kotlin/Android, and TypeScript/WASM are separate lanes. Each
lane either names the provider it routes to or records typed
unsupported-algorithm behavior. Silent fallback is not allowed.

TypeScript remains sync-first for v0.1.1; WebCrypto is not a package provider
because it would force async facade signatures. Kotlin/JVM and Kotlin/Android
stay separate even when v0.1.1 routes both through the same BouncyCastle-backed
implementation.

<!-- BEGIN GENERATED PROVIDER MATRIX -->
| Algorithm | Family | Swift | Kotlin/JVM | Kotlin/Android | TypeScript/WASM |
|---|---|---|---|---|---|
| `Ed25519` | signature | Provider-aware<br>ReallyMeRustCAbiEd25519<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeEd25519<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeEd25519<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeEd25519<br>Providers: @noble/curves<br>Rust: no<br>Fallback: typed provider failure |
| `ECDSA-P256-SHA256` | signature | Provider-aware<br>ReallyMeRustCAbiP256Ecdsa<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeP256Ecdsa<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeP256Ecdsa<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeP256Ecdsa<br>Providers: @noble/curves + @noble/hashes<br>Rust: no<br>Fallback: typed provider failure |
| `ECDSA-P384-SHA384` | signature | Provider-aware<br>ReallyMeRustCAbiP384Ecdsa<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeP384Ecdsa<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeP384Ecdsa<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeP384Ecdsa<br>Providers: @noble/curves + @noble/hashes<br>Rust: no<br>Fallback: typed provider failure |
| `ECDSA-P521-SHA512` | signature | Provider-aware<br>ReallyMeRustCAbiP521Ecdsa<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeP521Ecdsa<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeP521Ecdsa<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeP521Ecdsa<br>Providers: @noble/curves + @noble/hashes<br>Rust: no<br>Fallback: typed provider failure |
| `ECDSA-secp256k1-SHA256` | signature | Supported<br>ReallyMeSecp256k1<br>Providers: CSecp256k1 + CryptoKit<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeSecp256k1<br>Providers: Bitcoin Core libsecp256k1<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeSecp256k1<br>Providers: Bitcoin Core libsecp256k1<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeSecp256k1<br>Providers: @noble/curves + @noble/hashes<br>Rust: no<br>Fallback: typed provider failure |
| `BIP340-Schnorr-secp256k1-SHA256` | signature | Provider-aware<br>ReallyMeCrypto.sign with explicit auxRand32 + rustCAbiLibrary<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeCrypto.signBip340Schnorr with explicit auxRand32<br>Providers: Bitcoin Core libsecp256k1<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeCrypto.signBip340Schnorr with explicit auxRand32<br>Providers: Bitcoin Core libsecp256k1<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeCrypto.signBip340Schnorr with explicit auxRand32<br>Providers: @noble/curves<br>Rust: no<br>Fallback: typed provider failure |
| `RSA-PKCS1v15-SHA1` | signature | Provider-aware<br>ReallyMeRustCAbiRsa verify<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeRsa verify<br>Providers: JCA/JCE + BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: JCA/JCE + BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `RSA-PKCS1v15-SHA256` | signature | Provider-aware<br>ReallyMeRustCAbiRsa verify<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeRsa verify<br>Providers: JCA/JCE + BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: JCA/JCE + BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `RSA-PKCS1v15-SHA384` | signature | Provider-aware<br>ReallyMeRustCAbiRsa verify<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeRsa verify<br>Providers: JCA/JCE + BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: JCA/JCE + BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `RSA-PKCS1v15-SHA512` | signature | Provider-aware<br>ReallyMeRustCAbiRsa verify<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeRsa verify<br>Providers: JCA/JCE + BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: JCA/JCE + BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `RSA-PSS-SHA1-MGF1-SHA1` | signature | Provider-aware<br>ReallyMeRustCAbiRsa verify<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeRsa verify<br>Providers: JCA/JCE + BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: JCA/JCE + BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `RSA-PSS-SHA256-MGF1-SHA256` | signature | Provider-aware<br>ReallyMeRustCAbiRsa verify<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeRsa verify<br>Providers: JCA/JCE + BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: JCA/JCE + BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `RSA-PSS-SHA384-MGF1-SHA384` | signature | Provider-aware<br>ReallyMeRustCAbiRsa verify<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeRsa verify<br>Providers: JCA/JCE + BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: JCA/JCE + BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `RSA-PSS-SHA512-MGF1-SHA512` | signature | Provider-aware<br>ReallyMeRustCAbiRsa verify<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeRsa verify<br>Providers: JCA/JCE + BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: JCA/JCE + BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeRsa verify<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `ML-DSA-44` | signature | Provider-aware<br>ReallyMeRustCAbiMlDsa<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeCrypto ML-DSA keygen/sign/verify<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeCrypto ML-DSA keygen/sign/verify<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeMlDsa<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `ML-DSA-65` | signature | Provider-aware<br>ReallyMeRustCAbiMlDsa<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeCrypto ML-DSA keygen/sign/verify<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeCrypto ML-DSA keygen/sign/verify<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeMlDsa<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `ML-DSA-87` | signature | Provider-aware<br>ReallyMeRustCAbiMlDsa<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeCrypto ML-DSA keygen/sign/verify<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeCrypto ML-DSA keygen/sign/verify<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeMlDsa<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `SLH-DSA-SHA2-128s` | signature | Provider-aware<br>ReallyMeRustCAbiSlhDsa<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeSlhDsa<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeSlhDsa<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeSlhDsa<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `X25519` | key_agreement | Supported<br>ReallyMeX25519<br>Providers: CryptoKit<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeX25519<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeX25519<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeX25519<br>Providers: @noble/curves<br>Rust: no<br>Fallback: typed provider failure |
| `P-256-ECDH` | key_agreement | Supported<br>ReallyMeP256Ecdh<br>Providers: CryptoKit<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeP256Ecdh<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeP256Ecdh<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeP256Ecdh<br>Providers: @noble/curves<br>Rust: no<br>Fallback: typed provider failure |
| `ML-KEM-512` | kem | Provider-aware<br>ReallyMeRustCAbiMlKem<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeMlKem<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeMlKem<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeMlKem<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `ML-KEM-768` | kem | Provider-aware<br>ReallyMeRustCAbiMlKem<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeMlKem<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeMlKem<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeMlKem<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `ML-KEM-1024` | kem | Provider-aware<br>ReallyMeRustCAbiMlKem<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeMlKem<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeMlKem<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeMlKem<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `X-Wing-768` | kem | Provider-aware<br>ReallyMeRustCAbiXWing<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeXWing<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeXWing<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeXWing<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `X-Wing-1024` | kem | Provider-aware<br>ReallyMeRustCAbiXWing<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeXWing<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeXWing<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeXWing<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `DHKEM-P256-HKDF-SHA256-HKDF-SHA256-AES-256-GCM` | hpke | Provider-aware<br>ReallyMeRustCAbiHpke<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeHpke<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeHpke<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeHpke<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `DHKEM-X25519-HKDF-SHA256-HKDF-SHA256-CHACHA20-POLY1305` | hpke | Provider-aware<br>ReallyMeRustCAbiHpke<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeHpke<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeHpke<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeHpke<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `AES-256-GCM` | aead | Supported<br>ReallyMeAesGcm<br>Providers: CryptoKit<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeAesGcm<br>Providers: JCA/JCE + BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeAesGcm<br>Providers: JCA/JCE + BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeAead<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
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
| `HMAC-SHA-512` | mac | Supported<br>ReallyMeHmac.authenticateSha*<br>Providers: CryptoKit<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeHmac.authenticateSha*<br>Providers: JCA/JCE<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeHmac.authenticateSha*<br>Providers: JCA/JCE<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeHmac.authenticateSha*<br>Providers: @noble/hashes<br>Rust: no<br>Fallback: typed provider failure |
| `HKDF-SHA256` | kdf | Supported<br>ReallyMeHkdf.deriveSha256<br>Providers: CryptoKit<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeHkdf.deriveSha256<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeHkdf.deriveSha256<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeHkdf.deriveSha256<br>Providers: @noble/hashes<br>Rust: no<br>Fallback: typed provider failure |
| `Argon2id` | kdf | Provider-aware<br>ReallyMeRustCAbiArgon2id<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Provider-aware<br>ReallyMeRustNativeProvider + ReallyMeArgon2id<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Provider-aware<br>ReallyMeRustNativeProvider + ReallyMeArgon2id<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeArgon2id<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `PBKDF2-HMAC-SHA-256` | kdf | Supported<br>ReallyMePbkdf2.deriveHmacSha*<br>Providers: CryptoKit<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMePbkdf2.deriveHmacSha*<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMePbkdf2.deriveHmacSha*<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMePbkdf2.deriveHmacSha*<br>Providers: @noble/hashes<br>Rust: no<br>Fallback: typed provider failure |
| `PBKDF2-HMAC-SHA-512` | kdf | Supported<br>ReallyMePbkdf2.deriveHmacSha*<br>Providers: CryptoKit<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMePbkdf2.deriveHmacSha*<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMePbkdf2.deriveHmacSha*<br>Providers: BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMePbkdf2.deriveHmacSha*<br>Providers: @noble/hashes<br>Rust: no<br>Fallback: typed provider failure |
| `AES-256-KW` | key_wrap | Provider-aware<br>ReallyMeRustCAbiAesKw<br>Providers: ReallyMe Rust C ABI<br>Rust: yes<br>Fallback: explicit provider required | Supported<br>ReallyMeAesKw<br>Providers: JCA/JCE + BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeAesKw<br>Providers: JCA/JCE + BouncyCastle<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeAesKw<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
| `Multicodec/multikey public-key codecs` | codec | Supported<br>ReallyMeMulticodec / ReallyMeMultikey<br>Providers: Digest<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeMulticodec / ReallyMeMultikey<br>Providers: Kotlin/JDK stdlib<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeMulticodec / ReallyMeMultikey<br>Providers: Kotlin/JDK stdlib<br>Rust: no<br>Fallback: typed provider failure | Supported<br>ReallyMeCodecs<br>Providers: ReallyMe Rust WASM<br>Rust: yes<br>Fallback: typed provider failure |
<!-- END GENERATED PROVIDER MATRIX -->
