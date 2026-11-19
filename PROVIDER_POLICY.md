# Provider Policy

No silent fallback: each algorithm uses the provider recorded for its SDK lane
in `provider_manifest.json`. A missing or failed provider returns the SDK's
typed provider or unsupported-algorithm error. It does not retry elsewhere.

Every provider route must implement identical input validation, output
encodings and typed failure semantics. Provider support is separate from
recognizing an algorithm identifier.

## Using providers

- Swift packages bundle the Rust C ABI library. Use an explicit provider context
  when testing a different local library.
- Kotlin/JVM and Android callers load Rust-backed routes with
  `ReallyMeRustNativeProvider.loadBundledLibrary()`.
- TypeScript callers initialize the package-owned WASM module, then install it
  or pass it to `createReallyMeCrypto`. WebCrypto is not a provider for the synchronous TypeScript facade.

ML-KEM, ML-DSA, SLH-DSA, X-Wing, HPKE and Argon2id execute in Rust on every SDK
lane. Kotlin software P-curve ECDH also uses Rust through JNI. The matrix lists
classical algorithms served by CryptoKit, JCA/JCE, BouncyCastle, libsecp256k1
or the JavaScript providers.

Platform keys are separate handle-based APIs. Swift provides Secure Enclave
P-256 signing and agreement; Android provides
`ReallyMeAndroidPlatformKeys` on API 31+. Requesting StrongBox never permits
a downgrade to TEE. These routes are not fallback providers for raw keys.

## Platform Backend Matrix

Generated from `provider_manifest.json` by `scripts/generate_provider_matrix.mjs`.
Each cell lists availability and provider. **Provider-aware** means that the
caller must configure the required provider. **Partial** means only the
manifest-listed operations are available. The SDK READMEs contain setup examples;
the manifest records exact entry points and failure modes.

<!-- BEGIN GENERATED PROVIDER MATRIX -->
| Algorithm | Family | Swift | Kotlin/JVM | Kotlin/Android | TypeScript/WASM |
|---|---|---|---|---|---|
| `Ed25519` | signature | Provider-aware<br>ReallyMe Rust C ABI | Supported<br>BouncyCastle | Supported<br>BouncyCastle | Supported<br>@noble/curves |
| `ECDSA-P256-SHA256` | signature | Provider-aware<br>ReallyMe Rust C ABI + Secure Enclave/Keychain | Supported<br>BouncyCastle | Supported<br>BouncyCastle + Android Keystore + StrongBox | Supported<br>@noble/curves + @noble/hashes |
| `ECDSA-P384-SHA384` | signature | Provider-aware<br>ReallyMe Rust C ABI | Supported<br>BouncyCastle | Supported<br>BouncyCastle | Supported<br>@noble/curves + @noble/hashes |
| `ECDSA-P521-SHA512` | signature | Provider-aware<br>ReallyMe Rust C ABI | Supported<br>BouncyCastle | Supported<br>BouncyCastle | Supported<br>@noble/curves + @noble/hashes |
| `ECDSA-secp256k1-SHA256` | signature | Supported<br>CSecp256k1 + CryptoKit | Supported<br>Bitcoin Core libsecp256k1 | Supported<br>Bitcoin Core libsecp256k1 | Supported<br>@noble/curves + @noble/hashes |
| `BIP340-Schnorr-secp256k1-SHA256` | signature | Provider-aware<br>ReallyMe Rust C ABI | Supported<br>Bitcoin Core libsecp256k1 | Supported<br>Bitcoin Core libsecp256k1 | Supported<br>@noble/curves |
| `RSA-PKCS1v15-SHA1` | signature | Provider-aware<br>ReallyMe Rust C ABI | Supported<br>BouncyCastle | Supported<br>BouncyCastle | Supported<br>ReallyMe Rust WASM |
| `RSA-PKCS1v15-SHA256` | signature | Provider-aware<br>ReallyMe Rust C ABI | Supported<br>BouncyCastle | Supported<br>BouncyCastle | Supported<br>ReallyMe Rust WASM |
| `RSA-PKCS1v15-SHA384` | signature | Provider-aware<br>ReallyMe Rust C ABI | Supported<br>BouncyCastle | Supported<br>BouncyCastle | Supported<br>ReallyMe Rust WASM |
| `RSA-PKCS1v15-SHA512` | signature | Provider-aware<br>ReallyMe Rust C ABI | Supported<br>BouncyCastle | Supported<br>BouncyCastle | Supported<br>ReallyMe Rust WASM |
| `RSA-PSS-SHA1-MGF1-SHA1` | signature | Provider-aware<br>ReallyMe Rust C ABI | Supported<br>BouncyCastle | Supported<br>BouncyCastle | Supported<br>ReallyMe Rust WASM |
| `RSA-PSS-SHA256-MGF1-SHA256` | signature | Provider-aware<br>ReallyMe Rust C ABI | Supported<br>BouncyCastle | Supported<br>BouncyCastle | Supported<br>ReallyMe Rust WASM |
| `RSA-PSS-SHA384-MGF1-SHA384` | signature | Provider-aware<br>ReallyMe Rust C ABI | Supported<br>BouncyCastle | Supported<br>BouncyCastle | Supported<br>ReallyMe Rust WASM |
| `RSA-PSS-SHA512-MGF1-SHA512` | signature | Provider-aware<br>ReallyMe Rust C ABI | Supported<br>BouncyCastle | Supported<br>BouncyCastle | Supported<br>ReallyMe Rust WASM |
| `ML-DSA-44` | signature | Provider-aware<br>ReallyMe Rust C ABI | Provider-aware<br>ReallyMe Rust C ABI | Provider-aware<br>ReallyMe Rust C ABI | Supported<br>ReallyMe Rust WASM |
| `ML-DSA-65` | signature | Provider-aware<br>ReallyMe Rust C ABI | Provider-aware<br>ReallyMe Rust C ABI | Provider-aware<br>ReallyMe Rust C ABI | Supported<br>ReallyMe Rust WASM |
| `ML-DSA-87` | signature | Provider-aware<br>ReallyMe Rust C ABI | Provider-aware<br>ReallyMe Rust C ABI | Provider-aware<br>ReallyMe Rust C ABI | Supported<br>ReallyMe Rust WASM |
| `SLH-DSA-SHA2-128s` | signature | Provider-aware<br>ReallyMe Rust C ABI | Provider-aware<br>ReallyMe Rust C ABI | Provider-aware<br>ReallyMe Rust C ABI | Supported<br>ReallyMe Rust WASM |
| `X25519` | key_agreement | Supported<br>CryptoKit | Supported<br>BouncyCastle | Supported<br>BouncyCastle | Supported<br>@noble/curves |
| `P-256-ECDH` | key_agreement | Supported<br>CryptoKit + Secure Enclave/Keychain | Supported<br>ReallyMe Rust C ABI | Supported<br>ReallyMe Rust C ABI + Android Keystore + StrongBox | Supported<br>@noble/curves |
| `P-384-ECDH` | key_agreement | Supported<br>CryptoKit | Supported<br>ReallyMe Rust C ABI | Supported<br>ReallyMe Rust C ABI | Supported<br>@noble/curves |
| `P-521-ECDH` | key_agreement | Supported<br>CryptoKit | Supported<br>ReallyMe Rust C ABI | Supported<br>ReallyMe Rust C ABI | Supported<br>@noble/curves |
| `ML-KEM-512` | kem | Provider-aware<br>ReallyMe Rust C ABI | Provider-aware<br>ReallyMe Rust C ABI | Provider-aware<br>ReallyMe Rust C ABI | Supported<br>ReallyMe Rust WASM |
| `ML-KEM-768` | kem | Provider-aware<br>ReallyMe Rust C ABI | Provider-aware<br>ReallyMe Rust C ABI | Provider-aware<br>ReallyMe Rust C ABI | Supported<br>ReallyMe Rust WASM |
| `ML-KEM-1024` | kem | Provider-aware<br>ReallyMe Rust C ABI | Provider-aware<br>ReallyMe Rust C ABI | Provider-aware<br>ReallyMe Rust C ABI | Supported<br>ReallyMe Rust WASM |
| `X-Wing-768` | kem | Provider-aware<br>ReallyMe Rust C ABI | Provider-aware<br>ReallyMe Rust C ABI | Provider-aware<br>ReallyMe Rust C ABI | Supported<br>ReallyMe Rust WASM |
| `DHKEM-P256-HKDF-SHA256-HKDF-SHA256-AES-256-GCM` | hpke | Provider-aware<br>ReallyMe Rust C ABI | Provider-aware<br>ReallyMe Rust C ABI | Provider-aware<br>ReallyMe Rust C ABI | Supported<br>ReallyMe Rust WASM |
| `DHKEM-X25519-HKDF-SHA256-HKDF-SHA256-CHACHA20-POLY1305` | hpke | Provider-aware<br>ReallyMe Rust C ABI | Provider-aware<br>ReallyMe Rust C ABI | Provider-aware<br>ReallyMe Rust C ABI | Supported<br>ReallyMe Rust WASM |
| `AES-128-GCM` | aead | Supported<br>CryptoKit | Supported<br>BouncyCastle | Supported<br>BouncyCastle | Supported<br>ReallyMe Rust WASM |
| `AES-192-GCM` | aead | Supported<br>CryptoKit | Supported<br>BouncyCastle | Supported<br>BouncyCastle | Supported<br>ReallyMe Rust WASM |
| `AES-256-GCM` | aead | Supported<br>CryptoKit | Supported<br>BouncyCastle | Supported<br>BouncyCastle | Supported<br>ReallyMe Rust WASM |
| `AES-256-GCM-SIV` | aead | Provider-aware<br>ReallyMe Rust C ABI | Provider-aware<br>ReallyMe Rust C ABI | Provider-aware<br>ReallyMe Rust C ABI | Supported<br>ReallyMe Rust WASM |
| `ChaCha20-Poly1305` | aead | Supported<br>CryptoKit | Provider-aware<br>ReallyMe Rust C ABI | Provider-aware<br>ReallyMe Rust C ABI | Supported<br>ReallyMe Rust WASM |
| `XChaCha20-Poly1305` | aead | Provider-aware<br>ReallyMe Rust C ABI | Provider-aware<br>ReallyMe Rust C ABI | Provider-aware<br>ReallyMe Rust C ABI | Supported<br>ReallyMe Rust WASM |
| `SHA2-256` | hash | Supported<br>CryptoKit | Supported<br>JCA/JCE | Supported<br>JCA/JCE | Supported<br>@noble/hashes |
| `SHA2-384` | hash | Supported<br>CryptoKit | Supported<br>JCA/JCE | Supported<br>JCA/JCE | Supported<br>@noble/hashes |
| `SHA2-512` | hash | Supported<br>CryptoKit | Supported<br>JCA/JCE | Supported<br>JCA/JCE | Supported<br>@noble/hashes |
| `SHA3-224` | hash | Supported<br>Digest | Supported<br>BouncyCastle | Supported<br>BouncyCastle | Supported<br>@noble/hashes |
| `SHA3-256` | hash | Supported<br>Digest | Supported<br>BouncyCastle | Supported<br>BouncyCastle | Supported<br>@noble/hashes |
| `SHA3-384` | hash | Supported<br>Digest | Supported<br>BouncyCastle | Supported<br>BouncyCastle | Supported<br>@noble/hashes |
| `SHA3-512` | hash | Supported<br>Digest | Supported<br>BouncyCastle | Supported<br>BouncyCastle | Supported<br>@noble/hashes |
| `HMAC-SHA-256` | mac | Supported<br>CryptoKit | Supported<br>JCA/JCE | Supported<br>JCA/JCE | Supported<br>@noble/hashes |
| `HMAC-SHA-384` | mac | Supported<br>CryptoKit | Supported<br>JCA/JCE | Supported<br>JCA/JCE | Supported<br>@noble/hashes |
| `HMAC-SHA-512` | mac | Supported<br>CryptoKit | Supported<br>JCA/JCE | Supported<br>JCA/JCE | Supported<br>@noble/hashes |
| `HKDF-SHA256` | kdf | Supported<br>CryptoKit | Supported<br>BouncyCastle | Supported<br>BouncyCastle | Supported<br>@noble/hashes |
| `HKDF-SHA384` | kdf | Supported<br>CryptoKit | Supported<br>BouncyCastle | Supported<br>BouncyCastle | Supported<br>@noble/hashes |
| `Argon2id` | kdf | Provider-aware<br>ReallyMe Rust C ABI | Provider-aware<br>ReallyMe Rust C ABI | Provider-aware<br>ReallyMe Rust C ABI | Supported<br>ReallyMe Rust WASM |
| `PBKDF2-HMAC-SHA-256` | kdf | Supported<br>CryptoKit | Supported<br>BouncyCastle | Supported<br>BouncyCastle | Supported<br>@noble/hashes |
| `PBKDF2-HMAC-SHA-512` | kdf | Supported<br>CryptoKit | Supported<br>BouncyCastle | Supported<br>BouncyCastle | Supported<br>@noble/hashes |
| `JWA-CONCAT-KDF-SHA256` | kdf | Supported<br>CryptoKit | Supported<br>JCA/JCE | Supported<br>JCA/JCE | Supported<br>@noble/hashes |
| `KMAC256` | kdf | Provider-aware<br>ReallyMe Rust C ABI | Provider-aware<br>ReallyMe Rust C ABI | Provider-aware<br>ReallyMe Rust C ABI | Supported<br>ReallyMe Rust WASM |
| `AES-128-KW` | key_wrap | Provider-aware<br>ReallyMe Rust C ABI | Supported<br>BouncyCastle | Supported<br>BouncyCastle | Supported<br>ReallyMe Rust WASM |
| `AES-192-KW` | key_wrap | Provider-aware<br>ReallyMe Rust C ABI | Supported<br>BouncyCastle | Supported<br>BouncyCastle | Supported<br>ReallyMe Rust WASM |
| `AES-256-KW` | key_wrap | Provider-aware<br>ReallyMe Rust C ABI | Supported<br>BouncyCastle | Supported<br>BouncyCastle | Supported<br>ReallyMe Rust WASM |
<!-- END GENERATED PROVIDER MATRIX -->

## Standalone Rust APIs

The matrix covers SDK facades. It does not imply support for every standalone
Rust operation. In particular, direct X448, RS256 signing, explicit certificate
ECDSA verification and legacy AES-SIV opening have their own feature and byte
contracts. See the [Rust facade](crates/crypto/README.md),
[RSA crate](crates/rsa/README.md) and [reader APIs](docs/reader-primitive-compatibility.md).

After changing provider support, run:

```sh
node scripts/generate_provider_matrix.mjs
node scripts/check_provider_routing.mjs
```
