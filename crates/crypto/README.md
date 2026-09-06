<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
-->

# reallyme-crypto

[![Code Checks](https://github.com/reallyme/crypto/actions/workflows/rust-ci.yml/badge.svg)](https://github.com/reallyme/crypto/actions/workflows/rust-ci.yml)
[![reallyme-crypto](https://img.shields.io/crates/v/reallyme-crypto?label=reallyme-crypto&color=2563eb)](https://crates.io/crates/reallyme-crypto)
[![Security Policy](https://img.shields.io/badge/security-policy-0f766e)](https://github.com/reallyme/crypto/blob/main/SECURITY.md)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](https://github.com/reallyme/crypto/blob/main/LICENSE)

ReallyMe Crypto is the Rust facade for a cross-platform cryptography workspace
spanning Rust, Swift, Kotlin, Android, and TypeScript. It exposes typed
operation owners, explicit provider routing, and the package surfaces used by
the native and WASM adapters.

The protobuf schema is the source of truth for executable structured requests,
responses, algorithm identifiers, and wire errors. Generated bindings feed a
single Rust operation boundary. `provider_manifest.json` fixes the provider
selected for each SDK lane, and positive and negative vectors prove the byte
and failure contract. Missing providers and unsupported algorithms fail closed.

## Install

### Rust

```sh
cargo add reallyme-crypto --features native,dispatch,ed25519
```

The Rust crates require Rust `1.96.0` or newer. That MSRV is intentional:
ReallyMe Crypto tracks current stable Rust so the public packages can use the
compiler, dependency, lint, and target support expected by the conformance wall.

When default features are disabled, enable one backend lane and each algorithm
surface your crate calls:

```toml
reallyme-crypto = { version = "0.3.7", default-features = false, features = [
  "native",
  "ed25519",
  "p256",
  "secp256k1",
  "sha2",
] }
```

Messaging-focused consumers can use the narrow primitive bundle instead of the
default feature set:

```toml
reallyme-crypto = { version = "0.3.7", default-features = false, features = [
  "native",
  "messaging-primitives",
] }
```

`messaging-primitives` enables only ChaCha20-Poly1305/XChaCha20-Poly1305,
HKDF, HMAC, ML-KEM-768, SHA-2, and X25519. The ML-KEM-768 and X25519 algorithm
features require the typed router, so this bundle also enables `dispatch`; it
does not enable `signer`.

Dispatch and signer surfaces are feature-gated by algorithm, so enabling the
router does not pull in unrelated primitives unless the matching algorithm
feature is also selected.

The `native` and `wasm` features select the Rust backend lane. They do not, by
themselves, enable every primitive. Algorithm features such as `ed25519`,
`p256`, or `sha2` enable the root modules and re-exports. This keeps
no-default consumers from pulling unused cryptography while still forwarding
the selected backend into every enabled primitive crate. The `wasm` lane is for
`wasm32` builds; host builds should use `native`.

Some Rust helper APIs are intentionally lane-scoped. P-256 raw scalar import is
available in both native and wasm lanes through
`p256::generate_p256_keypair_from_secret_key`; it validates an existing private
scalar and is not random key generation. P-384 and P-521 ECDH are available
in both Rust lanes; the Swift, Kotlin, and TypeScript facades expose their
manifest-declared provider-backed P-384/P-521 ECDH surfaces.

For standalone X25519 and secp256k1 random key generation, prefer
`try_generate_x25519_keypair` and `try_generate_secp256k1_keypair`. These
return typed errors when operating-system entropy is unavailable. The legacy
infallible functions remain for compatibility; the dispatch API uses the
fallible path.

The Swift package also includes a P-256 ECDH Secure Enclave / Keychain API for
applications that need non-exportable private-key residency, such as JOSE/JWE
decryption with platform-held keys. That API uses explicit handles and is
separate from raw private-key bytes.

## Examples

Fixed keys, nonces, and auxiliary randomness below are public test fixtures.
Applications must supply secret keys and enforce nonce uniqueness for each AEAD
key; never use these fixed values to protect real data.

```rust
// This example requires the `ed25519` feature.
# #[cfg(feature = "ed25519")]
# fn main() -> Result<(), reallyme_crypto::operations::OperationError> {
use reallyme_crypto::Algorithm;
use reallyme_crypto::operations::signature::{generate_key_pair, sign, verify};

let key_pair = generate_key_pair(Algorithm::Ed25519)?;
let signature = sign(Algorithm::Ed25519, &key_pair.secret_key, b"message")?;
verify(Algorithm::Ed25519, &key_pair.public_key, b"message", &signature)?;
# Ok(())
# }
# #[cfg(not(feature = "ed25519"))]
# fn main() {}
```

BIP-340 uses an x-only secp256k1 public key and requires callers to provide a
32-byte message representative and 32 bytes of auxiliary randomness explicitly:

```rust
// This example requires the `secp256k1` feature.
# #[cfg(feature = "secp256k1")]
# fn main() -> Result<(), reallyme_crypto::operations::OperationError> {
use reallyme_crypto::operations::signature::{
    generate_bip340_key_pair, sign_bip340, verify_bip340,
};

let key_pair = generate_bip340_key_pair()?;
let message32 = [0x42u8; 32];
let aux_rand32 = [0x24u8; 32];
let signature = sign_bip340(&key_pair.secret_key, &message32, &aux_rand32)?;
verify_bip340(&signature, &message32, &key_pair.public_key)?;
# Ok(())
# }
# #[cfg(not(feature = "secp256k1"))]
# fn main() {}
```

Hashing is owned by the semantic operation layer. Adapters should call this
surface instead of selecting a primitive independently:

```rust
// This example requires the `sha2` feature.
# #[cfg(feature = "sha2")]
# fn main() -> Result<(), reallyme_crypto::operations::OperationError> {
use reallyme_crypto::HashAlgorithm;
use reallyme_crypto::operations::hash;

let digest = hash::digest(HashAlgorithm::Sha2_256, b"abc")?;
assert_eq!(
    digest,
    [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    ],
);
# Ok(())
# }
# #[cfg(not(feature = "sha2"))]
# fn main() {}
```

HMAC authentication and fail-closed verification share the same semantic
operation owner across Rust, structured protobuf, and C ABI adapters:

```rust
// This example requires the `hmac` feature.
# #[cfg(feature = "hmac")]
# fn main() -> Result<(), reallyme_crypto::operations::OperationError> {
use reallyme_crypto::MacAlgorithm;
use reallyme_crypto::operations::mac;

let key = [0x42u8; 32];
let message = b"authenticated message";
let tag = mac::authenticate(MacAlgorithm::HmacSha256, &key, message)?;
mac::verify(MacAlgorithm::HmacSha256, &key, message, &tag)?;
# Ok(())
# }
# #[cfg(not(feature = "hmac"))]
# fn main() {}
```

Authenticated encryption uses the same operation owner for algorithm selection,
typed failures, and zeroizing recovered plaintext:

```rust
// This example requires the `aes` feature.
# #[cfg(feature = "aes")]
# fn main() -> Result<(), reallyme_crypto::operations::OperationError> {
use reallyme_crypto::operations::aead;
use reallyme_crypto::AeadAlgorithm;

let key = [0x42u8; 32];
let nonce = [0x24u8; 12];
let plaintext = b"authenticated plaintext";
let ciphertext = aead::seal(
    AeadAlgorithm::Aes256Gcm,
    &key,
    &nonce,
    b"context",
    plaintext,
)?;
let opened = aead::open(
    AeadAlgorithm::Aes256Gcm,
    &key,
    &nonce,
    b"context",
    &ciphertext,
)?;
assert_eq!(opened.as_slice(), plaintext);
# Ok(())
# }
# #[cfg(not(feature = "aes"))]
# fn main() {}
```

MLS and HPKE derive nonces from their protocol key schedules. The focused
AES-256-GCM facade therefore accepts an explicit typed nonce and deliberately
does not offer a random-nonce overload:

```rust
// This example requires the `aes` feature.
# #[cfg(feature = "aes")]
# fn main() -> Result<(), reallyme_crypto::CryptoError> {
use reallyme_crypto::aes256_gcm::{
    aes256_gcm_decrypt, aes256_gcm_encrypt, Aes256GcmKey, Aes256GcmNonce,
};

let key = Aes256GcmKey::from_slice(&[0x42; 32])?;
// In MLS or HPKE, this value comes from the protocol key schedule.
let nonce = Aes256GcmNonce::from_slice(&[0x24; 12])?;
let ciphertext = aes256_gcm_encrypt(&key, nonce, b"context", b"payload")?;
let plaintext = aes256_gcm_decrypt(&key, nonce, b"context", &ciphertext)?;
assert_eq!(plaintext, b"payload");
# Ok(())
# }
# #[cfg(not(feature = "aes"))]
# fn main() {}
```

The HPKE facade exposes explicit registry identifiers and derives its nonce
internally; seal/open requests have no caller-supplied nonce field:

```rust
// This example requires the `hpke` and `native` features.
# #[cfg(all(feature = "hpke", feature = "native"))]
# fn main() -> Result<(), reallyme_crypto::operations::OperationError> {
use reallyme_crypto::hpke::{
    derive_keypair, open_base, seal_base, HpkeOpenRequest, HpkeSealRequest,
    HPKE_DHKEM_P256_HKDF_SHA256_AES256GCM,
};

let suite = HPKE_DHKEM_P256_HKDF_SHA256_AES256GCM;
let recipient = derive_keypair(suite, &[0x5a; 32])?;
let sealed = seal_base(&HpkeSealRequest {
    suite,
    recipient_public_key: &recipient.public_key,
    info: b"reallyme/example/v0.3",
    aad: b"message metadata",
    plaintext: b"confidential payload",
})?;
let opened = open_base(&HpkeOpenRequest {
    suite,
    encapsulated_key: &sealed.encapsulated_key,
    recipient_private_key: recipient.private_key(),
    info: b"reallyme/example/v0.3",
    aad: b"message metadata",
    ciphertext: &sealed.ciphertext,
})?;
assert_eq!(opened.plaintext.as_slice(), b"confidential payload");
# Ok(())
# }
# #[cfg(not(all(feature = "hpke", feature = "native")))]
# fn main() {}
```

AES-KW uses the operation owner for suite selection and returns unwrapped key
material in a zeroizing owner:

```rust
// This example requires the `aes-kw` feature.
# #[cfg(feature = "aes-kw")]
# fn main() -> Result<(), reallyme_crypto::operations::OperationError> {
use reallyme_crypto::operations::key_wrap;
use reallyme_crypto::KeyWrapAlgorithm;

let kek = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
let key_data = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];
let wrapped = key_wrap::wrap_key(KeyWrapAlgorithm::Aes128Kw, &kek, &key_data)?;
let unwrapped = key_wrap::unwrap_key(
    KeyWrapAlgorithm::Aes128Kw,
    &kek,
    wrapped.as_bytes(),
)?;
assert_eq!(unwrapped.as_bytes(), key_data);
# Ok(())
# }
# #[cfg(not(feature = "aes-kw"))]
# fn main() {}
```

Signature verification fails closed: an invalid signature returns an error
rather than a boolean that can be accidentally ignored.

## Protobuf

Enable `operation-response` to use
`reallyme_crypto::operation_contract::process_operation_response(request_bytes)`.
It accepts an encoded `CryptoOperationRequest` and returns binary
`CryptoOperationResponse` bytes containing a typed result or error. The
ProtoJSON entrypoint accepts only non-secret request selectors and still returns
binary protobuf. Secret-bearing operations must use binary protobuf.

See [the protobuf contract](https://github.com/reallyme/crypto/blob/main/docs/protobuf.md)
for schemas, generated SDK adapters, limits, and JSON restrictions.

## Documentation

See the [repository overview](https://github.com/reallyme/crypto) for the complete
algorithm list and other SDKs. The [provider policy](https://github.com/reallyme/crypto/blob/main/PROVIDER_POLICY.md),
[memory model](https://github.com/reallyme/crypto/blob/main/SECURITY_MEMORY_MODEL.md),
and [conformance instructions](https://github.com/reallyme/crypto/blob/main/docs/conformance.md)
define the shared guarantees and validation requirements.

## License

Licensed under either the MIT License or the Apache License, Version 2.0,
at your option. See [LICENSE](https://github.com/reallyme/crypto/blob/main/LICENSE). Third-party components retain
their own licenses and notices.
