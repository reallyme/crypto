<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# reallyme-crypto

[![Code Checks](https://github.com/reallyme/crypto/actions/workflows/rust-ci.yml/badge.svg)](https://github.com/reallyme/crypto/actions/workflows/rust-ci.yml)
[![reallyme-crypto](https://img.shields.io/crates/v/reallyme-crypto?label=reallyme-crypto&color=2563eb)](https://crates.io/crates/reallyme-crypto)
[![npm](https://img.shields.io/npm/v/@reallyme/crypto?label=npm&color=2563eb)](https://www.npmjs.com/package/@reallyme/crypto)
[![Maven Central](https://img.shields.io/maven-central/v/me.really/crypto?label=maven)](https://central.sonatype.com/artifact/me.really/crypto)
[![Security Policy](https://img.shields.io/badge/security-policy-0f766e)](https://github.com/reallyme/crypto/blob/main/SECURITY.md)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/reallyme/crypto/blob/main/LICENSE)

ReallyMe Crypto is the Rust facade for a cross-platform cryptography workspace
spanning Rust, Swift, Kotlin, Android, and TypeScript. It exposes typed
operation owners, explicit provider routing, and the package surfaces used by
the native and WASM adapters.

The protobuf schema is the source of truth for executable structured requests,
responses, algorithm identifiers, and wire errors. Generated bindings feed a
single Rust operation boundary. `provider_manifest.json` fixes the provider
selected for each SDK lane, and positive and negative vectors prove the byte
and failure contract. Missing providers and unsupported algorithms fail closed.

## Why

Modern cryptography APIs differ across platforms. Algorithms are exposed
differently, key formats vary, providers have different capabilities, and error
behavior is inconsistent.

ReallyMe Crypto makes platform differences explicit while preserving consistent
algorithm identifiers, encodings, errors, and verification semantics for every
supported route. Provider selection is deterministic and unavailable routes
return typed errors instead of switching implementations.

## Packages

| Language | Package | Notes |
|---|---|---|
| Rust | `reallyme-crypto` | Umbrella crate for cryptographic APIs. |
| Swift | `ReallyMeCrypto` | Swift Package at the repository root, with native Apple providers and Rust C ABI routes where needed. |
| Kotlin/JVM | [`me.really:crypto`](https://central.sonatype.com/artifact/me.really/crypto) | JVM package with explicit JCA/JCE, BouncyCastle, and Rust-backed routes. |
| Android | `me.really:crypto-android` | Android AAR with `jniLibs` Rust provider packaging and the published `me.really:codec-android` dependency. |
| TypeScript | [`@reallyme/crypto`](https://www.npmjs.com/package/@reallyme/crypto) | npm package for Node, browsers, and WASM-backed primitives. |
| Protobuf | `reallyme/crypto/v1/crypto.proto` | Canonical structured operation, algorithm identifier, and typed wire-error contract. |

General-purpose encoding, serialization, and multiformat codec APIs live in
[`github.com/reallyme/codec`](https://github.com/reallyme/codec).

## Supported Algorithms

| Category | Algorithms |
|---|---|
| AEAD and key wrap | AES-128/192/256-GCM, AES-256-GCM-SIV, AES-128/192/256-KW, ChaCha20-Poly1305, XChaCha20-Poly1305 |
| Hash, MAC, and KDF | SHA-2, SHA-3, HMAC-SHA-256/384/512, HKDF-SHA256/384, KMAC256 KDF, JWA Concat KDF (ECDH-ES), PBKDF2-HMAC-SHA-256/512, Argon2id |
| Signatures | Ed25519, ECDSA P-256/P-384/P-521, secp256k1 ECDSA, BIP-340 Schnorr, RSA verification, ML-DSA-44/65/87, SLH-DSA-SHA2-128s |
| Key agreement and KEM | X25519, P-256/P-384/P-521 ECDH, ML-KEM-512/768/1024, X-Wing-768 |
| Protocols | HPKE |
| Key and wire envelopes | JWK and public-key multikey bindings used by the crypto facades |

X-Wing-768 follows the IETF CFRG Internet-Draft
[`draft-connolly-cfrg-xwing-kem`](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/),
which defines a hybrid KEM built from X25519 and ML-KEM-768.

The ML-KEM and X-Wing deterministic key-derivation and encapsulation helpers
are expert conformance APIs. They consume caller-supplied seed or encapsulation
randomness and therefore must not replace randomized key generation or
encapsulation in production protocols. Their public contract is gated by the
same committed known-answer vectors used across supported SDK lanes.

Availability varies by SDK lane. The exact provider and support map lives in
[PROVIDER_POLICY.md](https://github.com/reallyme/crypto/blob/main/PROVIDER_POLICY.md). For each language lane,
an algorithm is either handled by its declared provider
or rejected with a typed unsupported-algorithm error.

### HPKE Profiles

The cross-platform SDK facade exposes two RFC 9180 Base-mode profiles:

| Profile | KEM | KDF | AEAD |
|---|---|---|---|
| `DHKEM-P256-HKDF-SHA256-HKDF-SHA256-AES-256-GCM` | DHKEM(P-256, HKDF-SHA256) | HKDF-SHA256 | AES-256-GCM |
| `DHKEM-X25519-HKDF-SHA256-HKDF-SHA256-CHACHA20-POLY1305` | DHKEM(X25519, HKDF-SHA256) | HKDF-SHA256 | ChaCha20-Poly1305 |

The Rust native operation contract also supports reviewed classical,
post-quantum, and hybrid HPKE components. See the
[protobuf contract](https://github.com/reallyme/crypto/blob/main/docs/protobuf.md#hpke-support)
for the executable component set and operation-level constraints.

For OpenMLS adapters, the Rust HPKE API additionally exposes suite-generic PSK
sender and receiver contexts, typed PSK references, arbitrary-length IKM key
derivation through the selected KEM's `DeriveKeyPair` construction, and exact
aliases for the MLS 192/256-bit ML-KEM-1024 and MLKEM1024-P384 draft profiles.
Live contexts are deliberately non-exportable and remain outside serialized
SDK transports. Deterministic Base seal and sender export have operation-layer
entry points behind `test-vectors`; caller-controlled randomness is never part
of the production protobuf contract. The operation facade requires at least 32
bytes of high-entropy IKM; the explicit raw HPKE alias retains the KEM-defined
non-empty input contract.

With default features disabled, `hpke-openmls` selects only ML-KEM-1024,
ML-KEM-1024/P-384, X-Wing, HKDF-SHA256, HKDF-SHA384, AES-256-GCM, and
ChaCha20-Poly1305. The SHAKE256 HPKE KDF and unrelated KEMs are excluded. The
existing `hpke` feature remains the compatibility aggregate for the complete
reviewed HPKE surface. Direct `reallyme-crypto-hpke` consumers can compose
individual `kem-*`, `kdf-*`, and `aead-*` component features.

The root `reallyme_crypto::hpke` facade makes its error boundary explicit.
Established unsuffixed functions and their `*_operation` aliases return the
workspace-wide `OperationError`; matching `*_raw` aliases return `HpkeError`
directly for protocol adapters that need HPKE-specific failure handling. Raw
split sender outputs use the `RawHpkePskSenderSetupOutput` and
`RawHpkePskSenderContext` names so traffic-state ownership is unambiguous.

Every provider route must implement identical input validation and
normalization, output encodings, typed failure semantics, and edge-case
behavior. Security-sensitive composition, canonical serialization,
deterministic signatures, post-quantum primitives, memory-hard KDFs, and
provider-ambiguous algorithms default to the ReallyMe Rust implementation
through FFI, JNI, or WASM unless a native route is explicitly proven equivalent.

RSA support is intentionally verification-only for historical X.509 and eMRTD
PKI interoperability. The package does not generate RSA keys, sign with RSA
private keys, or provide RSA encryption/decryption APIs.

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
reallyme-crypto = { version = "0.3.3", default-features = false, features = [
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
reallyme-crypto = { version = "0.3.3", default-features = false, features = [
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
scalar and is not random key generation. P-384 and P-521 ECDH are native Rust
APIs today; the Swift, Kotlin, and TypeScript package facades expose their own
provider-backed P-384/P-521 ECDH surfaces.

The Swift package also includes a P-256 ECDH Secure Enclave / Keychain API for
applications that need non-exportable private-key residency, such as JOSE/JWE
decryption with platform-held keys. That API uses explicit handles and is
separate from raw private-key bytes.

### Swift

```swift
.package(
    url: "https://github.com/reallyme/crypto",
    from: "0.3.3"
)
```

```swift
.product(name: "ReallyMeCrypto", package: "crypto")
```

### Kotlin

```kotlin
dependencies {
    implementation("me.really:crypto:0.3.3")
}
```

### TypeScript

```sh
npm install @reallyme/crypto
```

For production deployments, pin exact package versions, release tags, or Git
revisions so cryptographic behavior and conformance vectors remain identical
across all language lanes.

## Quick Start

Rust:

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

Swift:

```swift
import ReallyMeCrypto

let digest = try ReallyMeCrypto.hash(.sha2_256, Array("abc".utf8))
```

Kotlin:

```kotlin
import me.really.crypto.ReallyMeCrypto
import me.really.crypto.ReallyMeHashAlgorithm

val digest = ReallyMeCrypto.hash(ReallyMeHashAlgorithm.SHA2_256, "abc".toByteArray())
```

TypeScript:

```ts
import { ReallyMeCrypto } from "@reallyme/crypto";

const digest = ReallyMeCrypto.hash("SHA2-256", new TextEncoder().encode("abc"));
```

Signature verification fails closed: an invalid signature returns an error
rather than a boolean that can be accidentally ignored.

## Protobuf

The canonical structured wire contract lives at
[`crates/proto/proto/reallyme/crypto/v1/crypto.proto`](https://github.com/reallyme/crypto/blob/main/crates/proto/proto/reallyme/crypto/v1/crypto.proto).
Service, application, and storage protos can import it when they need the
structured operation boundary, stable algorithm identifiers, or typed errors.

ReallyMe Crypto uses raw bytes for single primitive outputs, protobuf bytes for
fixed multi-field boundary results, and strict proto-JSON for Connect JSON,
CLI, browser-adapter, and conformance boundaries that require JSON. Proto-JSON
is available for operation requests, but it is not a casual
JSON crypto facade and is not the preferred representation for secret-bearing
payloads. JSON convenience shapes remain limited to public metadata such as
JWK/JWKS.

For example, a JSON-only client can express a SHA2-256 hash request as strict
proto-JSON:

```json
{
  "hash": {
    "algorithm": {
      "hash": "HASH_ALGORITHM_SHA2_256"
    },
    "input": "YWJj"
  }
}
```

See [docs/proto-json.md](https://github.com/reallyme/crypto/blob/main/docs/proto-json.md) for operation-family examples and
the security notes for secret-bearing JSON payloads.

Rust adapters can enable the `operation-response` feature and call
`reallyme_crypto::operation_contract::process_operation_response(request_bytes)`
with one encoded `CryptoOperationRequest`: serialized request bytes in, binary
`CryptoOperationResponse` bytes out, with either a generated
`CryptoOperationResult` or generated `CryptoError` outcome. The ProtoJSON
entrypoint accepts only generated non-secret hash, verification,
key-generation, encapsulation, and sender-export requests and still returns
binary protobuf. Secret-bearing operations must use the binary protobuf route.
TypeScript exposes `processOperationResponse`
and `processOperationResponseJson`; Swift and Kotlin expose the same method
names on `ReallyMeCrypto`. Every structured adapter returns the generated
operation response directly. Native SDK methods remain the primary ergonomic
application API.

The generated proto adapters are available through:

| Language | Proto surface |
|---|---|
| Rust | `reallyme-crypto-proto` |
| Swift | `ReallyMeCryptoProto` and `ReallyMeCryptoProtoAdapters` |
| Kotlin | `me.really.crypto.v1` and `me.really.crypto.proto` |
| TypeScript | `@reallyme/crypto/proto` |

See [docs/protobuf.md](https://github.com/reallyme/crypto/blob/main/docs/protobuf.md) for the boundary rules and adapter
policy.

## Documentation

- [PROVIDER_POLICY.md](https://github.com/reallyme/crypto/blob/main/PROVIDER_POLICY.md) — provider matrix and backend
  selection for every algorithm and lane.
- [CONTRACT.md](https://github.com/reallyme/crypto/blob/main/CONTRACT.md) — the public package and wire contract.
- [docs/jwk.md](https://github.com/reallyme/crypto/blob/main/docs/jwk.md) — JWK and multikey encoding.
- [docs/protobuf.md](https://github.com/reallyme/crypto/blob/main/docs/protobuf.md) — structured operations, algorithm
  identifiers, typed wire errors, and boundary rules.
- [docs/proto-json.md](https://github.com/reallyme/crypto/blob/main/docs/proto-json.md) — strict proto-JSON request examples.
- [docs/conformance.md](https://github.com/reallyme/crypto/blob/main/docs/conformance.md) — running the conformance vectors.
- [docs/dependency-updates.md](https://github.com/reallyme/crypto/blob/main/docs/dependency-updates.md) — dependency update
  policy and Renovate review rules.
- [docs/rust-publishing.md](https://github.com/reallyme/crypto/blob/main/docs/rust-publishing.md) — publishing the Rust crates.
- [SECURITY.md](https://github.com/reallyme/crypto/blob/main/SECURITY.md), [SECURITY_MEMORY_MODEL.md](https://github.com/reallyme/crypto/blob/main/SECURITY_MEMORY_MODEL.md)
  — reporting security issues and how secret material is handled.

## Security Rules

This repository is security-sensitive code. The project policy is:

- no panics, unwraps, or generic string errors in production paths;
- typed errors only;
- zeroizing owners for secret material;
- checked arithmetic for buffer sizes and offsets;
- negative tests and conformance vectors for every primitive;
- no silent platform fallback in release platform lanes.

## Conformance

Shared vectors live in [vectors](https://github.com/reallyme/crypto/tree/main/vectors). The generator and platform verifiers
live in [crates/conformance](https://github.com/reallyme/crypto/tree/main/crates/conformance).

The everyday all-feature Rust check is:

```sh
cargo nextest run --workspace --all-features
```

The full release wall is documented in [docs/conformance.md](https://github.com/reallyme/crypto/blob/main/docs/conformance.md).
