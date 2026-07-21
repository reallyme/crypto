<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# reallyme-crypto

[![Code Checks](https://github.com/reallyme/crypto/actions/workflows/rust-ci.yml/badge.svg)](https://github.com/reallyme/crypto/actions/workflows/rust-ci.yml)
[![reallyme-crypto](https://img.shields.io/crates/v/reallyme-crypto?label=reallyme-crypto&color=2563eb)](https://crates.io/crates/reallyme-crypto)
[![npm](https://img.shields.io/npm/v/@reallyme/crypto?label=npm&color=2563eb)](https://www.npmjs.com/package/@reallyme/crypto)
[![Maven Central](https://img.shields.io/maven-central/v/me.really/crypto?label=maven)](https://central.sonatype.com/artifact/me.really/crypto)
[![Security Policy](https://img.shields.io/badge/security-policy-0f766e)](SECURITY.md)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

ReallyMe Crypto is a cross-platform cryptography workspace for Rust, Swift,
Kotlin, Android, and TypeScript. It provides one typed operation contract,
explicit provider routing, and shared conformance evidence across server,
mobile, browser, and WASM environments.

The protobuf schema is the source of truth for executable structured requests,
responses, algorithm identifiers, and wire errors. Generated bindings feed a
single Rust operation boundary; native SDK facades provide ergonomic APIs over
the same semantics. `provider_manifest.json` fixes the provider selected for
each SDK lane, and positive and negative vectors prove the byte and failure
contract. Missing providers and unsupported algorithms fail closed.
The canonical contract is not mechanically generated from one language API.

## Why

Modern cryptography APIs differ across platforms. Algorithms are exposed
differently, key formats vary, providers have different capabilities, and error
behavior is inconsistent.

ReallyMe Crypto makes those differences explicit. Applications use consistent
algorithm identifiers, encodings, errors, and verification semantics wherever
a lane is supported. Provider selection is deterministic, verification fails
closed, and an unavailable route returns a typed error instead of switching
implementations.

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
| Key agreement and KEM | X25519, X448 (standalone Rust crate and HPKE component only), P-256/P-384/P-521/secp256k1 ECDH, ML-KEM-512/768/1024, X-Wing-768 |
| Protocols | HPKE |
| Key and wire envelopes | JWK and public-key multikey bindings used by the crypto facades |

X-Wing-768 follows the IETF CFRG Internet-Draft
[`draft-connolly-cfrg-xwing-kem`](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/),
which defines a hybrid KEM built from X25519 and ML-KEM-768.

Availability varies by SDK lane. The exact provider and support map lives in
[PROVIDER_POLICY.md](PROVIDER_POLICY.md). For each language lane,
an algorithm is either handled by its declared provider
or rejected with a typed unsupported-algorithm error.

X448 is not an umbrella-crate or SDK-facade algorithm. It is available through
the standalone `reallyme-crypto-x448` Rust crate and as an internal HPKE KEM
component. It is therefore intentionally absent from the package provider
manifest and exact cross-language support map.

### HPKE Profiles

The cross-platform SDK facade exposes two RFC 9180 Base-mode profiles:

| Profile | KEM | KDF | AEAD | Swift | Kotlin/JVM and Android | TypeScript |
|---|---|---|---|---|---|---|
| `DHKEM-P256-HKDF-SHA256-HKDF-SHA256-AES-256-GCM` | DHKEM(P-256, HKDF-SHA256) | HKDF-SHA256 | AES-256-GCM | Rust C ABI provider | BouncyCastle | Rust WASM provider |
| `DHKEM-X25519-HKDF-SHA256-HKDF-SHA256-CHACHA20-POLY1305` | DHKEM(X25519, HKDF-SHA256) | HKDF-SHA256 | ChaCha20-Poly1305 | Rust C ABI provider | BouncyCastle | Rust WASM provider |

Swift requires an explicit Rust C ABI provider for these profiles. Missing or
unavailable providers fail closed. The Rust native operation contract also
supports reviewed classical, post-quantum, and hybrid HPKE components; see
[docs/protobuf.md](docs/protobuf.md#hpke-support) for the executable component
set and operation-level constraints.

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
reallyme-crypto = { version = "0.3.0", default-features = false, features = [
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
reallyme-crypto = { version = "0.3.0", default-features = false, features = [
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
    from: "0.3.0"
)
```

```swift
.product(name: "ReallyMeCrypto", package: "crypto")
```

### Kotlin

```kotlin
dependencies {
    implementation("me.really:crypto:0.3.0")
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
use reallyme_crypto::Algorithm;
use reallyme_crypto::dispatch::{generate_keypair, sign, verify};

let (public_key, secret_key) = generate_keypair(Algorithm::Ed25519)?;
let signature = sign(Algorithm::Ed25519, &secret_key, b"message")?;
verify(Algorithm::Ed25519, &public_key, b"message", &signature)?;
# Ok::<(), reallyme_crypto::dispatch::AlgorithmError>(())
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
[`crates/proto/proto/reallyme/crypto/v1/crypto.proto`](crates/proto/proto/reallyme/crypto/v1/crypto.proto).
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

See [docs/proto-json.md](docs/proto-json.md) for operation-family examples and
the security notes for secret-bearing JSON payloads.

Rust adapters can enable the `operation-response` feature and call
`reallyme_crypto::operation_contract::process_operation_response(request_bytes)`
with one encoded `CryptoOperationRequest`: serialized request bytes in, binary
`CryptoOperationResponse` bytes out, with either a generated
`CryptoOperationResult` or generated `CryptoError` outcome. The ProtoJSON
entrypoint accepts the generated JSON representation of the same request and
still returns binary protobuf. TypeScript exposes `processOperationResponse`
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

See [docs/protobuf.md](docs/protobuf.md) for the boundary rules and adapter
policy.

## Documentation

- [PROVIDER_POLICY.md](PROVIDER_POLICY.md) — provider matrix and backend
  selection for every algorithm and lane.
- [CONTRACT.md](CONTRACT.md) — the public package and wire contract.
- [docs/architecture.md](docs/architecture.md) — workspace boundaries and
  dependency direction.
- [docs/jwk.md](docs/jwk.md) — JWK and multikey encoding.
- [docs/protobuf.md](docs/protobuf.md) — structured operations, algorithm
  identifiers, typed wire errors, and boundary rules.
- [docs/proto-json.md](docs/proto-json.md) — strict proto-JSON request examples.
- [docs/conformance.md](docs/conformance.md) — running the conformance vectors.
- [docs/external-conformance-vectors.md](docs/external-conformance-vectors.md)
  — External conformance vectors from NIST ACVP, CCTV, Wycheproof, BIP-340, and
  RFC 8032, plus the optional audit workflow and formal-methods notes.
- [docs/dependency-updates.md](docs/dependency-updates.md) — dependency update
  policy and Renovate review rules.
- [docs/rust-publishing.md](docs/rust-publishing.md) — publishing the Rust crates.
- [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) — cross-ecosystem release gates.
- [SECURITY.md](SECURITY.md), [SECURITY_MEMORY_MODEL.md](SECURITY_MEMORY_MODEL.md)
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

Shared vectors live in [vectors](vectors). The generator and platform verifiers
live in [crates/conformance](crates/conformance). External third-party vector
coverage is documented in
[External conformance vectors](docs/external-conformance-vectors.md).

The everyday all-feature Rust check is:

```sh
cargo nextest run --workspace --all-features
```

The full release wall is documented in [docs/conformance.md](docs/conformance.md).
