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

ReallyMe Crypto provides a platform-agnostic cryptography API for Rust, Swift,
Kotlin, and TypeScript. Applications can implement cryptographic logic once
and rely on identical algorithms, key formats, and verification behavior across
servers, Apple platforms, Android, browsers, and WASM. Native platform providers
are used where appropriate, while shared conformance vectors ensure byte-for-byte
compatible behavior across every supported language.

The canonical contract is not mechanically generated from one language API. It
is the combination of protobuf/enums, package algorithm identifiers, typed error
taxonomy, provider manifest, and shared conformance vectors. Rust is the
reference implementation and the shared implementation for selected primitives;
platform facades may use approved native providers only when the same input,
output, error, and edge-case contract is proven by vectors and negative tests.

> [!NOTE]
> **Current release:** [`0.2.0`](https://github.com/reallyme/crypto/releases/tag/v0.2.0).
> Public APIs and wire contracts are
> documented in `CONTRACT.md` and evolve through explicit versioned releases.
> Cross-language package release requirements are tracked in
> `RELEASE_BLOCKERS.md` and enforced by release preflight checks.

## Why

Modern cryptography APIs differ across platforms. Algorithms are exposed
differently, key formats vary, providers have different capabilities, and error
behavior is inconsistent.

ReallyMe Crypto provides a consistent cryptography contract across all
supported platforms. The same application logic can be shared between backend
services, mobile applications, and browsers without maintaining separate
cryptographic implementations. Provider selection is always explicit,
verification fails closed, and unsupported algorithms return typed errors instead
of silently falling back to another implementation.

## Packages

| Language | Package | Notes |
|---|---|---|
| Rust | `reallyme-crypto` | Umbrella crate for cryptographic APIs. |
| Swift | `ReallyMeCrypto` | Swift Package at the repository root, with native Apple providers and Rust C ABI routes where needed. |
| Kotlin/JVM | [`me.really:crypto`](https://central.sonatype.com/artifact/me.really/crypto) | JVM package with explicit JCA/JCE, BouncyCastle, and Rust-backed routes. |
| Android | `me.really:crypto-android` | Android AAR with `jniLibs` Rust provider packaging and the published `me.really:codec-android` dependency. |
| TypeScript | [`@reallyme/crypto`](https://www.npmjs.com/package/@reallyme/crypto) | npm package for Node, browsers, and WASM-backed primitives. |
| Protobuf | `reallyme/crypto/v1/crypto.proto` | Importable identifiers and non-PII error envelopes for wire and configuration contracts. |

Encoding, serialization, and multiformat codec concepts now live in
[`github.com/reallyme/codec`](https://github.com/reallyme/codec).

## Supported Algorithms

| Category | Algorithms |
|---|---|
| AEAD and key wrap | AES-128/192/256-GCM, AES-256-GCM-SIV, AES-256-KW, ChaCha20-Poly1305, XChaCha20-Poly1305 |
| Hash, MAC, and KDF | SHA-2, SHA-3, HMAC-SHA-256/512, HKDF-SHA256, JWA Concat KDF (ECDH-ES), PBKDF2-HMAC-SHA-256/512, Argon2id |
| Signatures | Ed25519, ECDSA P-256/P-384/P-521, secp256k1 ECDSA, BIP-340 Schnorr, RSA verification, ML-DSA-44/65/87, SLH-DSA-SHA2-128s |
| Key agreement and KEM | X25519, P-256/P-384/P-521 ECDH, ML-KEM-512/768/1024, X-Wing-768/1024 |
| Protocols | HPKE |
| Key and wire envelopes | JWK and public-key multikey bindings used by the crypto facades |

X-Wing-768 follows the IETF CFRG Internet-Draft
[`draft-connolly-cfrg-xwing-kem`](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/),
which defines a hybrid KEM built from X25519 and ML-KEM-768. X-Wing-1024 uses
the same combiner shape with ML-KEM-1024.

The exact per-language provider map lives in
[PROVIDER_POLICY.md](PROVIDER_POLICY.md). For each language lane,
an algorithm is either handled by its declared provider
or rejected with a typed unsupported-algorithm error.
Every provider route must implement identical input validation and
normalization, output encodings, typed failure semantics, and edge-case
behavior. Security-sensitive composition, canonical serialization,
deterministic signatures, post-quantum primitives, memory-hard KDFs, and
provider-ambiguous algorithms default to the ReallyMe Rust implementation
through FFI, JNI, or WASM unless a native route is explicitly proven equivalent.

RSA support is intentionally verification-only for X.509, eMRTD, and legacy
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
reallyme-crypto = { version = "0.2.0", default-features = false, features = [
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
reallyme-crypto = { version = "0.2.0", default-features = false, features = [
  "native",
  "messaging-primitives",
] }
```

`messaging-primitives` enables only ChaCha20-Poly1305/XChaCha20-Poly1305,
HKDF, HMAC, ML-KEM-768, SHA-2, and X25519. It does not enable `dispatch` or
`signer`. Use `messaging-dispatch` when a crate needs the same narrow set
through algorithm-by-identifier dispatch:

```toml
reallyme-crypto = { version = "0.2.0", default-features = false, features = [
  "native",
  "messaging-dispatch",
] }
```

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
    from: "0.2.0"
)
```

```swift
.product(name: "ReallyMeCrypto", package: "crypto")
```

### Kotlin

```kotlin
dependencies {
    implementation("me.really:crypto:0.2.0")
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
use reallyme_crypto::core::Algorithm;
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

The importable wire/config contract lives at
[`crates/proto/crypto/proto/reallyme/crypto/v1/crypto.proto`](crates/proto/crypto/proto/reallyme/crypto/v1/crypto.proto).
Service, application, and storage protos can import them when they need stable
algorithm identifiers or non-secret error envelopes.

ReallyMe Crypto uses raw bytes for single primitive outputs, protobuf bytes for
fixed multi-field boundary results, and JSON convenience shapes only for public
metadata such as JWK/JWKS. Operation request/result envelopes and structured
`CryptoError` bytes are intended for FFI, RPC, storage, and Connect-ready
service wrappers.

Rust service adapters can enable the `proto-process` feature and call
`reallyme_crypto::proto_process::process_proto(operation, request_bytes)` for a
Codec-style executable protobuf lane: serialized request bytes in, result
envelope bytes out, with structured `CryptoError` bytes on failure. Native
Swift, Kotlin, TypeScript, and Rust SDK methods remain the primary ergonomic
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
- [docs/jwk.md](docs/jwk.md) — JWK and multikey encoding.
- [docs/protobuf.md](docs/protobuf.md) — protobuf identifiers, error envelopes,
  and boundary rules.
- [docs/conformance.md](docs/conformance.md) — running the conformance vectors.
- [docs/dependency-updates.md](docs/dependency-updates.md) — dependency update
  policy and Renovate review rules.
- [docs/rust-publishing.md](docs/rust-publishing.md) — publishing the Rust crates.
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
live in [crates/conformance/vectors](crates/conformance/vectors).

The everyday all-feature Rust check is:

```sh
cargo nextest run --workspace --all-features
```

The full release wall is documented in [docs/conformance.md](docs/conformance.md).
