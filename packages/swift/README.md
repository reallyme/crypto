<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# ReallyMeCrypto Swift

`ReallyMeCrypto` is the Swift SDK for
[ReallyMe Crypto](https://github.com/reallyme/crypto), for Apple platforms.

ReallyMe Crypto provides a platform-agnostic cryptography API for Rust, Swift,
Kotlin, and TypeScript. Applications can implement cryptographic operations once
and rely on identical algorithms, key formats, and verification behavior across
servers, Apple platforms, Android, browsers, and WASM. On Apple platforms, native
providers are used where appropriate, while shared conformance vectors ensure
byte-for-byte compatible behavior across every supported language.

The manifest sits at the repository root (`Package.swift`) so SwiftPM can add it
by Git URL; the source lives under `packages/swift` with the other language SDKs.

## Install

```swift
.package(
    url: "https://github.com/reallyme/crypto",
    from: "0.2.0"
)
```

```swift
.product(name: "ReallyMeCrypto", package: "crypto")
```

Applications that store or receive ReallyMe crypto protobuf identifiers can add
the proto products at the same boundary:

```swift
.product(name: "ReallyMeCryptoProto", package: "crypto")
.product(name: "ReallyMeCryptoProtoAdapters", package: "crypto")
```

## Quick Start

```swift
import ReallyMeCrypto

let digest = try ReallyMeCrypto.hash(.sha2_256, Array("abc".utf8))

let tag = try ReallyMeCrypto.authenticate(
    .hmacSha256,
    key: key,
    message: Array("message".utf8)
)

let ciphertext = try ReallyMeCrypto.seal(
    .aes256Gcm,
    key: aeadKey,
    nonce: nonce,
    aad: aad,
    plaintext: plaintext
)

let plaintext = try ReallyMeCrypto.open(
    .aes256Gcm,
    key: aeadKey,
    nonce: nonce,
    aad: aad,
    ciphertextWithTag: ciphertext
)
```

Signature verification throws on invalid signatures. It does not return a
boolean that can be accidentally ignored.

## Provider Model

Provider selection is explicit:

- CryptoKit for Apple-native classical primitives where it matches the shared
  contract.
- Security.framework / Secure Enclave for P-256 ECDH keys that must stay
  non-exportable.
- [reallyme/CSecp256k1](https://github.com/reallyme/CSecp256k1) for
  secp256k1 ECDSA, since CryptoKit does not provide secp256k1.
- Digest for SHA-3, which CryptoKit does not expose.
- The ReallyMe Rust C ABI for primitives that should stay shared with Rust,
  including ML-KEM, ML-DSA, SLH-DSA, X-Wing, Argon2id, AES-KW, HPKE, and RSA
  verification.

The public API has two layers:

- algorithm-specific types, such as `ReallyMeX25519`, `ReallyMeP256Ecdh`, and
  `ReallyMeSecp256k1`;
- `ReallyMeCrypto`, a typed facade keyed by repository-wide algorithm enums.

Reserved identifiers, future contract entries, and unsupported overload shapes
throw `ReallyMeCryptoError.unsupportedAlgorithm`. The Swift package does not
silently fall back to a different provider. The complete lane is tracked in
[PROVIDER_POLICY.md](../../PROVIDER_POLICY.md).

## Secure Enclave ECDH

Use the handle-backed P-256 API when an application needs a platform-held key
for JOSE/JWE or another ECDH flow. The private key is generated as a permanent
Secure Enclave key; callers store the returned handle, not raw private-key
bytes.

```swift
let tag = Array("me.really.example.p256.jwe".utf8)
let keyPair = try ReallyMeCrypto.generateSecureEnclaveKeyAgreementKeyPair(
    .p256Ecdh,
    tag: tag,
    overwriteExisting: false
)

let sharedSecret = try ReallyMeCrypto.deriveSharedSecretWithPrivateKeyHandle(
    .p256Ecdh,
    publicKey: peerPublicKey,
    privateKeyHandle: keyPair.privateKeyHandle
)
```

The handle API is intentionally separate from `ReallyMeP256Ecdh`, which accepts
raw private-key bytes. Unsupported platforms return
`ReallyMeCryptoError.unsupportedPlatform`; unsupported algorithms return
`ReallyMeCryptoError.unsupportedAlgorithm`.

## Protobuf

```swift
import ReallyMeCrypto
import ReallyMeCryptoProto
import ReallyMeCryptoProtoAdapters

let facadeAlgorithm = try ReallyMeCryptoProtoAdapters.fromProto(
    ReallyMeCryptoProto.ReallyMeProtoHashAlgorithm.sha2256
)
let protoAlgorithm = ReallyMeCryptoProtoAdapters.toProto(facadeAlgorithm)
```

`UNSPECIFIED`, unrecognized values, and private reserved identifiers throw
`ReallyMeCryptoError.unsupportedAlgorithm`.

## Rust C ABI Providers

Released SwiftPM packages ship the `ReallyMeCryptoFFI` binary target and link
the Rust C ABI provider automatically. A consumer that adds the package and uses
`ReallyMeCrypto()` gets Apple-native routes where those are approved and the
bundled Rust provider for Rust-backed primitives such as ML-KEM, ML-DSA,
SLH-DSA, X-Wing, Argon2id, AES-KW, HPKE, and RSA verification.

Source-tree development can still build and install a freshly compiled Rust C
ABI library in an explicit provider context:

```sh
cargo build -p crypto-ffi
```

```swift
let rustAbi = try ReallyMeRustCAbiLibrary(path: "/path/to/libcrypto_ffi.dylib")
let crypto = ReallyMeCrypto(providers: ReallyMeCryptoProviders(rustCAbiLibrary: rustAbi))

let wrappedKey = try crypto.wrapKey(
    .aes256Kw,
    wrappingKey: keyEncryptionKey,
    keyToWrap: keyData
)

let mlKemKeyPair = try crypto.generateKemKeyPair(.mlKem768)

let sealed = try crypto.sealHpke(
    .dhkemX25519HkdfSha256HkdfSha256ChaCha20Poly1305,
    recipientPublicKey: recipientPublicKey,
    info: info,
    aad: aad,
    plaintext: plaintext
)
```

An explicitly empty provider context still fails closed with typed provider or
unsupported-algorithm errors for operations that require Rust. The lower-level
`rustCAbiLibrary:` overloads remain available for local development and tests
that deliberately want per-call provider control.

## Memory Hygiene

Rust-owned secret buffers are zeroized by the Rust implementation and FFI
adapters. Swift-managed arrays are best-effort only: ARC, framework providers,
protobuf codecs, debuggers, and crash reporters can create copies outside the
SDK's control. Clear caller-owned byte arrays as soon as practical:

```swift
ReallyMeCryptoMemory.bestEffortClear(&secretBytes)
```

Do not move private keys, passwords, plaintext, shared secrets, or derived keys
through strings or JSON paths.

## Test

```sh
swift test

cargo build -p crypto-ffi
REALLYME_CRYPTO_FFI_LIBRARY_PATH="$PWD/target/debug/libcrypto_ffi.dylib" swift test
```

Plain source-tree tests skip Rust ABI vectors unless the environment variable is
set. Release preflight builds `ReallyMeCryptoFFI.xcframework`, patches the
SwiftPM manifest, and reruns the Swift suite against the linked binary target so
the published package path is tested without `REALLYME_CRYPTO_FFI_LIBRARY_PATH`.

This package is the SDK API. The Swift conformance harness under
`crates/conformance/vectors/platform/swift` remains a test harness.
