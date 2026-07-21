<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# ReallyMeCrypto Swift

`ReallyMeCrypto` is the Apple-platform SDK for
[ReallyMe Crypto](https://github.com/reallyme/crypto). It combines native Apple
providers with explicit Rust C ABI routes behind one typed Swift facade.

The package shares algorithm identifiers, byte formats, typed failures, and
conformance vectors with the Rust, Kotlin, Android, and TypeScript SDKs.
Availability is provider-specific; unsupported routes fail closed.

The manifest sits at the repository root (`Package.swift`) so SwiftPM can add it
by Git URL; the source lives under `packages/swift` with the other language SDKs.

## Install

```swift
.package(
    url: "https://github.com/reallyme/crypto",
    from: "0.3.0"
)
```

```swift
.product(name: "ReallyMeCrypto", package: "crypto")
```

The `from:` version resolves after publication. The verified Swift package
release workflow creates the corresponding immutable `v<version>` tag together
with the XCFramework-backed GitHub release; an unreleased version has no tag.

Applications that process structured operations or store ReallyMe Crypto
algorithm identifiers can add the proto products at the same boundary:

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
- Security.framework / Secure Enclave for P-256 ECDH and P-256 ECDSA signing
  keys that must stay non-exportable.
- [reallyme/CSecp256k1](https://github.com/reallyme/CSecp256k1) for
  secp256k1 ECDSA, since CryptoKit does not provide secp256k1.
- Digest for SHA-3, which CryptoKit does not expose.
- The ReallyMe Rust C ABI for primitives that should stay shared with Rust,
  including deterministic Ed25519 and P-256/P-384/P-521 ECDSA signing,
  ML-KEM, ML-DSA, SLH-DSA, X-Wing, Argon2id, AES-KW, HPKE, and RSA
  verification.

The public API has two layers:

- algorithm-specific types, such as `ReallyMeX25519`, `ReallyMeP256Ecdh`, and
  `ReallyMeSecp256k1`;
- `ReallyMeCrypto`, a typed facade keyed by repository-wide algorithm enums.

Unspecified identifiers and algorithm/operation combinations that a method
does not define throw `ReallyMeCryptoError.unsupportedAlgorithm`. The Swift package does not
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

Application tags are unique key identifiers. Generation with an existing tag
fails as `ReallyMeCryptoError.invalidInput` unless `overwriteExisting` is true;
delete remains idempotent for missing keys.

Secure Enclave storage identifiers are purpose-separated hashes. Public handles
remain opaque facade values and resolve only the current storage identifier;
raw application tags are deliberately not lookup handles.

Secure Enclave ECDH keys deliberately use non-interactive `.privateKeyUsage`
access control so background receive/decryption flows can derive shared
secrets. Secure Enclave residency prevents private-key export; it does not add
per-operation user-presence or biometric authorization. Applications that
require an interactive policy must enforce that policy before invoking ECDH.

## Secure Enclave Signing

Use the handle-backed P-256 signing API when a user-presence or biometric-gated
device key should sign a challenge without exporting the private key. This is a
Security.framework / Secure Enclave route, not the Rust deterministic ECDSA
route used for cross-lane raw-key vectors.

```swift
let tag = Array("me.really.example.p256.signing".utf8)
let keyPair = try ReallyMeCrypto.generateSecureEnclaveSigningKeyPair(
    .ecdsaP256Sha256,
    tag: tag,
    accessControl: .userPresence,
    overwriteExisting: false
)

let signatureDer = try ReallyMeCrypto.signWithPrivateKeyHandle(
    .ecdsaP256Sha256,
    message: challenge,
    privateKeyHandle: keyPair.privateKeyHandle,
    authenticationPrompt: "Confirm signing"
)

try ReallyMeCrypto.verifySecureEnclaveSignature(
    .ecdsaP256Sha256,
    signature: signatureDer,
    message: challenge,
    publicKey: keyPair.publicKey
)
```

`ReallyMeSecureEnclaveAccessControl.userPresence` allows the platform to use
Touch ID, Face ID, or passcode according to device policy. The stricter
`.biometryAny` and `.biometryCurrentSet` policies are also available when an
application must require biometrics specifically.

Signing tags follow the same uniqueness rule as ECDH tags: duplicate generation
fails closed unless `overwriteExisting` is true, and delete is idempotent.

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
bundled Rust provider for Rust-backed primitives such as deterministic
P-256/P-384/P-521 ECDSA, Ed25519, ML-KEM, ML-DSA, SLH-DSA, X-Wing, Argon2id,
AES-KW, HPKE, and RSA verification.

Deterministic ECDSA signing is intentionally provider-aware on Swift. Use the
instance facade, or the explicit `rustCAbiLibrary:` overloads in tests and local
provider development. The ECDSA contract returns SEC1 compressed public keys and
DER signatures:

```swift
let crypto = ReallyMeCrypto()
let keyPair = try crypto.generateKeyPair(.ecdsaP256Sha256)
let signatureDer = try crypto.sign(
    .ecdsaP256Sha256,
    message: message,
    secretKey: keyPair.secretKey
)
try crypto.verify(
    .ecdsaP256Sha256,
    signature: signatureDer,
    message: message,
    publicKey: keyPair.publicKey
)
```

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

`ReallyMeCrypto.processOperationResponse(_:)` accepts one generated binary
`CryptoOperationRequest`. `ReallyMeCrypto.processOperationResponseJson(_:)`
accepts the strict generated ProtoJSON view only for non-secret hash,
verification, key-generation, encapsulation, and sender-export requests. Both return
binary `CryptoOperationResponse` bytes, preserving exact `CryptoError` branches
and reasons rather than projecting operation failures into Swift errors.
This is the single executable structured response contract.

ProtoJSON is request-only. Secret-bearing operation selectors are rejected
before JSON value deserialization and must use protobuf bytes. Clear
caller-owned arrays after processing because Swift cannot guarantee removal of
ARC or framework-created copies.

## Memory Hygiene

Rust-owned secret buffers are zeroized by the Rust implementation and FFI
adapters. Swift-managed arrays are best-effort only: ARC, framework providers,
protobuf codecs, debuggers, and crash reporters can create copies outside the
SDK's control. Clear caller-owned byte arrays as soon as practical:

The AES-KW adapter rejects any Rust provider result whose produced length is not
exactly the RFC 3394 `plaintext + 8` or `wrapped - 8` length. Temporary native
unwrapped-key and derived-key owners are zeroized after copying into
Swift-managed arrays. KMAC keys and customization strings are capped at 4 KiB,
contexts at 64 KiB, and outputs at 64 KiB before crossing the C ABI.

```swift
ReallyMeCryptoMemory.bestEffortClear(&secretBytes)
```

Do not move private keys, passwords, plaintext, shared secrets, or derived keys
through strings or JSON paths.

## Test

```sh
swift test

cargo build -p crypto-ffi
touch .reallyme-crypto-runtime-ffi
REALLYME_CRYPTO_FFI_LIBRARY_PATH="$PWD/target/debug/libcrypto_ffi.dylib" \
  REALLYME_CRYPTO_SWIFTPM_RUNTIME_FFI=1 \
  swift test
rm .reallyme-crypto-runtime-ffi
```

Plain source-tree tests skip Rust ABI vectors unless the runtime library path is
set. The SwiftPM runtime-FFI override is development-only and requires both
`REALLYME_CRYPTO_SWIFTPM_RUNTIME_FFI=1` and the repo-local
`.reallyme-crypto-runtime-ffi` marker; the environment variable alone is ignored
so normal consumers keep the reviewed binary target. Release preflight builds
`ReallyMeCryptoFFI.xcframework`, patches the SwiftPM manifest, and reruns the
Swift suite against the linked binary target so the published package path is
tested without `REALLYME_CRYPTO_FFI_LIBRARY_PATH`.

This package is the SDK API. The Swift conformance harness under
`crates/conformance/platform/swift` remains a test harness.
