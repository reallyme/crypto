# ReallyMeCrypto Swift

`ReallyMeCrypto` is the Apple-platform SDK for
[ReallyMe Crypto](https://github.com/reallyme/crypto). It combines native Apple
providers with explicit Rust C ABI routes behind one typed Swift facade.

## Install

```swift
.package(
    url: "https://github.com/reallyme/crypto",
    from: "0.4.3"
)
```

```swift
.product(name: "ReallyMeCrypto", package: "crypto")
```

Requires Swift 6.3 or later.

Applications that process structured operations or store ReallyMe Crypto
algorithm identifiers can add the proto products at the same boundary:

```swift
.product(name: "ReallyMeCryptoProto", package: "crypto")
.product(name: "ReallyMeCryptoProtoAdapters", package: "crypto")
```

## Example

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

Signature verification throws on invalid signatures.

## Providers

Released packages link the Rust C ABI provider. Use `ReallyMeCrypto()` for its
configured routes; algorithm-specific types expose the lower-level APIs.
[PROVIDER_POLICY.md](../../PROVIDER_POLICY.md) lists supported algorithms and
providers. Unspecified identifiers or unsupported combinations throw
`ReallyMeCryptoError.unsupportedAlgorithm`; provider failures do not trigger
fallback.

`ReallyMeP256EcdsaSignature` normalizes canonical DER or 64-byte `r || s`
signatures to low-S. Secure Enclave signing applies normalization automatically;
external HSM integrations can call it explicitly.

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

Store the returned handle; raw application tags are not lookup handles.

Secure Enclave ECDH keys use non-interactive `.privateKeyUsage`
access control so background receive/decryption flows can derive shared
secrets. Secure Enclave residency prevents private-key export; it does not add
per-operation user-presence or biometric authorization. Applications that
require an interactive policy must enforce that policy before invoking ECDH.

## Secure Enclave Signing

Use the handle-backed P-256 signing API when a user-presence or biometric-gated
device key should sign a challenge without exporting the private key. Hardware
signing does not reproduce deterministic software-signing bytes.

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
the Rust provider automatically. The instance facade returns compressed SEC1
public keys and deterministic DER ECDSA signatures:

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

ProtoJSON is request-only. Secret-bearing operation selectors are rejected
before JSON value deserialization and must use protobuf bytes.

## Secret buffers

Rust owners clear their retained secret buffers. Swift arrays can have copies
retained by ARC, providers, codecs or debuggers; clearing one array does not
clear those copies. Clear caller-owned arrays when no longer needed:

```swift
ReallyMeCryptoMemory.bestEffortClear(&secretBytes)
```

KMAC keys and customization strings are capped at 4 KiB, contexts and outputs
at 64 KiB. Do not transport private keys, passwords, plaintext, shared secrets
or derived keys as strings or JSON.

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

Plain `swift test` uses the binary target selected by the root manifest,
including its checksum validation, and tests the linked Rust ABI. For changes
to local Rust sources, use the runtime override above to test the newly built
library. Hardware-dependent tests may skip when their requirements are absent.
The SwiftPM runtime-FFI override is development-only and requires both
`REALLYME_CRYPTO_SWIFTPM_RUNTIME_FFI=1` and the repo-local
`.reallyme-crypto-runtime-ffi` marker; the environment variable alone is ignored
so normal consumers keep the reviewed binary target.
