# ReallyMeCrypto Kotlin

`me.really:crypto` is the Kotlin/JVM SDK for
[ReallyMe Crypto](https://github.com/reallyme/crypto). It combines JCA/JCE,
BouncyCastle, secp256k1 JNI, and explicit Rust JNI routes behind one typed
Kotlin facade.

## Install

```kotlin
dependencies {
    implementation("me.really:crypto:0.4.3")
}
```

Android consumers should use the separate `me.really:crypto-android` AAR from
`packages/kotlin-android`, which depends on `me.really:codec-android` and
packages the Rust provider under `jniLibs`. Both Maven artifacts publish the
same Gradle capability, `me.really:crypto`, so Gradle consumers that accidentally
include both artifacts get a dependency-resolution conflict instead of duplicate
`me.really.crypto` classes.

## Example

```kotlin
import me.really.crypto.ReallyMeCrypto
import me.really.crypto.ReallyMeHashAlgorithm
import me.really.crypto.ReallyMeMacAlgorithm

val digest = ReallyMeCrypto.hash(
    ReallyMeHashAlgorithm.SHA2_256,
    "abc".toByteArray(),
)

val tag = ReallyMeCrypto.authenticate(
    ReallyMeMacAlgorithm.HMAC_SHA256,
    key,
    "message".toByteArray(),
)
```

Signature verification throws on invalid signatures.

## Providers and encodings

Load Rust before using HPKE, post-quantum algorithms, Argon2id, software
P-curve ECDH or Rust-backed AEADs:

```kotlin
ReallyMeRustNativeProvider.loadBundledLibrary()
```

Missing Rust providers return typed `UnsupportedAlgorithm` or provider errors.
There is no BouncyCastle or Android Keystore fallback. Other routes use the
providers listed in [PROVIDER_POLICY.md](../../PROVIDER_POLICY.md): JCA/JCE
for SHA-2, HMAC and JWA Concat KDF; BouncyCastle for SHA-3, AES-GCM, AES-KW,
RSA verification and deterministic NIST ECDSA; libsecp256k1 JNI for secp256k1 and BIP-340.

- NIST ECDSA returns deterministic DER signatures. Verification requires
  canonical DER and standard compressed or uncompressed SEC1 public keys.
- `ReallyMeP256Ecdsa` normalizes canonical DER or 64-byte `r || s` to low-S
  for external-signing integrations.
- secp256k1 ECDSA uses a SHA-256 prehash, low-S compact signatures and compressed
  SEC1 public keys. BIP-340 has a separate method with explicit auxiliary bytes.
- ML-KEM, ML-DSA, SLH-DSA, X-Wing and HPKE execute through Rust JNI.
  Production packages do not expose seeded encapsulation.
- Invalid HPKE recipient/encapsulated keys return `InvalidInput`;
  authentication failures with otherwise valid keys return `AuthenticationFailed`.
- Recognizing a multicodec identifier does not enable its signing or KEM API.

Unspecified or wrong-family identifiers throw
`ReallyMeCryptoException.UnsupportedAlgorithm`.

## Protobuf

Generated structured operation messages and algorithm identifiers are included
in the same artifact under `me.really.crypto.v1`, with adapters in
`me.really.crypto.proto`.

```kotlin
import me.really.crypto.proto.ReallyMeCryptoProtoAdapters
import me.really.crypto.v1.HashAlgorithm

val facadeAlgorithm = ReallyMeCryptoProtoAdapters.fromProto(
    HashAlgorithm.HASH_ALGORITHM_SHA2_256,
)
val protoAlgorithm = ReallyMeCryptoProtoAdapters.toProto(facadeAlgorithm)
```

`UNSPECIFIED`, unrecognized values, and private multicodec identifiers throw
`ReallyMeCryptoException.UnsupportedAlgorithm`.

`ReallyMeCrypto.processOperationResponse(request)` accepts one generated binary
`CryptoOperationRequest`.
`ReallyMeCrypto.processOperationResponseJson(requestJson)` accepts the strict
generated ProtoJSON view only for non-secret hash, verification,
key-generation, encapsulation, and sender-export requests. Both return binary
`CryptoOperationResponse` bytes; operation failures remain inside the generated
response with their exact `CryptoError` branch and reason.

ProtoJSON is request-only. Secret-bearing operation selectors are rejected
before JSON value deserialization and must use protobuf bytes.

## Secret buffers

Rust owners clear their retained secret buffers. JVM/Android arrays can have
copies retained by the runtime, providers, codecs or debuggers. Clear keypair
secrets, shared secrets, plaintext and derived keys when no longer needed:

```kotlin
ReallyMeCryptoMemory.bestEffortClear(secretBytes)
```

Returned secret arrays are independently owned: clearing an input does not
clear the result or earlier runtime copies. Do not transport secrets as strings
or JSON.

KMAC keys and customization strings are limited to 4 KiB, contexts and outputs
to 64 KiB. Rust-backed AEAD plaintext/AAD, Argon2id secrets and protocol/PQ JNI
inputs are limited to one mebibyte; authenticated ciphertext permits its
additional 16-byte tag.

On desktop JVMs, `loadBundledLibrary()` extracts the native library into a
private temporary directory and checks its size and SHA-256 before loading.
The process needs a writable temporary location; loaded files may remain until
process exit. Android loads the AAR's packaged `jniLibs` instead.

Dependency verification metadata is committed in
`gradle/verification-metadata.xml`. Review downloaded artifacts before updating it:

```sh
./gradlew --write-verification-metadata sha256 help
```

The JVM package, Kotlin conformance lane, and Android package use Gradle 9.9.1.
The Android package uses Android Gradle Plugin 9.5.1 with built-in Kotlin.

## More Examples

```kotlin
val ed25519Signature = ReallyMeCrypto.sign(
    ReallyMeSignatureAlgorithm.ED25519,
    "message".toByteArray(),
    ed25519SecretKey,
)

ReallyMeRustNativeProvider.loadBundledLibrary()
val mlKemKeyPair = ReallyMeCrypto.generateKemKeyPair(ReallyMeKemAlgorithm.ML_KEM_768)
val mlKemEncapsulation = ReallyMeCrypto.encapsulate(
    ReallyMeKemAlgorithm.ML_KEM_768,
    mlKemKeyPair.publicKey,
)

val hpkeMessage = ReallyMeCrypto.sealHpke(
    ReallyMeHpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305,
    recipientPublicKey,
    info,
    aad,
    plaintext,
)
```

## Test

```sh
cd packages/kotlin
./gradlew test
```

Protocol KATs run in an isolated JVM against a conformance-only Rust library.
To select protocol cases, use `./gradlew testRustProtocols --tests '...pattern...'`.
For focused production-facade tests, use
`./gradlew test --tests '...pattern...' -x testRustProtocols`.
The unfiltered `test` task includes both production and conformance coverage.

## Package

The published `me.really:crypto` artifact includes a sources jar, a javadoc
jar, and Maven POM metadata.
