# ReallyMeCrypto Kotlin

`me.really:crypto` is the Kotlin/JVM SDK for
[ReallyMe Crypto](https://github.com/reallyme/crypto). It combines JCA/JCE,
BouncyCastle, secp256k1 JNI, and explicit Rust JNI routes behind one typed
Kotlin facade.

The package shares algorithm identifiers, byte formats, typed failures, and
conformance vectors with the Rust, Swift, Android, and TypeScript SDKs.
Availability is provider-specific; unsupported routes fail closed.

JVM and Android are tracked as separate lanes in the provider matrix. Where the
two platforms' own providers disagree, the package pins one so both produce
identical output.

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

## Quick Start

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

Signature verification throws on invalid signatures. It does not return a
boolean that can be accidentally ignored.

## Provider Model

Provider selection is explicit:

- JCA/JCE for the manifest-declared JVM-native hash, HMAC, and JWA Concat KDF
  routes.
- BouncyCastle, pinned to the version exercised by the Kotlin conformance lane,
  for AES-GCM, AES-KW, RSA verification, deterministic NIST-curve,
  and other explicitly declared classical primitive routes.
- Bitcoin Core libsecp256k1 through ACINQ's pinned `secp256k1-kmp` JNI
  bindings for secp256k1 ECDSA and BIP-340 Schnorr.
- ReallyMe Rust through JNI for ML-KEM, ML-DSA, SLH-DSA, X-Wing, HPKE,
  software P-256/P-384/P-521 ECDH, Argon2id, and the Rust-backed AEADs. Load `ReallyMeRustNativeProvider`
  explicitly before using these routes. Missing protocol/PQ and P-curve ECDH providers fail with
  typed `UnsupportedAlgorithm`; there is no BouncyCastle fallback.

Software P-curve ECDH key generation, public-key derivation, and agreement
execute in Rust with constant-time curve arithmetic. ECDSA remains the explicit
BouncyCastle deterministic-signature route; verification requires canonical
DER and standard compressed or uncompressed SEC1 keys. HPKE executes in Rust.
Android Keystore and StrongBox are not fallback providers for these raw-byte
routes.

The public API has two layers:

- algorithm-specific objects, such as `ReallyMeEd25519`, `ReallyMeX25519`,
  `ReallyMeP256Ecdh`, and `ReallyMeSecp256k1`;
- `ReallyMeCrypto`, a typed facade keyed by repository-wide algorithm enums.

Unspecified identifiers and algorithm/operation combinations that a method
does not define throw `ReallyMeCryptoException.UnsupportedAlgorithm`. The Kotlin package does
not silently fall back to a different provider. The complete JVM and Android
lanes are tracked in [PROVIDER_POLICY.md](../../PROVIDER_POLICY.md).

## Algorithms

- Ed25519 uses plain deterministic Ed25519 over the full message.
- P-256 ECDSA uses deterministic DER/SHA-256 signatures through BouncyCastle so
  it matches the shared vectors.
- `ReallyMeP256Ecdsa` exposes strict low-S normalization for canonical DER and
  fixed-width 64-byte `r || s` signatures returned by external signers.
- secp256k1 ECDSA and BIP-340 Schnorr use libsecp256k1 through
  `secp256k1-kmp`; no secret-scalar elliptic-curve math is hand-rolled in
  Kotlin.
- secp256k1 ECDSA follows the workspace contract: SHA-256 prehash,
  deterministic nonces, low-S compact signatures, and compressed SEC1 public
  keys.
- ML-KEM, ML-DSA, SLH-DSA-SHA2-128s, HPKE, and X-Wing are covered by the same
  shared vectors as the Rust and TypeScript lanes. Their JNI adapters preserve
  the public API while Rust owns key generation, signing, KEMs, and HPKE.
  Chosen-randomness helpers exist only in test sources and require a separately
  built native library with `test-vectors`. The production Kotlin JAR has no
  seeded encapsulation API, and production native libraries omit those symbols.
  HPKE rejects low-order recipient and encapsulated keys with `InvalidInput`
  across sealing, opening, and PSK context setup, matching the Rust core's
  key-validation errors. Authentication failures with otherwise valid keys
  return `AuthenticationFailed`.
- Multicodec and multikey support is scoped to public-key metadata. It does not
  imply support for the corresponding signing or KEM primitive.

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
response with their exact `CryptoError` branch and reason. This is the single
executable structured response contract.

ProtoJSON is request-only. Secret-bearing operation selectors are rejected
before JSON value deserialization and must use protobuf bytes. Clear
caller-owned arrays after processing because JVM and Android runtimes cannot
guarantee removal of managed copies.

## Memory Hygiene

Rust-owned secret buffers are zeroized by the Rust implementation and JNI
adapters. JVM and Android byte arrays are best-effort only: runtimes, providers,
protobuf codecs, debuggers, and crash reporters can create copies outside the
SDK's control. Clear caller-owned byte arrays as soon as practical:

AES-KW is bound directly to the bundled BouncyCastle provider and rejects
results that do not have the exact RFC 3394 `plaintext + 8` or `wrapped - 8`
length. KMAC JNI copies of the key, context, customization, and output are
zeroized on native exit. KMAC keys and customization strings are capped at
4 KiB, contexts at 64 KiB, and outputs at 64 KiB before native allocation.
Rust-backed AEAD plaintext and AAD, plus Argon2id secrets, are capped at one
mebibyte before JNI copies are created. Authenticated AEAD ciphertext may also
contain its 16-byte tag. Protocol and post-quantum JNI inputs are
also capped at one mebibyte before copying; HPKE ciphertext permits the
additional 16-byte authentication tag. Temporary native copies and Kotlin
transport envelopes are wiped on both successful and failed operations.

```kotlin
ReallyMeCryptoMemory.bestEffortClear(secretBytes)
```

Do not move private keys, passwords, plaintext, shared secrets, or derived keys
through strings or JSON paths.

Secret-bearing result classes expose caller-owned `ByteArray` values. Generated
and derived keypair methods return independent secret arrays; wiping the input
does not wipe the returned keypair, and wiping the returned keypair does not
wipe earlier provider or runtime copies. Encapsulation results and native
operation results that contain plaintext, shared secrets, or derived keys must
be cleared by the caller when no longer needed.

On desktop JVMs, `ReallyMeRustNativeProvider.loadBundledLibrary()` extracts the
classpath native library into a private temporary directory, verifies the
manifest SHA-256 and size in memory, writes and forces the file to disk, then
re-hashes the on-disk file immediately before `System.load`. If extraction or
re-verification fails, the provider fails closed with a typed provider failure.
Successfully loaded native libraries can leave crash residue in the private
temporary directory because some JVMs and operating systems require the loaded
file to remain addressable for the process lifetime. Android uses
`System.loadLibrary` from package-managed `jniLibs` instead of this classpath
extraction path.

Dependency verification metadata is committed in
`gradle/verification-metadata.xml`. Regenerate it only as a reviewed
supply-chain event:

```sh
./gradlew --write-verification-metadata sha256 help
```

Gradle builds use strict dependency verification and validate the checked-in
wrapper jars.

The JVM package, Kotlin conformance lane, and Android package use Gradle 9.9.1.
The Android package uses Android Gradle Plugin 9.5.1 with built-in Kotlin. Each
lane pins its distribution checksum, validates its wrapper jar, and uses strict
dependency verification.

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

This package is the SDK API. The Kotlin conformance harness under
`crates/conformance/platform/kotlin` remains a test harness.
