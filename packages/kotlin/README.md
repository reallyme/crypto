<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

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
    implementation("me.really:crypto:0.3.0")
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
  post-quantum, and other explicitly declared routes.
- Bitcoin Core libsecp256k1 through ACINQ's pinned `secp256k1-kmp` JNI
  bindings for secp256k1 ECDSA and BIP-340 Schnorr.
- The ReallyMe Rust C ABI for primitives that should stay shared with Rust.

P-256, P-384, and P-521 base-point secret-scalar operations use
BouncyCastle's fixed-point comb multiplier to match the HPKE mitigation already
used in this package. Raw ECDH peer-point multiplication remains a
BouncyCastle-backed byte API until a reviewed Rust/native route is approved.
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
- secp256k1 ECDSA and BIP-340 Schnorr use libsecp256k1 through
  `secp256k1-kmp`; no secret-scalar elliptic-curve math is hand-rolled in
  Kotlin.
- secp256k1 ECDSA follows the workspace contract: SHA-256 prehash,
  deterministic nonces, low-S compact signatures, and compressed SEC1 public
  keys.
- ML-KEM, ML-DSA, SLH-DSA-SHA2-128s, HPKE, and X-Wing are covered by the same
  shared vectors as the Rust and TypeScript lanes.
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
contain its 16-byte tag.

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

Release and CI workflows run Gradle with strict dependency verification and
validate all checked-in Gradle wrapper jars before invoking `gradlew`.

The JVM package and Kotlin conformance lane intentionally use Gradle 9.6.1.
The Android package remains independently pinned to Gradle 8.14.4 because that
is the reviewed wrapper line for Android Gradle Plugin 8.13.0. Each lane pins
its distribution checksum, validates its wrapper jar, and uses strict
dependency verification; release readiness rejects unreviewed version or
checksum drift instead of treating the version difference as an implicit
shared version range.

## More Examples

```kotlin
val ed25519Signature = ReallyMeCrypto.sign(
    ReallyMeSignatureAlgorithm.ED25519,
    "message".toByteArray(),
    ed25519SecretKey,
)

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

## Publish

The build configures `maven-publish` with coordinates
`me.really:crypto`, a sources jar, a javadoc jar, Maven
Central-ready POM metadata, and optional PGP artifact signing.

Inspect the generated Maven repository locally:

```sh
cd packages/kotlin
./gradlew publishMavenPublicationToLocalReleaseRepository
```

Publish to a Maven-compatible remote repository by supplying repository and
signing secrets. The release workflow decides the repository URL; the package
does not hard-code Maven Central, GitHub Packages, or a staging endpoint.

This package is the SDK API. The Kotlin conformance harness under
`crates/conformance/platform/kotlin` remains a test harness.
