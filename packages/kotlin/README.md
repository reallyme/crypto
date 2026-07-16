<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# ReallyMeCrypto Kotlin

`me.really:crypto` is the Kotlin/JVM SDK for
[ReallyMe Crypto](https://github.com/reallyme/crypto).

ReallyMe Crypto provides a platform-agnostic cryptography API for Rust, Swift,
Kotlin, and TypeScript. Applications can implement cryptographic operations once
and rely on identical algorithms, key formats, and verification behavior across
servers, Apple platforms, Android, browsers, and WASM. On JVM, native
providers are used where appropriate, while shared conformance vectors ensure
byte-for-byte compatible behavior across every supported language.

JVM and Android are tracked as separate lanes in the provider matrix. Where the
two platforms' own providers disagree, the package pins one so both produce
identical output.

## Install

```kotlin
dependencies {
    implementation("me.really:crypto:0.2.0")
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

- JCA/JCE for JVM-native hashes and symmetric primitives.
- BouncyCastle, pinned to the version exercised by the Kotlin conformance lane,
  for deterministic NIST-curve, post-quantum, and compatibility behavior.
- Bitcoin Core libsecp256k1 through ACINQ's pinned `secp256k1-kmp` JNI
  bindings for secp256k1 ECDSA and BIP-340 Schnorr.
- The ReallyMe Rust C ABI for primitives that should stay shared with Rust.

The public API has two layers:

- algorithm-specific objects, such as `ReallyMeEd25519`, `ReallyMeX25519`,
  `ReallyMeP256Ecdh`, and `ReallyMeSecp256k1`;
- `ReallyMeCrypto`, a typed facade keyed by repository-wide algorithm enums.

Reserved identifiers, future contract entries, and unsupported overload shapes
throw `ReallyMeCryptoException.UnsupportedAlgorithm`. The Kotlin package does
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

Generated protobuf identifiers are included in the same artifact under
`me.really.crypto.v1`, with adapters in `me.really.crypto.proto`.

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

## Memory Hygiene

Rust-owned secret buffers are zeroized by the Rust implementation and JNI
adapters. JVM and Android byte arrays are best-effort only: runtimes, providers,
protobuf codecs, debuggers, and crash reporters can create copies outside the
SDK's control. Clear caller-owned byte arrays as soon as practical:

```kotlin
ReallyMeCryptoMemory.bestEffortClear(secretBytes)
```

Do not move private keys, passwords, plaintext, shared secrets, or derived keys
through strings or JSON paths.

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
`crates/conformance/vectors/platform/kotlin` remains a test harness.
