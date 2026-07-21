<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# ReallyMe Crypto Android

`me.really:crypto-android` is the Android AAR for the ReallyMe Crypto Kotlin
facade. It packages the validated Android provider graph and the Rust JNI
libraries required by Rust-backed routes.

## Install

```kotlin
dependencies {
    implementation("me.really:crypto-android:0.3.0")
}
```

The package reuses the audited Kotlin facade sources from `packages/kotlin`,
depends on the published `me.really:codec-android:0.2.0` artifact, and bundles
`libcrypto_ffi.so` for the standard Android ABIs:

- `arm64-v8a`
- `armeabi-v7a`
- `x86`
- `x86_64`

Consumers should load the bundled Rust provider explicitly before using
Rust-backed algorithms:

```kotlin
ReallyMeRustNativeProvider.loadBundledLibrary()
```

The AAR declares `minSdk = 26`. `compileSdk` is a build-time API level and does
not limit newer Android runtimes. Because the package is built with Android
Gradle Plugin 8.13.0 and Java 21, consuming builds need a toolchain that can
compile against `compileSdk = 36` and Java 21 bytecode. The release artifact is
the supported consumption boundary for app developers; local source builds should use
the same Android SDK/NDK versions as CI.

The packaged `assets/reallyme-crypto/native-manifest.json` is a release and
external-verification artifact for the bundled JNI libraries. Android runtime
loading still uses `System.loadLibrary("crypto_ffi")` from the app's signed
native library locations; it does not parse the manifest at runtime.

Release packaging verifies that `arm64-v8a` and `x86_64` JNI libraries have
16 KiB-compatible ELF `LOAD` segment alignment. The 32-bit `armeabi-v7a` and
`x86` libraries are still required and checksummed, but they are intentionally
not held to the 64-bit page-size rule. The native rebuild scripts pass the
64-bit linker max-page-size flag explicitly and print the selected NDK and
effective Rust flags.

## Android Keystore and StrongBox

The Android AAR exposes non-exportable P-256 signing and ECDH keys through
`ReallyMeAndroidPlatformKeys`. This handle-backed API is separate from the
deterministic raw-byte facade: raw P-256 operations remain BouncyCastle routes
and never silently fall back to Android Keystore.

```kotlin
val keyPair = ReallyMeAndroidPlatformKeys.generateSigningKeyPair(
    applicationTag = "com.example.identity.signing".toByteArray(),
    policy = ReallyMeAndroidPlatformKeyPolicy(
        requestedSecurityLevel =
            ReallyMeAndroidPlatformKeySecurityLevel.TRUSTED_ENVIRONMENT,
    ),
)

val signature = ReallyMeAndroidPlatformKeys.sign(message, keyPair.privateKeyHandle)
ReallyMeAndroidPlatformKeys.verify(signature, message, keyPair.publicKey)
ReallyMeAndroidPlatformKeys.deleteKey(keyPair.privateKeyHandle)
```

Application-tag bytes are bounded, domain-separated, and hashed before they
become a purpose-specific Keystore alias. Handles do not contain the raw tag.
Generation verifies non-exportability, key purpose, origin, size, and actual
hardware security level through `KeyInfo`; software-backed keys are deleted and
reported as `HardwareUnavailable`. A StrongBox request is strict and never
downgrades to TEE. The complete platform-key API requires Android API 31 so
every signing and ECDH operation can authenticate exact TEE or StrongBox
residency through `KeyInfo`; `PURPOSE_AGREE_KEY` also begins there. Other AAR
cryptography remains available from the package's declared `minSdk` of 26.

Policies can require biometric or device-credential authentication, an unlocked
device, user confirmation, and a generation-time attestation challenge. For
per-use biometric flows, wrap `newSigningOperation` or
`newKeyAgreementOperation` in the application's biometric prompt CryptoObject.
Attestation challenges must be fresh caller-generated nonces of 16 through 128
bytes. Biometric-enrollment invalidation is accepted only for per-operation,
biometric-only keys because other Android policy combinations do not enforce
that property.
`attest` returns the certificate chain; the relying party remains responsible
for validating the challenge, authorization extension, trusted root, and
revocation state. Errors are typed and contain no aliases, tags, handles,
prompts, certificates, or provider exception text.

The local JNI build script is a Bash wrapper around the repository-level Android
native resource builder and is intended for macOS/Linux CI or a Unix-like shell.
Windows consumers should use the published AAR rather than rebuilding the native
libraries locally.

Use `me.really:crypto-android`, not `me.really:crypto`, for Android
applications. Both artifacts publish the same Gradle capability,
`me.really:crypto`, so Gradle consumers that accidentally include both get a
dependency-resolution conflict instead of duplicate `me.really.crypto` classes.

Build the release AAR with a locally staged JNI directory:

```sh
scripts/build_android_native_resources.sh build/android-jniLibs
node scripts/write_native_manifest.mjs \
  build/android-jniLibs \
  build/android-native-assets/reallyme-crypto/native-manifest.json
packages/kotlin-android/gradlew -p packages/kotlin-android \
  verifyAndroidJniLibs \
  bundleReleaseAar \
  verifyReleaseAarContainsJniLibs \
  -Preallyme.crypto.androidJniLibsDir="$PWD/build/android-jniLibs" \
  -Preallyme.crypto.androidNativeAssetsDir="$PWD/build/android-native-assets" \
  -Preallyme.crypto.requireAndroidJniLibs=true
```

The release workflow uses the same staging model before publishing. Native
libraries are stripped before their checksums are recorded, and AAR verification
recomputes each packaged size and SHA-256 against the manifest. This keeps
generated native libraries out of source control while binding every approved
ABI payload to the reviewed source commit.

Dependency verification metadata is committed in
`gradle/verification-metadata.xml`. Regenerate it only as a reviewed Android
supply-chain event:

```sh
packages/kotlin-android/gradlew -p packages/kotlin-android \
  --write-verification-metadata sha256 help
```
