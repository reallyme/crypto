# ReallyMe Crypto Android

`me.really:crypto-android` is the Android AAR for the ReallyMe Crypto Kotlin
facade. It packages the Android provider routes and the Rust JNI
libraries required by Rust-backed routes.

## Install

```kotlin
dependencies {
    implementation("me.really:crypto-android:0.4.3")
}
```

The package reuses the Kotlin facade sources from `packages/kotlin`,
requires `me.really:codec-android:0.4.4`, and bundles
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
Gradle Plugin 9.5.1 and Java 21, consuming builds need a toolchain that can
compile against `compileSdk = 37` and Java 21 bytecode. The release artifact is
the supported consumption boundary for app developers; local source builds should use
the same Android SDK/NDK versions as CI.

The packaged `assets/reallyme-crypto/native-manifest.json` is a release and
external-verification artifact for the bundled JNI libraries. Android runtime
loading still uses `System.loadLibrary("crypto_ffi")` from the app's signed
native library locations; it does not parse the manifest at runtime.

Release packaging checks 16 KiB ELF segment alignment for the 64-bit JNI
libraries and checksums all four ABIs.

## Android Keystore and StrongBox

The Android AAR exposes non-exportable P-256 signing and ECDH keys through
`ReallyMeAndroidPlatformKeys`. This handle-backed API is separate from the
raw-byte facade: software P-256 signing uses BouncyCastle and software ECDH
uses Rust JNI. Neither falls back to Android Keystore.

Platform signing returns canonical low-S DER. When an initialized signing
operation is completed outside the SDK—for example through a biometric
`CryptoObject`—pass its result to
`ReallyMeAndroidPlatformKeys.normalizeSigningResult`.

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

The platform-key API requires Android API 31. A StrongBox request is strict and never
downgrades to TEE. Software-backed or indeterminate-security-level keys are
rejected. Other AAR cryptography remains available from `minSdk` 26.

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
revocation state.

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

Native libraries are stripped before their checksums are recorded. AAR
verification recomputes each packaged size and SHA-256 against the manifest.

Dependency verification metadata is committed in
`gradle/verification-metadata.xml`. Regenerate it only as a reviewed Android
supply-chain event:

```sh
packages/kotlin-android/gradlew -p packages/kotlin-android \
  --write-verification-metadata sha256 help
```
