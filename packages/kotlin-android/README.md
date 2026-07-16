<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# ReallyMe Crypto Android

Android AAR packaging for the ReallyMe Crypto Kotlin facade.

The package reuses the audited Kotlin facade sources from `packages/kotlin`,
depends on the published `me.really:codec-android:0.1.21` artifact, and bundles
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
the compatibility boundary for app developers; local source builds should use
the same Android SDK/NDK versions as CI.

The packaged `assets/reallyme-crypto/native-manifest.json` is a release and
external-verification artifact for the bundled JNI libraries. Android runtime
loading still uses `System.loadLibrary("crypto_ffi")` from the app's signed
native library locations; it does not parse the manifest at runtime.

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
  bundleReleaseAar \
  verifyReleaseAarContainsJniLibs \
  -Preallyme.crypto.androidJniLibsDir="$PWD/build/android-jniLibs" \
  -Preallyme.crypto.androidNativeAssetsDir="$PWD/build/android-native-assets" \
  -Preallyme.crypto.requireAndroidJniLibs=true
```

The release workflow uses the same staging model before publishing. This keeps
generated native libraries out of source control while ensuring the published
AAR contains every required JNI library and the native checksum manifest.
