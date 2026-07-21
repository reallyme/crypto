# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: Apache-2.0

# BouncyCastle registers many JCA/JCE SPI implementations by class name.
# Consumers that minify with R8 full mode must not strip the provider classes
# used by the pinned ReallyMe Kotlin/Android provider route.
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# Protobuf javalite messages are generated into the ReallyMe namespace and are
# consumed across the lossless wire layer. Keep this package's generated message
# implementations without pinning a consuming application's unrelated protos.
-keep class me.really.crypto.** extends com.google.protobuf.GeneratedMessageLite { *; }
-keepclassmembers class me.really.crypto.** extends com.google.protobuf.GeneratedMessageLite { *; }

# Keep JNI entry point holders and native method names stable for the Android
# System.loadLibrary path.
-keepclasseswithmembernames class me.really.crypto.** {
    native <methods>;
}
-keep class me.really.crypto.ReallyMeRustNativeProvider { *; }
-keep class me.really.crypto.ReallyMeRustAead { *; }
-keep class me.really.crypto.ReallyMeArgon2id { *; }

# JNI constructs this typed failure by its binary class name if no Java
# exception is already pending. Keep the class and no-argument constructor.
-keep class me.really.crypto.ReallyMeCryptoException$ProviderFailure { *; }
