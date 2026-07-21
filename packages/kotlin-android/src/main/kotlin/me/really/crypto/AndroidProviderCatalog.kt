// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

/** Hardware providers that exist only in the Android AAR runtime lane. */
public enum class ReallyMeAndroidCryptoProvider(public val providerName: String) {
    ANDROID_KEYSTORE("Android Keystore"),
    STRONGBOX("StrongBox"),
}

/** Explicit Android-only complement to the shared Kotlin provider catalog. */
public object ReallyMeAndroidCryptoProviderCatalog {
    public val compiledHardwareProviders: List<ReallyMeAndroidCryptoProvider> = listOf(
        ReallyMeAndroidCryptoProvider.ANDROID_KEYSTORE,
        ReallyMeAndroidCryptoProvider.STRONGBOX,
    )
}
