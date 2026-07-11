// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

/** Providers compiled into the Kotlin package. */
public enum class ReallyMeCryptoProvider(public val providerName: String) {
    KOTLIN_JDK_STDLIB("Kotlin/JDK stdlib"),
    JCA_JCE("JCA/JCE"),
    BOUNCY_CASTLE("BouncyCastle"),
    LIBSECP256K1("Bitcoin Core libsecp256k1"),
    RUST_C_ABI("ReallyMe Rust C ABI"),
}

/**
 * Compile-time provider catalog used by package consumers and conformance
 * tests to assert that JVM crypto is backed by explicit provider packages.
 */
public object ReallyMeCryptoProviderCatalog {
    public val compiledProviders: List<ReallyMeCryptoProvider> = listOf(
        ReallyMeCryptoProvider.KOTLIN_JDK_STDLIB,
        ReallyMeCryptoProvider.JCA_JCE,
        ReallyMeCryptoProvider.BOUNCY_CASTLE,
        ReallyMeCryptoProvider.LIBSECP256K1,
        ReallyMeCryptoProvider.RUST_C_ABI,
    )
}
