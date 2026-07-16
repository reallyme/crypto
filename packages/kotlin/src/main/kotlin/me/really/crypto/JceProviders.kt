// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import java.security.Provider
import java.security.Signature
import javax.crypto.Cipher
import org.bouncycastle.jce.provider.BouncyCastleProvider

private const val BOUNCY_CASTLE_PROVIDER_NAME = "BC"

internal object ReallyMeJceProviders {
    private val bouncyCastleProvider: Provider by lazy { BouncyCastleProvider() }

    fun cipher(transformation: String): Cipher =
        try {
            Cipher.getInstance(transformation).takeUnless { usesUnapprovedBouncyCastle(it.provider) }
                ?: Cipher.getInstance(transformation, bouncyCastleProvider)
        } catch (_: java.security.GeneralSecurityException) {
            Cipher.getInstance(transformation, bouncyCastleProvider)
        }

    fun cipherProviderName(transformation: String): String =
        cipher(transformation).provider.name

    fun bouncyCastleCipher(transformation: String): Cipher =
        Cipher.getInstance(transformation, bouncyCastleProvider)

    fun signature(algorithm: String): Signature =
        try {
            Signature.getInstance(algorithm).takeUnless { usesUnapprovedBouncyCastle(it.provider) }
                ?: Signature.getInstance(algorithm, bouncyCastleProvider)
        } catch (_: java.security.GeneralSecurityException) {
            Signature.getInstance(algorithm, bouncyCastleProvider)
        }

    fun signatureProviderName(algorithm: String): String =
        signature(algorithm).provider.name

    fun isBundledBouncyCastleProvider(provider: Provider): Boolean =
        provider === bouncyCastleProvider

    private fun usesUnapprovedBouncyCastle(provider: Provider): Boolean =
        provider.name == BOUNCY_CASTLE_PROVIDER_NAME && provider !== bouncyCastleProvider
}
