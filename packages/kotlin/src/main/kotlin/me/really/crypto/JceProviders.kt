// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import java.security.Provider
import java.security.Security
import java.security.Signature
import javax.crypto.Cipher
import org.bouncycastle.jce.provider.BouncyCastleProvider

private const val BOUNCY_CASTLE_PROVIDER_NAME = "BC"

internal object ReallyMeJceProviders {
    private val bouncyCastleProvider: Provider by lazy {
        val installed = Security.getProvider(BOUNCY_CASTLE_PROVIDER_NAME)
        if (installed != null) {
            installed
        } else {
            val provider = BouncyCastleProvider()
            Security.addProvider(provider)
            provider
        }
    }

    fun cipher(transformation: String): Cipher =
        try {
            Cipher.getInstance(transformation)
        } catch (_: java.security.GeneralSecurityException) {
            Cipher.getInstance(transformation, bouncyCastleProvider)
        }

    fun signature(algorithm: String): Signature =
        try {
            Signature.getInstance(algorithm)
        } catch (_: java.security.GeneralSecurityException) {
            Signature.getInstance(algorithm, bouncyCastleProvider)
        }
}
