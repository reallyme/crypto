// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import java.security.KeyFactory
import java.security.Provider
import java.security.Signature
import javax.crypto.Cipher
import org.bouncycastle.jce.provider.BouncyCastleProvider

internal object ReallyMeJceProviders {
    private val bouncyCastleProvider: Provider by lazy { BouncyCastleProvider() }

    fun bouncyCastleCipher(transformation: String): Cipher =
        Cipher.getInstance(transformation, bouncyCastleProvider)

    fun bouncyCastleKeyFactory(algorithm: String): KeyFactory =
        KeyFactory.getInstance(algorithm, bouncyCastleProvider)

    fun bouncyCastleSignature(algorithm: String): Signature =
        Signature.getInstance(algorithm, bouncyCastleProvider)

    fun isBundledBouncyCastleProvider(provider: Provider): Boolean =
        provider === bouncyCastleProvider
}
