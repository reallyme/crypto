// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import java.security.GeneralSecurityException
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES-GCM backed by the platform JCA/JCE provider, with the pinned
 * BouncyCastle provider as the explicit fallback for Android/JVM variance.
 *
 * The package contract keeps the 96-bit nonce separate and returns
 * `ciphertext || tag`, matching the Rust, Swift, and TypeScript vectors.
 */
public object ReallyMeAesGcm {
    public const val AES_128_KEY_LENGTH: Int = 16
    public const val AES_192_KEY_LENGTH: Int = 24
    public const val AES_256_KEY_LENGTH: Int = 32
    public const val KEY_LENGTH: Int = AES_256_KEY_LENGTH
    public const val NONCE_LENGTH: Int = 12
    public const val TAG_LENGTH: Int = 16

    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val KEY_ALGORITHM = "AES"
    private const val TAG_LENGTH_BITS = TAG_LENGTH * 8

    public fun sealAes128Gcm(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
    ): ByteArray = sealWithKeyLength(key, AES_128_KEY_LENGTH, nonce, aad, plaintext)

    public fun sealAes192Gcm(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
    ): ByteArray = sealWithKeyLength(key, AES_192_KEY_LENGTH, nonce, aad, plaintext)

    public fun seal(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
    ): ByteArray = sealWithKeyLength(key, AES_256_KEY_LENGTH, nonce, aad, plaintext)

    public fun openAes128Gcm(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        ciphertextWithTag: ByteArray,
    ): ByteArray = openWithKeyLength(key, AES_128_KEY_LENGTH, nonce, aad, ciphertextWithTag)

    public fun openAes192Gcm(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        ciphertextWithTag: ByteArray,
    ): ByteArray = openWithKeyLength(key, AES_192_KEY_LENGTH, nonce, aad, ciphertextWithTag)

    public fun open(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        ciphertextWithTag: ByteArray,
    ): ByteArray = openWithKeyLength(key, AES_256_KEY_LENGTH, nonce, aad, ciphertextWithTag)

    private fun sealWithKeyLength(
        key: ByteArray,
        expectedKeyLength: Int,
        nonce: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
    ): ByteArray {
        validateKeyAndNonce(key, expectedKeyLength, nonce)
        return try {
            val cipher = ReallyMeJceProviders.cipher(TRANSFORMATION)
            cipher.init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(key, KEY_ALGORITHM),
                GCMParameterSpec(TAG_LENGTH_BITS, nonce),
            )
            cipher.updateAAD(aad)
            cipher.doFinal(plaintext)
        } catch (_: GeneralSecurityException) {
            throw ReallyMeCryptoException.ProviderFailure()
        }
    }

    private fun openWithKeyLength(
        key: ByteArray,
        expectedKeyLength: Int,
        nonce: ByteArray,
        aad: ByteArray,
        ciphertextWithTag: ByteArray,
    ): ByteArray {
        validateKeyAndNonce(key, expectedKeyLength, nonce)
        if (ciphertextWithTag.size < TAG_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }

        return try {
            val cipher = ReallyMeJceProviders.cipher(TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(key, KEY_ALGORITHM),
                GCMParameterSpec(TAG_LENGTH_BITS, nonce),
            )
            cipher.updateAAD(aad)
            cipher.doFinal(ciphertextWithTag)
        } catch (_: AEADBadTagException) {
            throw ReallyMeCryptoException.AuthenticationFailed()
        } catch (_: GeneralSecurityException) {
            throw ReallyMeCryptoException.ProviderFailure()
        }
    }

    private fun validateKeyAndNonce(key: ByteArray, expectedKeyLength: Int, nonce: ByteArray) {
        if (key.size != expectedKeyLength || nonce.size != NONCE_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }
}
