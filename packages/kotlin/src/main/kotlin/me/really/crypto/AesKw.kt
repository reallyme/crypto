// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import java.security.GeneralSecurityException
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/**
 * AES-256-KW (RFC 3394) backed by JCA/JCE with explicit BouncyCastle fallback.
 *
 * The provider accepts only 256-bit KEKs and key data that RFC 3394 can wrap:
 * at least two 64-bit blocks and a multiple of 64 bits.
 */
public object ReallyMeAesKw {
    public const val WRAPPING_KEY_LENGTH: Int = 32
    public const val INTEGRITY_LENGTH: Int = 8
    public const val MIN_KEY_DATA_LENGTH: Int = 16
    public const val MIN_WRAPPED_KEY_LENGTH: Int = 24
    public const val MAX_KEY_DATA_LENGTH: Int = 4096

    private const val TRANSFORMATION = "AESWrap"
    private const val KEY_ALGORITHM = "AES"

    public fun wrapKey(wrappingKey: ByteArray, keyToWrap: ByteArray): ByteArray {
        validateWrappingKey(wrappingKey)
        validateKeyData(keyToWrap)

        return try {
            val cipher = ReallyMeJceProviders.cipher(TRANSFORMATION)
            cipher.init(Cipher.WRAP_MODE, SecretKeySpec(wrappingKey, KEY_ALGORITHM))
            cipher.wrap(SecretKeySpec(keyToWrap, KEY_ALGORITHM))
        } catch (_: GeneralSecurityException) {
            throw ReallyMeCryptoException.ProviderFailure()
        }
    }

    public fun unwrapKey(wrappingKey: ByteArray, wrappedKey: ByteArray): ByteArray {
        validateWrappingKey(wrappingKey)
        validateWrappedKey(wrappedKey)

        return try {
            val cipher = ReallyMeJceProviders.cipher(TRANSFORMATION)
            cipher.init(Cipher.UNWRAP_MODE, SecretKeySpec(wrappingKey, KEY_ALGORITHM))
            val key = cipher.unwrap(wrappedKey, KEY_ALGORITHM, Cipher.SECRET_KEY)
            key.encoded ?: throw ReallyMeCryptoException.ProviderFailure()
        } catch (_: ReallyMeCryptoException.ProviderFailure) {
            throw ReallyMeCryptoException.ProviderFailure()
        } catch (_: GeneralSecurityException) {
            throw ReallyMeCryptoException.AuthenticationFailed()
        }
    }

    private fun validateWrappingKey(key: ByteArray) {
        if (key.size != WRAPPING_KEY_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }

    private fun validateKeyData(keyData: ByteArray) {
        if (keyData.size < MIN_KEY_DATA_LENGTH ||
            keyData.size > MAX_KEY_DATA_LENGTH ||
            keyData.size % INTEGRITY_LENGTH != 0
        ) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }

    private fun validateWrappedKey(wrappedKey: ByteArray) {
        if (wrappedKey.size < MIN_WRAPPED_KEY_LENGTH ||
            wrappedKey.size > MAX_KEY_DATA_LENGTH + INTEGRITY_LENGTH ||
            wrappedKey.size % INTEGRITY_LENGTH != 0
        ) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }
}
