// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import java.security.GeneralSecurityException
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/**
 * AES-KW (RFC 3394) backed by the bundled BouncyCastle provider.
 *
 * The provider accepts only suite-matching KEK lengths and key data that RFC
 * 3394 can wrap: at least two 64-bit blocks and a multiple of 64 bits.
 */
public object ReallyMeAesKw {
    public const val AES_128_WRAPPING_KEY_LENGTH: Int = 16
    public const val AES_192_WRAPPING_KEY_LENGTH: Int = 24
    public const val AES_256_WRAPPING_KEY_LENGTH: Int = 32
    public const val WRAPPING_KEY_LENGTH: Int = AES_256_WRAPPING_KEY_LENGTH
    public const val INTEGRITY_LENGTH: Int = 8
    public const val MIN_KEY_DATA_LENGTH: Int = 16
    public const val MIN_WRAPPED_KEY_LENGTH: Int = 24
    public const val MAX_KEY_DATA_LENGTH: Int = 4096

    private const val TRANSFORMATION = "AESWrap"
    private const val KEY_ALGORITHM = "AES"

    public fun wrapKey(
        algorithm: ReallyMeKeyWrapAlgorithm,
        wrappingKey: ByteArray,
        keyToWrap: ByteArray,
    ): ByteArray {
        validateWrappingKey(algorithm, wrappingKey)
        validateKeyData(keyToWrap)

        return try {
            val cipher = ReallyMeJceProviders.bouncyCastleCipher(TRANSFORMATION)
            cipher.init(Cipher.WRAP_MODE, SecretKeySpec(wrappingKey, KEY_ALGORITHM))
            val wrapped = cipher.wrap(SecretKeySpec(keyToWrap, KEY_ALGORITHM))
            if (wrapped.size != keyToWrap.size + INTEGRITY_LENGTH) {
                wrapped.fill(0)
                throw ReallyMeCryptoException.ProviderFailure()
            }
            wrapped
        } catch (error: ReallyMeCryptoException.ProviderFailure) {
            throw error
        } catch (_: GeneralSecurityException) {
            throw ReallyMeCryptoException.ProviderFailure()
        }
    }

    public fun unwrapKey(
        algorithm: ReallyMeKeyWrapAlgorithm,
        wrappingKey: ByteArray,
        wrappedKey: ByteArray,
    ): ByteArray {
        validateWrappingKey(algorithm, wrappingKey)
        validateWrappedKey(wrappedKey)

        val cipher = try {
            ReallyMeJceProviders.bouncyCastleCipher(TRANSFORMATION).also { cipher ->
                cipher.init(Cipher.UNWRAP_MODE, SecretKeySpec(wrappingKey, KEY_ALGORITHM))
            }
        } catch (_: GeneralSecurityException) {
            throw ReallyMeCryptoException.ProviderFailure()
        }
        return try {
            val key = cipher.unwrap(wrappedKey, KEY_ALGORITHM, Cipher.SECRET_KEY)
            val encoded = key.encoded ?: throw ReallyMeCryptoException.ProviderFailure()
            if (encoded.size != wrappedKey.size - INTEGRITY_LENGTH) {
                encoded.fill(0)
                throw ReallyMeCryptoException.ProviderFailure()
            }
            encoded
        } catch (_: ReallyMeCryptoException.ProviderFailure) {
            throw ReallyMeCryptoException.ProviderFailure()
        } catch (_: GeneralSecurityException) {
            throw ReallyMeCryptoException.AuthenticationFailed()
        }
    }

    private fun validateWrappingKey(algorithm: ReallyMeKeyWrapAlgorithm, key: ByteArray) {
        if (key.size != wrappingKeyLength(algorithm)) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }

    private fun wrappingKeyLength(algorithm: ReallyMeKeyWrapAlgorithm): Int =
        when (algorithm) {
            ReallyMeKeyWrapAlgorithm.AES_128_KW -> AES_128_WRAPPING_KEY_LENGTH
            ReallyMeKeyWrapAlgorithm.AES_192_KW -> AES_192_WRAPPING_KEY_LENGTH
            ReallyMeKeyWrapAlgorithm.AES_256_KW -> AES_256_WRAPPING_KEY_LENGTH
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
