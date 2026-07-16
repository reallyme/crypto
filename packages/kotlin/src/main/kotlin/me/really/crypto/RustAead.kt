// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

/**
 * AEAD providers intentionally backed by the ReallyMe Rust native library.
 *
 * GCM-SIV and XChaCha are not portable JCE contracts across JVM and Android.
 * Requiring an explicit native-library load keeps provider selection visible
 * and prevents accidental downgrade to a provider with different semantics.
 */
public object ReallyMeRustAead {
    public const val KEY_LENGTH: Int = 32
    public const val AES_GCM_SIV_NONCE_LENGTH: Int = 12
    public const val CHACHA20_POLY1305_NONCE_LENGTH: Int = 12
    public const val XCHACHA20_POLY1305_NONCE_LENGTH: Int = 24
    public const val TAG_LENGTH: Int = 16

    public fun sealAes256GcmSiv(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
    ): ByteArray {
        validateKeyAndNonce(key, nonce, AES_GCM_SIV_NONCE_LENGTH)
        return sealWithRust { aes256GcmSivSealNative(key, nonce, aad, plaintext) }
    }

    public fun openAes256GcmSiv(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        ciphertextWithTag: ByteArray,
    ): ByteArray {
        validateOpenInput(key, nonce, AES_GCM_SIV_NONCE_LENGTH, ciphertextWithTag)
        return openWithRust { aes256GcmSivOpenNative(key, nonce, aad, ciphertextWithTag) }
    }

    public fun sealChaCha20Poly1305(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
    ): ByteArray {
        validateKeyAndNonce(key, nonce, CHACHA20_POLY1305_NONCE_LENGTH)
        return sealWithRust { chacha20Poly1305SealNative(key, nonce, aad, plaintext) }
    }

    public fun openChaCha20Poly1305(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        ciphertextWithTag: ByteArray,
    ): ByteArray {
        validateOpenInput(key, nonce, CHACHA20_POLY1305_NONCE_LENGTH, ciphertextWithTag)
        return openWithRust { chacha20Poly1305OpenNative(key, nonce, aad, ciphertextWithTag) }
    }

    public fun sealXChaCha20Poly1305(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
    ): ByteArray {
        validateKeyAndNonce(key, nonce, XCHACHA20_POLY1305_NONCE_LENGTH)
        return sealWithRust { xchacha20Poly1305SealNative(key, nonce, aad, plaintext) }
    }

    public fun openXChaCha20Poly1305(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        ciphertextWithTag: ByteArray,
    ): ByteArray {
        validateOpenInput(key, nonce, XCHACHA20_POLY1305_NONCE_LENGTH, ciphertextWithTag)
        return openWithRust { xchacha20Poly1305OpenNative(key, nonce, aad, ciphertextWithTag) }
    }

    private fun sealWithRust(operation: () -> ByteArray?): ByteArray {
        ReallyMeRustNativeProvider.requireLoaded()
        return try {
            requireRustNativeBytes(operation())
        } catch (error: ReallyMeCryptoException) {
            throw error
        } catch (_: LinkageError) {
            throw ReallyMeCryptoException.ProviderFailure()
        } catch (_: RuntimeException) {
            throw ReallyMeCryptoException.ProviderFailure()
        }
    }

    private fun openWithRust(operation: () -> ByteArray?): ByteArray {
        ReallyMeRustNativeProvider.requireLoaded()
        return try {
            requireRustNativeBytes(operation())
        } catch (error: ReallyMeCryptoException) {
            throw error
        } catch (_: LinkageError) {
            throw ReallyMeCryptoException.ProviderFailure()
        } catch (_: RuntimeException) {
            throw ReallyMeCryptoException.ProviderFailure()
        }
    }

    private fun validateOpenInput(
        key: ByteArray,
        nonce: ByteArray,
        expectedNonceLength: Int,
        ciphertextWithTag: ByteArray,
    ) {
        validateKeyAndNonce(key, nonce, expectedNonceLength)
        if (ciphertextWithTag.size < TAG_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }

    private fun validateKeyAndNonce(key: ByteArray, nonce: ByteArray, expectedNonceLength: Int) {
        if (key.size != KEY_LENGTH || nonce.size != expectedNonceLength) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }

    @JvmStatic
    private external fun aes256GcmSivSealNative(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
    ): ByteArray?

    @JvmStatic
    private external fun aes256GcmSivOpenNative(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        ciphertextWithTag: ByteArray,
    ): ByteArray?

    @JvmStatic
    private external fun chacha20Poly1305SealNative(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
    ): ByteArray?

    @JvmStatic
    private external fun chacha20Poly1305OpenNative(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        ciphertextWithTag: ByteArray,
    ): ByteArray?

    @JvmStatic
    private external fun xchacha20Poly1305SealNative(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
    ): ByteArray?

    @JvmStatic
    private external fun xchacha20Poly1305OpenNative(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        ciphertextWithTag: ByteArray,
    ): ByteArray?
}
