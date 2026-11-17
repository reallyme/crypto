// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto

/** RFC 9180 HPKE Base mode. All KEM and key-schedule behavior executes in Rust. */
public object ReallyMeHpke {
    private const val HPKE_AEAD_TAG_LENGTH: Int = 16
    private const val P256_PUBLIC_KEY_LENGTH: Int = 65
    private const val X25519_PUBLIC_KEY_LENGTH: Int = 32
    private const val PRIVATE_KEY_LENGTH: Int = 32

    public fun seal(
        suite: ReallyMeHpkeSuite,
        recipientPublicKey: ByteArray,
        info: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
    ): ReallyMeHpkeSealedMessage {
        requireLength(recipientPublicKey, publicKeyLength(suite))
        return ReallyMeRustProtocols.seal(suite, recipientPublicKey, info, aad, plaintext, publicKeyLength(suite))
    }

    public fun open(
        suite: ReallyMeHpkeSuite,
        recipientSecretKey: ByteArray,
        encapsulatedKey: ByteArray,
        info: ByteArray,
        aad: ByteArray,
        ciphertext: ByteArray,
    ): ByteArray {
        requireLength(recipientSecretKey, PRIVATE_KEY_LENGTH)
        requireLength(encapsulatedKey, publicKeyLength(suite))
        if (ciphertext.size < HPKE_AEAD_TAG_LENGTH) throw ReallyMeCryptoException.InvalidInput()
        return ReallyMeRustProtocols.open(suite, recipientSecretKey, encapsulatedKey, info, aad, ciphertext)
    }

    private fun publicKeyLength(suite: ReallyMeHpkeSuite): Int = when (suite) {
        ReallyMeHpkeSuite.DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_256_GCM -> P256_PUBLIC_KEY_LENGTH
        ReallyMeHpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305 -> X25519_PUBLIC_KEY_LENGTH
    }

    private fun requireLength(bytes: ByteArray, length: Int) {
        if (bytes.size != length) throw ReallyMeCryptoException.InvalidInput()
    }
}
