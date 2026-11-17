// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto

import me.really.crypto.proto.ReallyMeCryptoProtoAdapters

/** Chosen randomness exists only in test sources and test-vectors native images. */
internal object ReallyMeProtocolConformance {
    fun encapsulate(
        algorithm: ReallyMeKemAlgorithm,
        publicKey: ByteArray,
        seed: ByteArray,
    ): ReallyMeKemEncapsulation {
        val ciphertextLength = when (algorithm) {
            ReallyMeKemAlgorithm.ML_KEM_512 -> 768
            ReallyMeKemAlgorithm.ML_KEM_768 -> 1_088
            ReallyMeKemAlgorithm.ML_KEM_1024 -> 1_568
            ReallyMeKemAlgorithm.X_WING_768 -> 1_120
        }
        val randomnessLength = if (algorithm == ReallyMeKemAlgorithm.X_WING_768) 64 else 32
        if (seed.size != randomnessLength) throw ReallyMeCryptoException.InvalidInput()
        val encoded = invoke { encapsulateNative(ReallyMeCryptoProtoAdapters.toProto(algorithm).number, publicKey, seed) }
        val (ciphertext, secret) = ReallyMeRustProtocols.decodePair(encoded, ciphertextLength, SHARED_SECRET_LENGTH)
        return ReallyMeKemEncapsulation(sharedSecret = secret, ciphertext = ciphertext)
    }

    fun seal(
        suite: ReallyMeHpkeSuite,
        recipientPublicKey: ByteArray,
        encapsulationSeed: ByteArray,
        info: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
    ): ReallyMeHpkeSealedMessage {
        if (encapsulationSeed.size != HPKE_SEED_LENGTH) throw ReallyMeCryptoException.InvalidInput()
        val ids = ReallyMeCryptoProtoAdapters.toProto(suite)
        val ciphertextLength = try {
            Math.addExact(plaintext.size, HPKE_TAG_LENGTH)
        } catch (_: ArithmeticException) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        val encapsulatedLength = when (suite) {
            ReallyMeHpkeSuite.DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_256_GCM -> 65
            ReallyMeHpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305 -> 32
        }
        val encoded = invoke {
            hpkeSealNative(ids.kemValue, ids.kdfValue, ids.aeadValue, recipientPublicKey, info, aad, plaintext, encapsulationSeed)
        }
        val (encapsulated, ciphertext) = ReallyMeRustProtocols.decodePair(encoded, encapsulatedLength, ciphertextLength)
        return ReallyMeHpkeSealedMessage(encapsulatedKey = encapsulated, ciphertext = ciphertext)
    }

    private fun invoke(operation: () -> ByteArray?): ByteArray = ReallyMeRustProtocols.invoke {
        try {
            operation()
        } catch (_: LinkageError) {
            // Release libraries deliberately omit these native entry points.
            throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }
    }

    private const val SHARED_SECRET_LENGTH: Int = 32
    private const val HPKE_SEED_LENGTH: Int = 32
    private const val HPKE_TAG_LENGTH: Int = 16

    @JvmStatic
    private external fun encapsulateNative(algorithm: Int, publicKey: ByteArray, seed: ByteArray): ByteArray?

    @JvmStatic
    private external fun hpkeSealNative(
        kem: Int,
        kdf: Int,
        aead: Int,
        publicKey: ByteArray,
        info: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
        seed: ByteArray,
    ): ByteArray?
}
