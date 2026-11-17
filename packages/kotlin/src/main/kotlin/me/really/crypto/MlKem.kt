// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto

private data class MlKemSuite(val publicKeyLength: Int, val ciphertextLength: Int)

/** ML-KEM (FIPS 203), executed by the canonical Rust operation owner. */
public object ReallyMeMlKem {
    public const val SECRET_KEY_LENGTH: Int = 64
    public const val ENCAPSULATION_RANDOMNESS_LENGTH: Int = 32
    public const val SHARED_SECRET_LENGTH: Int = 32

    public fun generateKeyPair(algorithm: ReallyMeKemAlgorithm): Pair<ByteArray, ByteArray> =
        ReallyMeRustProtocols.kemKeyPair(algorithm, null, suite(algorithm).publicKeyLength, SECRET_KEY_LENGTH)

    public fun deriveKeyPair(algorithm: ReallyMeKemAlgorithm, secretKey: ByteArray): Pair<ByteArray, ByteArray> {
        val config = suite(algorithm)
        requireLength(secretKey, SECRET_KEY_LENGTH)
        return ReallyMeRustProtocols.kemKeyPair(algorithm, secretKey, config.publicKeyLength, SECRET_KEY_LENGTH)
    }

    public fun derivePublicKey(algorithm: ReallyMeKemAlgorithm, secretKey: ByteArray): ByteArray {
        val (publicKey, ownedSecret) = deriveKeyPair(algorithm, secretKey)
        ownedSecret.fill(0)
        return publicKey
    }

    public fun encapsulate(algorithm: ReallyMeKemAlgorithm, publicKey: ByteArray): ReallyMeKemEncapsulation {
        val config = suite(algorithm)
        requireLength(publicKey, config.publicKeyLength)
        return ReallyMeRustProtocols.encapsulate(algorithm, publicKey, config.ciphertextLength)
    }

    public fun decapsulate(algorithm: ReallyMeKemAlgorithm, ciphertext: ByteArray, secretKey: ByteArray): ByteArray {
        val config = suite(algorithm)
        requireLength(secretKey, SECRET_KEY_LENGTH)
        requireLength(ciphertext, config.ciphertextLength)
        return ReallyMeRustProtocols.decapsulate(algorithm, ciphertext, secretKey)
    }

    private fun suite(algorithm: ReallyMeKemAlgorithm): MlKemSuite = when (algorithm) {
        ReallyMeKemAlgorithm.ML_KEM_512 -> MlKemSuite(800, 768)
        ReallyMeKemAlgorithm.ML_KEM_768 -> MlKemSuite(1_184, 1_088)
        ReallyMeKemAlgorithm.ML_KEM_1024 -> MlKemSuite(1_568, 1_568)
        ReallyMeKemAlgorithm.X_WING_768 -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
    }

    private fun requireLength(bytes: ByteArray, length: Int) {
        if (bytes.size != length) throw ReallyMeCryptoException.InvalidInput()
    }
}
