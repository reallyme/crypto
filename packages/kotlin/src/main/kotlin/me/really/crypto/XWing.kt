// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto

/** X-Wing-768. Seed expansion, component KEMs, and the combiner all execute in Rust. */
public object ReallyMeXWing {
    public const val SECRET_KEY_LENGTH: Int = 32
    public const val ENCAPSULATION_SEED_LENGTH: Int = 64
    public const val SHARED_SECRET_LENGTH: Int = 32
    private const val PUBLIC_KEY_LENGTH: Int = 1_216
    private const val CIPHERTEXT_LENGTH: Int = 1_120

    public fun generateKeyPair(algorithm: ReallyMeKemAlgorithm): Pair<ByteArray, ByteArray> {
        requireAlgorithm(algorithm)
        return ReallyMeRustProtocols.kemKeyPair(algorithm, null, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH)
    }

    public fun derivePublicKey(algorithm: ReallyMeKemAlgorithm, secretKey: ByteArray): ByteArray {
        requireAlgorithm(algorithm)
        requireLength(secretKey, SECRET_KEY_LENGTH)
        val (publicKey, ownedSecret) = ReallyMeRustProtocols.kemKeyPair(algorithm, secretKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH)
        ownedSecret.fill(0)
        return publicKey
    }

    public fun encapsulate(algorithm: ReallyMeKemAlgorithm, publicKey: ByteArray): ReallyMeKemEncapsulation {
        requireAlgorithm(algorithm)
        requireLength(publicKey, PUBLIC_KEY_LENGTH)
        return ReallyMeRustProtocols.encapsulate(algorithm, publicKey, CIPHERTEXT_LENGTH)
    }

    public fun decapsulate(algorithm: ReallyMeKemAlgorithm, ciphertext: ByteArray, secretKey: ByteArray): ByteArray {
        requireAlgorithm(algorithm)
        requireLength(ciphertext, CIPHERTEXT_LENGTH)
        requireLength(secretKey, SECRET_KEY_LENGTH)
        return ReallyMeRustProtocols.decapsulate(algorithm, ciphertext, secretKey)
    }

    private fun requireAlgorithm(algorithm: ReallyMeKemAlgorithm) {
        if (algorithm != ReallyMeKemAlgorithm.X_WING_768) throw ReallyMeCryptoException.UnsupportedAlgorithm()
    }

    private fun requireLength(bytes: ByteArray, length: Int) {
        if (bytes.size != length) throw ReallyMeCryptoException.InvalidInput()
    }
}
