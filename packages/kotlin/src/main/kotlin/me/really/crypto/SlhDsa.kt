// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto

/** SLH-DSA-SHA2-128s (FIPS 205), executed entirely by Rust. */
public object ReallyMeSlhDsa {
    public const val KEYGEN_SEED_LENGTH: Int = 16
    public const val PUBLIC_KEY_LENGTH: Int = 32
    public const val SECRET_KEY_LENGTH: Int = 64
    public const val SIGNATURE_LENGTH: Int = 7_856
    private const val DERIVE_SEED_LENGTH: Int = 48
    private const val PK_SEED_OFFSET: Int = 32

    public fun generateKeyPair(algorithm: ReallyMeSignatureAlgorithm): Pair<ByteArray, ByteArray> {
        requireAlgorithm(algorithm)
        return ReallyMeRustProtocols.signatureKeyPair(algorithm, null, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH)
    }

    public fun deriveKeyPair(
        algorithm: ReallyMeSignatureAlgorithm,
        skSeed: ByteArray,
        skPrf: ByteArray,
        pkSeed: ByteArray,
    ): Pair<ByteArray, ByteArray> {
        requireAlgorithm(algorithm)
        requireLength(skSeed, KEYGEN_SEED_LENGTH)
        requireLength(skPrf, KEYGEN_SEED_LENGTH)
        requireLength(pkSeed, KEYGEN_SEED_LENGTH)
        // This is the schema's ordered three-seed input, not an independent
        // key-generation implementation. Rust owns expansion and validation.
        val seeds = ByteArray(DERIVE_SEED_LENGTH)
        try {
            skSeed.copyInto(seeds)
            skPrf.copyInto(seeds, KEYGEN_SEED_LENGTH)
            pkSeed.copyInto(seeds, PK_SEED_OFFSET)
            return ReallyMeRustProtocols.signatureKeyPair(algorithm, seeds, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH)
        } finally {
            seeds.fill(0)
        }
    }

    public fun sign(algorithm: ReallyMeSignatureAlgorithm, message: ByteArray, secretKey: ByteArray): ByteArray {
        requireAlgorithm(algorithm)
        requireLength(secretKey, SECRET_KEY_LENGTH)
        val signature = ReallyMeRustProtocols.sign(algorithm, secretKey, message)
        if (signature.size != SIGNATURE_LENGTH) {
            signature.fill(0)
            throw ReallyMeCryptoException.ProviderFailure()
        }
        return signature
    }

    public fun verify(
        algorithm: ReallyMeSignatureAlgorithm,
        signature: ByteArray,
        message: ByteArray,
        publicKey: ByteArray,
    ) {
        requireAlgorithm(algorithm)
        requireLength(publicKey, PUBLIC_KEY_LENGTH)
        requireLength(signature, SIGNATURE_LENGTH)
        ReallyMeRustProtocols.verify(algorithm, publicKey, message, signature)
    }

    private fun requireAlgorithm(algorithm: ReallyMeSignatureAlgorithm) {
        if (algorithm != ReallyMeSignatureAlgorithm.SLH_DSA_SHA2_128S) throw ReallyMeCryptoException.UnsupportedAlgorithm()
    }

    private fun requireLength(bytes: ByteArray, length: Int) {
        if (bytes.size != length) throw ReallyMeCryptoException.InvalidInput()
    }
}
