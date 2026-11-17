// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto

private data class MlDsaSuite(val publicKeyLength: Int, val signatureLength: Int)

/** ML-DSA (FIPS 204) with canonical Rust seed and deterministic signing semantics. */
public object ReallyMeMlDsa {
    public const val SECRET_SEED_LENGTH: Int = 32

    public fun generateKeyPair(algorithm: ReallyMeSignatureAlgorithm): Pair<ByteArray, ByteArray> =
        ReallyMeRustProtocols.signatureKeyPair(algorithm, null, suite(algorithm).publicKeyLength, SECRET_SEED_LENGTH)

    public fun deriveKeyPair(algorithm: ReallyMeSignatureAlgorithm, secretSeed: ByteArray): Pair<ByteArray, ByteArray> {
        val config = suite(algorithm)
        requireLength(secretSeed, SECRET_SEED_LENGTH)
        return ReallyMeRustProtocols.signatureKeyPair(algorithm, secretSeed, config.publicKeyLength, SECRET_SEED_LENGTH)
    }

    public fun derivePublicKey(algorithm: ReallyMeSignatureAlgorithm, secretSeed: ByteArray): ByteArray {
        val (publicKey, ownedSecret) = deriveKeyPair(algorithm, secretSeed)
        ownedSecret.fill(0)
        return publicKey
    }

    public fun sign(algorithm: ReallyMeSignatureAlgorithm, message: ByteArray, secretSeed: ByteArray): ByteArray {
        val config = suite(algorithm)
        requireLength(secretSeed, SECRET_SEED_LENGTH)
        val signature = ReallyMeRustProtocols.sign(algorithm, secretSeed, message)
        if (signature.size != config.signatureLength) {
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
        val config = suite(algorithm)
        requireLength(publicKey, config.publicKeyLength)
        requireLength(signature, config.signatureLength)
        ReallyMeRustProtocols.verify(algorithm, publicKey, message, signature)
    }

    private fun suite(algorithm: ReallyMeSignatureAlgorithm): MlDsaSuite = when (algorithm) {
        ReallyMeSignatureAlgorithm.ML_DSA_44 -> MlDsaSuite(1_312, 2_420)
        ReallyMeSignatureAlgorithm.ML_DSA_65 -> MlDsaSuite(1_952, 3_309)
        ReallyMeSignatureAlgorithm.ML_DSA_87 -> MlDsaSuite(2_592, 4_627)
        else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
    }

    private fun requireLength(bytes: ByteArray, length: Int) {
        if (bytes.size != length) throw ReallyMeCryptoException.InvalidInput()
    }
}
