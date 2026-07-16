// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import org.bouncycastle.crypto.CryptoException
import org.bouncycastle.crypto.DataLengthException
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters
import org.bouncycastle.crypto.params.MLDSAParameters
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters
import org.bouncycastle.crypto.signers.MLDSASigner
import java.security.SecureRandom

private data class MlDsaSuite(
    val parameters: MLDSAParameters,
    val publicKeyLength: Int,
    val signatureLength: Int,
)

/**
 * ML-DSA (FIPS 204) backed by BouncyCastle.
 *
 * The package stores private material as the 32-byte FIPS seed so signatures
 * remain byte-compatible with the repository's cross-lane KATs.
 */
public object ReallyMeMlDsa {
    public const val SECRET_SEED_LENGTH: Int = 32

    public fun generateKeyPair(algorithm: ReallyMeSignatureAlgorithm): Pair<ByteArray, ByteArray> {
        val suite = suite(algorithm)
        val generator = MLDSAKeyPairGenerator()
        generator.init(MLDSAKeyGenerationParameters(SecureRandom(), suite.parameters))
        return try {
            val keyPair = generator.generateKeyPair()
            val privateKey = keyPair.private as MLDSAPrivateKeyParameters
            val publicKey = keyPair.public as MLDSAPublicKeyParameters
            Pair(publicKey.encoded, privateKey.seed)
        } catch (_: ClassCastException) {
            throw ReallyMeCryptoException.ProviderFailure()
        } catch (_: IllegalArgumentException) {
            throw ReallyMeCryptoException.ProviderFailure()
        }
    }

    public fun deriveKeyPair(algorithm: ReallyMeSignatureAlgorithm, secretSeed: ByteArray): Pair<ByteArray, ByteArray> {
        validateSecretSeed(secretSeed)
        return Pair(derivePublicKey(algorithm, secretSeed), secretSeed.copyOf())
    }

    public fun derivePublicKey(algorithm: ReallyMeSignatureAlgorithm, secretSeed: ByteArray): ByteArray {
        val suite = suite(algorithm)
        validateSecretSeed(secretSeed)
        return try {
            MLDSAPrivateKeyParameters(suite.parameters, secretSeed).publicKey
        } catch (_: IllegalArgumentException) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }

    public fun sign(algorithm: ReallyMeSignatureAlgorithm, message: ByteArray, secretSeed: ByteArray): ByteArray {
        val suite = suite(algorithm)
        validateSecretSeed(secretSeed)
        return try {
            val signer = MLDSASigner()
            signer.init(true, MLDSAPrivateKeyParameters(suite.parameters, secretSeed))
            signer.update(message, 0, message.size)
            signer.generateSignature()
        } catch (_: IllegalArgumentException) {
            throw ReallyMeCryptoException.InvalidInput()
        } catch (_: DataLengthException) {
            throw ReallyMeCryptoException.InvalidInput()
        } catch (_: CryptoException) {
            throw ReallyMeCryptoException.ProviderFailure()
        }
    }

    public fun verify(
        algorithm: ReallyMeSignatureAlgorithm,
        signature: ByteArray,
        message: ByteArray,
        publicKey: ByteArray,
    ) {
        val suite = suite(algorithm)
        validatePublicKey(suite, publicKey)
        validateSignature(suite, signature)

        try {
            val verifier = MLDSASigner()
            verifier.init(false, MLDSAPublicKeyParameters(suite.parameters, publicKey))
            verifier.update(message, 0, message.size)
            if (!verifier.verifySignature(signature)) {
                throw ReallyMeCryptoException.InvalidSignature()
            }
        } catch (_: IllegalArgumentException) {
            throw ReallyMeCryptoException.InvalidInput()
        } catch (_: DataLengthException) {
            throw ReallyMeCryptoException.InvalidInput()
        } catch (_: CryptoException) {
            throw ReallyMeCryptoException.ProviderFailure()
        }
    }

    private fun suite(algorithm: ReallyMeSignatureAlgorithm): MlDsaSuite =
        when (algorithm) {
            ReallyMeSignatureAlgorithm.ML_DSA_44 -> MlDsaSuite(MLDSAParameters.ml_dsa_44, 1_312, 2_420)
            ReallyMeSignatureAlgorithm.ML_DSA_65 -> MlDsaSuite(MLDSAParameters.ml_dsa_65, 1_952, 3_309)
            ReallyMeSignatureAlgorithm.ML_DSA_87 -> MlDsaSuite(MLDSAParameters.ml_dsa_87, 2_592, 4_627)
            else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    private fun validateSecretSeed(secretSeed: ByteArray) {
        if (secretSeed.size != SECRET_SEED_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }

    private fun validatePublicKey(suite: MlDsaSuite, publicKey: ByteArray) {
        if (publicKey.size != suite.publicKeyLength) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }

    private fun validateSignature(suite: MlDsaSuite, signature: ByteArray) {
        if (signature.size != suite.signatureLength) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }
}
