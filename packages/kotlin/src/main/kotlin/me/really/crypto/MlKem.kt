// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import java.security.SecureRandom
import org.bouncycastle.crypto.kems.MLKEMExtractor
import org.bouncycastle.crypto.kems.MLKEMGenerator
import org.bouncycastle.crypto.params.MLKEMParameters
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters

private data class MlKemSuite(
    val parameters: MLKEMParameters,
    val publicKeyLength: Int,
    val ciphertextLength: Int,
)

/**
 * ML-KEM (FIPS 203) backed by BouncyCastle.
 *
 * Secret keys at the package boundary are the repository's 64-byte
 * `fips-203-seed` form. That lets Kotlin reproduce the committed keygen and
 * decapsulation vectors without exposing expanded private key internals.
 */
public object ReallyMeMlKem {
    public const val SECRET_KEY_LENGTH: Int = 64
    public const val ENCAPSULATION_RANDOMNESS_LENGTH: Int = 32
    public const val SHARED_SECRET_LENGTH: Int = 32

    public fun generateKeyPair(algorithm: ReallyMeKemAlgorithm): Pair<ByteArray, ByteArray> {
        val suite = suite(algorithm)
        val secretKey = ByteArray(SECRET_KEY_LENGTH)
        SecureRandom().nextBytes(secretKey)
        val publicKey = try {
            derivePublicKey(algorithm, secretKey)
        } catch (_: ReallyMeCryptoException.InvalidInput) {
            secretKey.fill(0)
            throw ReallyMeCryptoException.ProviderFailure()
        }
        return Pair(publicKey, secretKey)
    }

    public fun deriveKeyPair(algorithm: ReallyMeKemAlgorithm, secretKey: ByteArray): Pair<ByteArray, ByteArray> {
        validateSecretKey(secretKey)
        return Pair(derivePublicKey(algorithm, secretKey), secretKey.copyOf())
    }

    public fun derivePublicKey(algorithm: ReallyMeKemAlgorithm, secretKey: ByteArray): ByteArray {
        val suite = suite(algorithm)
        validateSecretKey(secretKey)
        return try {
            MLKEMPrivateKeyParameters(suite.parameters, secretKey).publicKey
        } catch (_: IllegalArgumentException) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }

    public fun encapsulate(algorithm: ReallyMeKemAlgorithm, publicKey: ByteArray): ReallyMeKemEncapsulation {
        val suite = suite(algorithm)
        validatePublicKey(suite, publicKey)
        val encapsulated = try {
            MLKEMGenerator(SecureRandom()).generateEncapsulated(
                MLKEMPublicKeyParameters(suite.parameters, publicKey),
            )
        } catch (_: IllegalArgumentException) {
            throw ReallyMeCryptoException.InvalidInput()
        }

        return try {
            val sharedSecret = encapsulated.secret.copyOf()
            val ciphertext = encapsulated.encapsulation.copyOf()
            if (sharedSecret.size != SHARED_SECRET_LENGTH || ciphertext.size != suite.ciphertextLength) {
                sharedSecret.fill(0)
                ciphertext.fill(0)
                throw ReallyMeCryptoException.ProviderFailure()
            }
            ReallyMeKemEncapsulation(sharedSecret = sharedSecret, ciphertext = ciphertext)
        } finally {
            encapsulated.destroy()
        }
    }

    internal fun encapsulateDeterministicForTest(
        algorithm: ReallyMeKemAlgorithm,
        publicKey: ByteArray,
        randomness: ByteArray,
    ): ReallyMeKemEncapsulation {
        val suite = suite(algorithm)
        validatePublicKey(suite, publicKey)
        if (randomness.size != ENCAPSULATION_RANDOMNESS_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }

        val encapsulated = try {
            MLKEMGenerator(MlKemFixedSecureRandom(randomness)).generateEncapsulated(
                MLKEMPublicKeyParameters(suite.parameters, publicKey),
            )
        } catch (_: IllegalArgumentException) {
            throw ReallyMeCryptoException.InvalidInput()
        }

        return try {
            val sharedSecret = encapsulated.secret.copyOf()
            val ciphertext = encapsulated.encapsulation.copyOf()
            if (sharedSecret.size != SHARED_SECRET_LENGTH || ciphertext.size != suite.ciphertextLength) {
                sharedSecret.fill(0)
                ciphertext.fill(0)
                throw ReallyMeCryptoException.ProviderFailure()
            }
            ReallyMeKemEncapsulation(sharedSecret = sharedSecret, ciphertext = ciphertext)
        } finally {
            encapsulated.destroy()
        }
    }

    public fun decapsulate(
        algorithm: ReallyMeKemAlgorithm,
        ciphertext: ByteArray,
        secretKey: ByteArray,
    ): ByteArray {
        val suite = suite(algorithm)
        validateSecretKey(secretKey)
        if (ciphertext.size != suite.ciphertextLength) {
            throw ReallyMeCryptoException.InvalidInput()
        }

        return try {
            val privateKey = MLKEMPrivateKeyParameters(suite.parameters, secretKey)
            val sharedSecret = MLKEMExtractor(privateKey).extractSecret(ciphertext)
            if (sharedSecret.size != SHARED_SECRET_LENGTH) {
                sharedSecret.fill(0)
                throw ReallyMeCryptoException.ProviderFailure()
            }
            sharedSecret
        } catch (_: IllegalArgumentException) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }

    private fun suite(algorithm: ReallyMeKemAlgorithm): MlKemSuite =
        when (algorithm) {
            ReallyMeKemAlgorithm.ML_KEM_512 -> MlKemSuite(MLKEMParameters.ml_kem_512, 800, 768)
            ReallyMeKemAlgorithm.ML_KEM_768 -> MlKemSuite(MLKEMParameters.ml_kem_768, 1_184, 1_088)
            ReallyMeKemAlgorithm.ML_KEM_1024 -> MlKemSuite(MLKEMParameters.ml_kem_1024, 1_568, 1_568)
            ReallyMeKemAlgorithm.X_WING_768,
            ReallyMeKemAlgorithm.X_WING_1024,
            -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    private fun validatePublicKey(suite: MlKemSuite, publicKey: ByteArray) {
        if (publicKey.size != suite.publicKeyLength) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }

    private fun validateSecretKey(secretKey: ByteArray) {
        if (secretKey.size != SECRET_KEY_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }
}

private class MlKemFixedSecureRandom(private val seed: ByteArray) : SecureRandom() {
    private var offset: Int = 0

    override fun nextBytes(bytes: ByteArray) {
        val nextOffset = offset + bytes.size
        if (nextOffset > seed.size) {
            throw IllegalStateException()
        }
        System.arraycopy(seed, offset, bytes, 0, bytes.size)
        offset = nextOffset
    }
}
