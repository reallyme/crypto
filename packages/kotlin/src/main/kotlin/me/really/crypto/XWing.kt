// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import java.security.SecureRandom
import org.bouncycastle.crypto.digests.SHA3Digest
import org.bouncycastle.crypto.digests.SHAKEDigest
import org.bouncycastle.crypto.kems.MLKEMExtractor
import org.bouncycastle.crypto.kems.MLKEMGenerator
import org.bouncycastle.crypto.params.MLKEMParameters
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters

private data class XWingSuiteConfig(
    val parameters: MLKEMParameters,
    val publicKeyLength: Int,
    val ciphertextLength: Int,
    val mlKemPublicKeyLength: Int,
    val mlKemCiphertextLength: Int,
)

/**
 * X-Wing hybrid KEM over X25519 and ML-KEM.
 *
 * BouncyCastle's convenience X-Wing classes currently model the draft
 * ML-KEM-768 suite. The package keeps the combiner explicit so the ReallyMe
 * ML-KEM-1024 variant follows the same seed and label contract as Rust.
 */
public object ReallyMeXWing {
    public const val SECRET_KEY_LENGTH: Int = 32
    public const val ENCAPSULATION_SEED_LENGTH: Int = 64
    public const val SHARED_SECRET_LENGTH: Int = 32

    private const val X25519_KEY_LENGTH: Int = 32
    private const val ML_KEM_SECRET_SEED_LENGTH: Int = 64
    private const val ML_KEM_SHARED_SECRET_LENGTH: Int = 32
    private const val EXPANDED_SECRET_LENGTH: Int = ML_KEM_SECRET_SEED_LENGTH + X25519_KEY_LENGTH
    private val xWingLabel = "\\.//^\\".toByteArray(Charsets.US_ASCII)

    public fun generateKeyPair(algorithm: ReallyMeKemAlgorithm): Pair<ByteArray, ByteArray> {
        val secretKey = ByteArray(SECRET_KEY_LENGTH)
        SecureRandom().nextBytes(secretKey)
        return Pair(derivePublicKey(algorithm, secretKey), secretKey)
    }

    public fun derivePublicKey(algorithm: ReallyMeKemAlgorithm, secretKey: ByteArray): ByteArray {
        val config = config(algorithm)
        val expanded = expandSecretKey(secretKey)
        val mlKemSeed = expanded.copyOfRange(0, ML_KEM_SECRET_SEED_LENGTH)
        val x25519Secret = expanded.copyOfRange(ML_KEM_SECRET_SEED_LENGTH, EXPANDED_SECRET_LENGTH)
        expanded.fill(0)

        return try {
            val mlKemPublicKey = MLKEMPrivateKeyParameters(config.parameters, mlKemSeed).publicKey
            val x25519PublicKey = X25519PrivateKeyParameters(x25519Secret, 0).generatePublicKey().encoded
            mlKemSeed.fill(0)
            x25519Secret.fill(0)
            composePublicKey(config, mlKemPublicKey, x25519PublicKey)
        } catch (_: IllegalArgumentException) {
            mlKemSeed.fill(0)
            x25519Secret.fill(0)
            throw ReallyMeCryptoException.InvalidInput()
        }
    }

    public fun encapsulate(algorithm: ReallyMeKemAlgorithm, publicKey: ByteArray): ReallyMeKemEncapsulation {
        val seed = ByteArray(ENCAPSULATION_SEED_LENGTH)
        SecureRandom().nextBytes(seed)
        return try {
            encapsulateDeterministicForTest(algorithm, publicKey, seed)
        } finally {
            seed.fill(0)
        }
    }

    public fun decapsulate(
        algorithm: ReallyMeKemAlgorithm,
        ciphertext: ByteArray,
        secretKey: ByteArray,
    ): ByteArray {
        val config = config(algorithm)
        if (ciphertext.size != config.ciphertextLength) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        val (mlKemCiphertext, x25519Ciphertext) = splitCiphertext(config, ciphertext)
        val expanded = expandSecretKey(secretKey)
        val mlKemSeed = expanded.copyOfRange(0, ML_KEM_SECRET_SEED_LENGTH)
        val x25519Secret = expanded.copyOfRange(ML_KEM_SECRET_SEED_LENGTH, EXPANDED_SECRET_LENGTH)
        expanded.fill(0)

        return try {
            val privateKey = MLKEMPrivateKeyParameters(config.parameters, mlKemSeed)
            val mlKemSharedSecret = MLKEMExtractor(privateKey).extractSecret(mlKemCiphertext)
            val x25519SharedSecret = x25519SharedSecret(x25519Secret, x25519Ciphertext)
            val x25519PublicKey = X25519PrivateKeyParameters(x25519Secret, 0).generatePublicKey().encoded
            val sharedSecret = combineSharedSecret(
                mlKemSharedSecret,
                x25519SharedSecret,
                x25519Ciphertext,
                x25519PublicKey,
            )
            mlKemSeed.fill(0)
            x25519Secret.fill(0)
            mlKemSharedSecret.fill(0)
            x25519SharedSecret.fill(0)
            sharedSecret
        } catch (_: IllegalArgumentException) {
            mlKemSeed.fill(0)
            x25519Secret.fill(0)
            throw ReallyMeCryptoException.InvalidInput()
        }
    }

    internal fun encapsulateDeterministicForTest(
        algorithm: ReallyMeKemAlgorithm,
        publicKey: ByteArray,
        seed: ByteArray,
    ): ReallyMeKemEncapsulation {
        val config = config(algorithm)
        if (seed.size != ENCAPSULATION_SEED_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        val (mlKemPublicKey, x25519PublicKey) = splitPublicKey(config, publicKey)
        val mlKemRandomness = seed.copyOfRange(0, ML_KEM_SHARED_SECRET_LENGTH)
        val x25519EphemeralSecret = seed.copyOfRange(ML_KEM_SHARED_SECRET_LENGTH, ENCAPSULATION_SEED_LENGTH)

        return try {
            val mlKemEncapsulated = MLKEMGenerator(FixedSecureRandom(mlKemRandomness)).generateEncapsulated(
                MLKEMPublicKeyParameters(config.parameters, mlKemPublicKey),
            )
            val mlKemCiphertext = mlKemEncapsulated.encapsulation.copyOf()
            val mlKemSharedSecret = mlKemEncapsulated.secret.copyOf()
            mlKemEncapsulated.destroy()
            val x25519Ciphertext = X25519PrivateKeyParameters(x25519EphemeralSecret, 0).generatePublicKey().encoded
            val x25519SharedSecret = x25519SharedSecret(x25519EphemeralSecret, x25519PublicKey)
            val sharedSecret = combineSharedSecret(
                mlKemSharedSecret,
                x25519SharedSecret,
                x25519Ciphertext,
                x25519PublicKey,
            )
            val ciphertext = composeCiphertext(config, mlKemCiphertext, x25519Ciphertext)
            mlKemRandomness.fill(0)
            x25519EphemeralSecret.fill(0)
            mlKemSharedSecret.fill(0)
            x25519SharedSecret.fill(0)
            ReallyMeKemEncapsulation(sharedSecret = sharedSecret, ciphertext = ciphertext)
        } catch (_: IllegalArgumentException) {
            mlKemRandomness.fill(0)
            x25519EphemeralSecret.fill(0)
            throw ReallyMeCryptoException.InvalidInput()
        } catch (_: XWingDeterministicRandomExhaustedException) {
            mlKemRandomness.fill(0)
            x25519EphemeralSecret.fill(0)
            throw ReallyMeCryptoException.ProviderFailure()
        }
    }

    private fun config(algorithm: ReallyMeKemAlgorithm): XWingSuiteConfig =
        when (algorithm) {
            ReallyMeKemAlgorithm.X_WING_768 ->
                XWingSuiteConfig(MLKEMParameters.ml_kem_768, 1_216, 1_120, 1_184, 1_088)
            ReallyMeKemAlgorithm.X_WING_1024 ->
                XWingSuiteConfig(MLKEMParameters.ml_kem_1024, 1_600, 1_600, 1_568, 1_568)
            ReallyMeKemAlgorithm.ML_KEM_512,
            ReallyMeKemAlgorithm.ML_KEM_768,
            ReallyMeKemAlgorithm.ML_KEM_1024,
            -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    private fun expandSecretKey(secretKey: ByteArray): ByteArray {
        if (secretKey.size != SECRET_KEY_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        val expanded = ByteArray(EXPANDED_SECRET_LENGTH)
        val shake = SHAKEDigest(256)
        shake.update(secretKey, 0, secretKey.size)
        shake.doFinal(expanded, 0, expanded.size)
        return expanded
    }

    private fun splitPublicKey(config: XWingSuiteConfig, publicKey: ByteArray): Pair<ByteArray, ByteArray> {
        if (publicKey.size != config.publicKeyLength) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        return Pair(
            publicKey.copyOfRange(0, config.mlKemPublicKeyLength),
            publicKey.copyOfRange(config.mlKemPublicKeyLength, config.publicKeyLength),
        )
    }

    private fun splitCiphertext(config: XWingSuiteConfig, ciphertext: ByteArray): Pair<ByteArray, ByteArray> =
        Pair(
            ciphertext.copyOfRange(0, config.mlKemCiphertextLength),
            ciphertext.copyOfRange(config.mlKemCiphertextLength, config.ciphertextLength),
        )

    private fun composePublicKey(config: XWingSuiteConfig, mlKemPublicKey: ByteArray, x25519PublicKey: ByteArray): ByteArray {
        if (mlKemPublicKey.size != config.mlKemPublicKeyLength || x25519PublicKey.size != X25519_KEY_LENGTH) {
            throw ReallyMeCryptoException.ProviderFailure()
        }
        return mlKemPublicKey + x25519PublicKey
    }

    private fun composeCiphertext(
        config: XWingSuiteConfig,
        mlKemCiphertext: ByteArray,
        x25519Ciphertext: ByteArray,
    ): ByteArray {
        if (mlKemCiphertext.size != config.mlKemCiphertextLength || x25519Ciphertext.size != X25519_KEY_LENGTH) {
            throw ReallyMeCryptoException.ProviderFailure()
        }
        return mlKemCiphertext + x25519Ciphertext
    }

    private fun x25519SharedSecret(secretKey: ByteArray, publicKey: ByteArray): ByteArray {
        if (secretKey.size != X25519_KEY_LENGTH || publicKey.size != X25519_KEY_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        val sharedSecret = ByteArray(X25519_KEY_LENGTH)
        X25519PrivateKeyParameters(secretKey, 0).generateSecret(
            X25519PublicKeyParameters(publicKey, 0),
            sharedSecret,
            0,
        )
        if (sharedSecret.all { byte -> byte == 0.toByte() }) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        return sharedSecret
    }

    private fun combineSharedSecret(
        mlKemSharedSecret: ByteArray,
        x25519SharedSecret: ByteArray,
        x25519Ciphertext: ByteArray,
        x25519PublicKey: ByteArray,
    ): ByteArray {
        if (
            mlKemSharedSecret.size != ML_KEM_SHARED_SECRET_LENGTH ||
            x25519SharedSecret.size != X25519_KEY_LENGTH ||
            x25519Ciphertext.size != X25519_KEY_LENGTH ||
            x25519PublicKey.size != X25519_KEY_LENGTH
        ) {
            throw ReallyMeCryptoException.ProviderFailure()
        }
        val digest = SHA3Digest(256)
        digest.update(mlKemSharedSecret, 0, mlKemSharedSecret.size)
        digest.update(x25519SharedSecret, 0, x25519SharedSecret.size)
        digest.update(x25519Ciphertext, 0, x25519Ciphertext.size)
        digest.update(x25519PublicKey, 0, x25519PublicKey.size)
        digest.update(xWingLabel, 0, xWingLabel.size)
        val sharedSecret = ByteArray(SHARED_SECRET_LENGTH)
        digest.doFinal(sharedSecret, 0)
        return sharedSecret
    }
}

private class FixedSecureRandom(private val seed: ByteArray) : SecureRandom() {
    private var offset: Int = 0

    override fun nextBytes(bytes: ByteArray) {
        val nextOffset = offset + bytes.size
        if (nextOffset > seed.size) {
            throw XWingDeterministicRandomExhaustedException()
        }
        System.arraycopy(seed, offset, bytes, 0, bytes.size)
        offset = nextOffset
    }
}

private class XWingDeterministicRandomExhaustedException : RuntimeException()
