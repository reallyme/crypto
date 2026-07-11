// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import java.security.SecureRandom
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.CryptoException
import org.bouncycastle.crypto.DataLengthException
import org.bouncycastle.crypto.generators.SLHDSAKeyPairGenerator
import org.bouncycastle.crypto.params.SLHDSAKeyGenerationParameters
import org.bouncycastle.crypto.params.SLHDSAParameters
import org.bouncycastle.crypto.params.SLHDSAPrivateKeyParameters
import org.bouncycastle.crypto.params.SLHDSAPublicKeyParameters
import org.bouncycastle.crypto.signers.SLHDSASigner

/**
 * SLH-DSA-SHA2-128s (FIPS 205) backed by BouncyCastle.
 *
 * The seed-derived route mirrors the FIPS 205 vector shape: SK seed, SK PRF,
 * and PK seed are independent 16-byte values. Signing initializes
 * BouncyCastle without a random wrapper so the optional randomizer is
 * deterministic and cross-lane vectors stay byte-identical.
 */
public object ReallyMeSlhDsa {
    public const val KEYGEN_SEED_LENGTH: Int = 16
    public const val PUBLIC_KEY_LENGTH: Int = 32
    public const val SECRET_KEY_LENGTH: Int = 64
    public const val SIGNATURE_LENGTH: Int = 7_856

    public fun generateKeyPair(algorithm: ReallyMeSignatureAlgorithm): Pair<ByteArray, ByteArray> {
        requireSlhDsaSha2_128s(algorithm)
        val generator = SLHDSAKeyPairGenerator()
        generator.init(SLHDSAKeyGenerationParameters(SecureRandom(), SLHDSAParameters.sha2_128s))
        return encodeKeyPair(generator.generateKeyPair())
    }

    public fun deriveKeyPair(
        algorithm: ReallyMeSignatureAlgorithm,
        skSeed: ByteArray,
        skPrf: ByteArray,
        pkSeed: ByteArray,
    ): Pair<ByteArray, ByteArray> {
        requireSlhDsaSha2_128s(algorithm)
        validateSeed(skSeed)
        validateSeed(skPrf)
        validateSeed(pkSeed)

        val keyPair = try {
            val generator = SLHDSAKeyPairGenerator()
            generator.init(SLHDSAKeyGenerationParameters(SecureRandom(), SLHDSAParameters.sha2_128s))
            generator.internalGenerateKeyPair(skSeed, skPrf, pkSeed)
        } catch (_: IllegalArgumentException) {
            throw ReallyMeCryptoException.InvalidInput()
        } catch (_: IllegalStateException) {
            throw ReallyMeCryptoException.ProviderFailure()
        }
        return encodeKeyPair(keyPair)
    }

    public fun sign(
        algorithm: ReallyMeSignatureAlgorithm,
        message: ByteArray,
        secretKey: ByteArray,
    ): ByteArray {
        requireSlhDsaSha2_128s(algorithm)
        validateSecretKey(secretKey)

        return try {
            val signer = SLHDSASigner()
            signer.init(true, SLHDSAPrivateKeyParameters(SLHDSAParameters.sha2_128s, secretKey))
            val signature = signer.generateSignature(message)
            if (signature.size != SIGNATURE_LENGTH) {
                signature.fill(0)
                throw ReallyMeCryptoException.ProviderFailure()
            }
            signature
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
        requireSlhDsaSha2_128s(algorithm)
        validatePublicKey(publicKey)
        validateSignature(signature)

        try {
            val verifier = SLHDSASigner()
            verifier.init(false, SLHDSAPublicKeyParameters(SLHDSAParameters.sha2_128s, publicKey))
            if (!verifier.verifySignature(message, signature)) {
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

    private fun encodeKeyPair(keyPair: AsymmetricCipherKeyPair): Pair<ByteArray, ByteArray> {
        val publicParams = keyPair.public
        val privateParams = keyPair.private
        if (publicParams !is SLHDSAPublicKeyParameters || privateParams !is SLHDSAPrivateKeyParameters) {
            throw ReallyMeCryptoException.ProviderFailure()
        }

        val publicKey = publicParams.encoded
        val secretKey = privateParams.encoded
        if (publicKey.size != PUBLIC_KEY_LENGTH || secretKey.size != SECRET_KEY_LENGTH) {
            publicKey.fill(0)
            secretKey.fill(0)
            throw ReallyMeCryptoException.ProviderFailure()
        }
        return Pair(publicKey, secretKey)
    }

    private fun requireSlhDsaSha2_128s(algorithm: ReallyMeSignatureAlgorithm) {
        if (algorithm != ReallyMeSignatureAlgorithm.SLH_DSA_SHA2_128S) {
            throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }
    }

    private fun validateSeed(seed: ByteArray) {
        if (seed.size != KEYGEN_SEED_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }

    private fun validatePublicKey(publicKey: ByteArray) {
        if (publicKey.size != PUBLIC_KEY_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }

    private fun validateSecretKey(secretKey: ByteArray) {
        if (secretKey.size != SECRET_KEY_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }

    private fun validateSignature(signature: ByteArray) {
        if (signature.size != SIGNATURE_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }
}
