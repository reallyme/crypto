// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import java.math.BigInteger
import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.hpke.HPKE
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.math.ec.FixedPointCombMultiplier

private data class HpkeSuiteConfig(
    val kemId: Short,
    val aeadId: Short,
    val publicKeyLength: Int,
    val privateKeyLength: Int,
)

/**
 * RFC 9180 HPKE Base mode backed by BouncyCastle.
 *
 * The public package API always uses provider randomness for sender
 * encapsulation. The deterministic helper is internal and exists only so the
 * package tests can reproduce committed KATs from their encapsulation seed.
 */
public object ReallyMeHpke {
    private const val HPKE_AEAD_TAG_LENGTH: Int = 16
    private const val P256_PUBLIC_KEY_LENGTH: Int = 65
    private const val P256_PRIVATE_KEY_LENGTH: Int = 32
    private const val X25519_PUBLIC_KEY_LENGTH: Int = 32
    private const val X25519_PRIVATE_KEY_LENGTH: Int = 32

    private val p256Domain: ECDomainParameters =
        ECDomainParameters(SECNamedCurves.getByName("secp256r1"))

    public fun seal(
        suite: ReallyMeHpkeSuite,
        recipientPublicKey: ByteArray,
        info: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
    ): ReallyMeHpkeSealedMessage =
        sealWithOptionalEncapsulationKeyPair(
            suite,
            recipientPublicKey,
            info,
            aad,
            plaintext,
            null,
        )

    public fun open(
        suite: ReallyMeHpkeSuite,
        recipientSecretKey: ByteArray,
        encapsulatedKey: ByteArray,
        info: ByteArray,
        aad: ByteArray,
        ciphertext: ByteArray,
    ): ByteArray {
        val config = config(suite)
        validatePrivateKey(config, recipientSecretKey)
        validatePublicKey(config, encapsulatedKey)
        if (ciphertext.size < HPKE_AEAD_TAG_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }

        return try {
            val hpke = hpke(suite)
            val recipientPublicKey = deriveRecipientPublicKey(suite, recipientSecretKey)
            val keyPair = hpke.deserializePrivateKey(recipientSecretKey, recipientPublicKey)
            hpke.open(encapsulatedKey, keyPair, info, aad, ciphertext, null, null, null)
        } catch (_: IllegalArgumentException) {
            throw ReallyMeCryptoException.InvalidInput()
        } catch (_: InvalidCipherTextException) {
            throw ReallyMeCryptoException.AuthenticationFailed()
        }
    }

    internal fun sealDeterministicForTest(
        suite: ReallyMeHpkeSuite,
        recipientPublicKey: ByteArray,
        encapsulationSeed: ByteArray,
        info: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
    ): ReallyMeHpkeSealedMessage {
        val config = config(suite)
        if (encapsulationSeed.size != config.privateKeyLength) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        val senderKeyPair = try {
            hpke(suite).deriveKeyPair(encapsulationSeed)
        } catch (_: IllegalArgumentException) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        return sealWithOptionalEncapsulationKeyPair(
            suite,
            recipientPublicKey,
            info,
            aad,
            plaintext,
            senderKeyPair,
        )
    }

    private fun sealWithOptionalEncapsulationKeyPair(
        suite: ReallyMeHpkeSuite,
        recipientPublicKey: ByteArray,
        info: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
        senderKeyPair: AsymmetricCipherKeyPair?,
    ): ReallyMeHpkeSealedMessage {
        val config = config(suite)
        validatePublicKey(config, recipientPublicKey)

        return try {
            val hpke = hpke(suite)
            val publicKey = hpke.deserializePublicKey(recipientPublicKey)
            val sealed = if (senderKeyPair == null) {
                hpke.seal(publicKey, info, aad, plaintext, null, null, null)
            } else {
                val context = hpke.setupBaseS(publicKey, info, senderKeyPair)
                arrayOf(context.seal(aad, plaintext), context.encapsulation)
            }
            encodeSealedMessage(config, plaintext.size, sealed)
        } catch (_: IllegalArgumentException) {
            throw ReallyMeCryptoException.InvalidInput()
        } catch (_: InvalidCipherTextException) {
            throw ReallyMeCryptoException.ProviderFailure()
        }
    }

    private fun encodeSealedMessage(
        config: HpkeSuiteConfig,
        plaintextLength: Int,
        sealed: Array<ByteArray>,
    ): ReallyMeHpkeSealedMessage {
        if (sealed.size != 2) {
            throw ReallyMeCryptoException.ProviderFailure()
        }
        val ciphertext = sealed[0].copyOf()
        val encapsulatedKey = sealed[1].copyOf()
        val expectedCiphertextLength = checkedCiphertextLength(plaintextLength)
        if (
            expectedCiphertextLength == null ||
            encapsulatedKey.size != config.publicKeyLength ||
            ciphertext.size != expectedCiphertextLength
        ) {
            encapsulatedKey.fill(0)
            ciphertext.fill(0)
            throw ReallyMeCryptoException.ProviderFailure()
        }
        return ReallyMeHpkeSealedMessage(encapsulatedKey = encapsulatedKey, ciphertext = ciphertext)
    }

    private fun hpke(suite: ReallyMeHpkeSuite): HPKE {
        val config = config(suite)
        return HPKE(HPKE.mode_base, config.kemId, HPKE.kdf_HKDF_SHA256, config.aeadId)
    }

    private fun config(suite: ReallyMeHpkeSuite): HpkeSuiteConfig =
        when (suite) {
            ReallyMeHpkeSuite.DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_256_GCM ->
                HpkeSuiteConfig(HPKE.kem_P256_SHA256, HPKE.aead_AES_GCM256, P256_PUBLIC_KEY_LENGTH, P256_PRIVATE_KEY_LENGTH)
            ReallyMeHpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305 ->
                HpkeSuiteConfig(
                    HPKE.kem_X25519_SHA256,
                    HPKE.aead_CHACHA20_POLY1305,
                    X25519_PUBLIC_KEY_LENGTH,
                    X25519_PRIVATE_KEY_LENGTH,
                )
        }

    private fun deriveRecipientPublicKey(suite: ReallyMeHpkeSuite, secretKey: ByteArray): ByteArray =
        when (suite) {
            ReallyMeHpkeSuite.DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_256_GCM ->
                deriveP256PublicKey(secretKey)
            ReallyMeHpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305 ->
                ReallyMeX25519.derivePublicKey(secretKey)
        }

    private fun deriveP256PublicKey(secretKey: ByteArray): ByteArray {
        val scalar = BigInteger(1, secretKey)
        if (scalar.signum() <= 0 || scalar >= p256Domain.n) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        // Use the fixed-point comb multiplier (the same timing-conscious base
        // point multiplier BouncyCastle's ECDSASigner uses) rather than the
        // curve default, so deriving the recipient public key from its secret
        // key during `open` does not run variable-time on secret material.
        return FixedPointCombMultiplier().multiply(p256Domain.g, scalar).normalize().getEncoded(false)
    }

    private fun validatePublicKey(config: HpkeSuiteConfig, publicKey: ByteArray) {
        if (publicKey.size != config.publicKeyLength) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }

    private fun validatePrivateKey(config: HpkeSuiteConfig, privateKey: ByteArray) {
        if (privateKey.size != config.privateKeyLength) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }

    private fun checkedCiphertextLength(plaintextLength: Int): Int? {
        if (plaintextLength > Int.MAX_VALUE - HPKE_AEAD_TAG_LENGTH) {
            return null
        }
        return plaintextLength + HPKE_AEAD_TAG_LENGTH
    }
}
