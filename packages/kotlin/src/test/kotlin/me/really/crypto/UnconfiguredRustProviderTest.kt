// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

class UnconfiguredRustProviderTest {
    @Test
    fun pCurveAgreementRequiresRustWithoutFallback() {
        for ((algorithm, publicLength, secretLength) in listOf(
            Triple(ReallyMeKeyAgreementAlgorithm.P256_ECDH, 33, 32),
            Triple(ReallyMeKeyAgreementAlgorithm.P384_ECDH, 49, 48),
            Triple(ReallyMeKeyAgreementAlgorithm.P521_ECDH, 67, 66),
        )) {
            val publicKey = ByteArray(publicLength).also { it[0] = 0x02 }
            val secretKey = ByteArray(secretLength).also { it[it.lastIndex] = 1 }
            try {
                assertFailsWith<ReallyMeCryptoException.UnsupportedAlgorithm> {
                    ReallyMeRustKeyAgreement.generateKeyPair(algorithm)
                }
                assertFailsWith<ReallyMeCryptoException.UnsupportedAlgorithm> {
                    ReallyMeCrypto.deriveKeyAgreementKeyPair(algorithm, secretKey)
                }
                assertFailsWith<ReallyMeCryptoException.UnsupportedAlgorithm> {
                    ReallyMeCrypto.deriveSharedSecret(algorithm, publicKey, secretKey)
                }
            } finally {
                secretKey.fill(0)
            }
        }
    }

    @Test
    fun unconfiguredRustRoutesReturnProviderFailure() {
        val key = ByteArray(ReallyMeRustAead.KEY_LENGTH)
        val nonce = ByteArray(ReallyMeRustAead.AES_GCM_SIV_NONCE_LENGTH)
        val empty = ByteArray(0)
        assertFailsWith<ReallyMeCryptoException.ProviderFailure> {
            ReallyMeCrypto.seal(ReallyMeAeadAlgorithm.AES_256_GCM_SIV, key, nonce, empty, empty)
        }
        assertFailsWith<ReallyMeCryptoException.ProviderFailure> {
            ReallyMeCrypto.open(
                ReallyMeAeadAlgorithm.AES_256_GCM_SIV,
                key,
                nonce,
                empty,
                ByteArray(ReallyMeRustAead.TAG_LENGTH),
            )
        }
        assertFailsWith<ReallyMeCryptoException.ProviderFailure> {
            ReallyMeCrypto.processOperationResponse(empty)
        }
        assertFailsWith<ReallyMeCryptoException.ProviderFailure> {
            ReallyMeCrypto.processOperationResponseJson("{}".encodeToByteArray())
        }
        assertEquals(
            32,
            ReallyMeCrypto.hash(ReallyMeHashAlgorithm.SHA2_256, empty).size,
        )
    }

    @Test
    fun protocolsAndPostQuantumAlgorithmsNeverFallBackWithoutRust() {
        for (algorithm in ReallyMeKemAlgorithm.entries) {
            assertFailsWith<ReallyMeCryptoException.UnsupportedAlgorithm> {
                ReallyMeCrypto.generateKemKeyPair(algorithm)
            }
        }
        for (algorithm in listOf(
            ReallyMeSignatureAlgorithm.ML_DSA_44,
            ReallyMeSignatureAlgorithm.ML_DSA_65,
            ReallyMeSignatureAlgorithm.ML_DSA_87,
            ReallyMeSignatureAlgorithm.SLH_DSA_SHA2_128S,
        )) {
            assertFailsWith<ReallyMeCryptoException.UnsupportedAlgorithm> {
                ReallyMeCrypto.generateKeyPair(algorithm)
            }
        }
        for (suite in ReallyMeHpkeSuite.entries) {
            val publicLength = if (suite == ReallyMeHpkeSuite.DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_256_GCM) 65 else 32
            assertFailsWith<ReallyMeCryptoException.UnsupportedAlgorithm> {
                ReallyMeHpke.seal(suite, ByteArray(publicLength), ByteArray(0), ByteArray(0), ByteArray(0))
            }
        }
    }

    @Test
    fun nativeUnsupportedAlgorithmStatusRetainsItsTypedError() {
        assertIs<ReallyMeCryptoException.UnsupportedAlgorithm>(
            ReallyMeNativeStatus.UNSUPPORTED_ALGORITHM.toFacadeError(),
        )
    }
}
