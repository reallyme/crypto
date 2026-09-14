// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto

import java.math.BigInteger
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFileAttributeView
import java.nio.file.attribute.PosixFilePermission
import java.security.SecureRandom
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import me.really.crypto.proto.ReallyMeCryptoProtoAdapters
import me.really.crypto.proto.ReallyMeCryptoWireErrorBranch
import me.really.crypto.v1.CryptoErrorReason
import me.really.crypto.v1.CryptoOperationResponse
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.junit.jupiter.api.Assumptions.assumeTrue

class ReallyMeCryptoPostQuantumTest : ReallyMeCryptoTestSupport() {
    @Test
    fun mlKemVectorsDecapsulateAndRejectImplicitly() {
        validateMlKemVector("mlkem512.json", ReallyMeKemAlgorithm.ML_KEM_512)
        validateMlKemVector("mlkem768.json", ReallyMeKemAlgorithm.ML_KEM_768)
        validateMlKemVector("mlkem1024.json", ReallyMeKemAlgorithm.ML_KEM_1024)
    }

    @Test
    fun mlKemGenerateAndEncapsulateRoundTrip() {
        val keyPair = ReallyMeCrypto.generateKemKeyPair(ReallyMeKemAlgorithm.ML_KEM_768)
        assertEquals(1_184, keyPair.publicKey.size)
        assertEquals(ReallyMeMlKem.SECRET_KEY_LENGTH, keyPair.secretKey.size)

        val encapsulation = ReallyMeCrypto.encapsulate(ReallyMeKemAlgorithm.ML_KEM_768, keyPair.publicKey)
        assertEquals(ReallyMeMlKem.SHARED_SECRET_LENGTH, encapsulation.sharedSecret.size)
        assertEquals(1_088, encapsulation.ciphertext.size)
        assertContentEquals(
            encapsulation.sharedSecret,
            ReallyMeCrypto.decapsulate(
                ReallyMeKemAlgorithm.ML_KEM_768,
                encapsulation.ciphertext,
                keyPair.secretKey,
            ),
        )
    }

    @Test
    fun mlKemDerivesKeyPairAndDeterministicEncapsulation() {
        val secretKey = ByteArray(ReallyMeMlKem.SECRET_KEY_LENGTH) { 0x21.toByte() }
        val randomness = ByteArray(ReallyMeMlKem.ENCAPSULATION_RANDOMNESS_LENGTH) { 0x22.toByte() }

        val keyPair = ReallyMeCrypto.deriveKemKeyPair(ReallyMeKemAlgorithm.ML_KEM_768, secretKey)
        val repeatedKeyPair = ReallyMeCrypto.deriveKemKeyPair(ReallyMeKemAlgorithm.ML_KEM_768, secretKey)

        assertContentEquals(keyPair.publicKey, repeatedKeyPair.publicKey)
        assertContentEquals(secretKey, keyPair.secretKey)

        val encapsulation = ReallyMeCrypto.encapsulateDeterministicForTest(
            ReallyMeKemAlgorithm.ML_KEM_768,
            keyPair.publicKey,
            randomness,
        )
        val repeatedEncapsulation = ReallyMeCrypto.encapsulateDeterministicForTest(
            ReallyMeKemAlgorithm.ML_KEM_768,
            keyPair.publicKey,
            randomness,
        )

        assertContentEquals(encapsulation.ciphertext, repeatedEncapsulation.ciphertext)
        assertContentEquals(encapsulation.sharedSecret, repeatedEncapsulation.sharedSecret)
        assertContentEquals(
            encapsulation.sharedSecret,
            ReallyMeCrypto.decapsulate(
                ReallyMeKemAlgorithm.ML_KEM_768,
                encapsulation.ciphertext,
                keyPair.secretKey,
            ),
        )
    }

    @Test
    fun mlKemRejectsMalformedInputs() {
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.encapsulate(ReallyMeKemAlgorithm.ML_KEM_512, ByteArray(799))
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.decapsulate(ReallyMeKemAlgorithm.ML_KEM_512, ByteArray(768), ByteArray(63))
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.deriveKemKeyPair(ReallyMeKemAlgorithm.ML_KEM_512, ByteArray(63))
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.encapsulateDeterministicForTest(
                ReallyMeKemAlgorithm.ML_KEM_512,
                ByteArray(800),
                ByteArray(31),
            )
        }
    }

    @Test
    fun xWingVectorsDeriveEncapsulateAndDecapsulate() {
        validateXWingVector("x_wing_768", ReallyMeKemAlgorithm.X_WING_768)
    }

    @Test
    fun xWingGenerateAndEncapsulateRoundTrip() {
        val keyPair = ReallyMeCrypto.generateKemKeyPair(ReallyMeKemAlgorithm.X_WING_768)
        val encapsulation = ReallyMeCrypto.encapsulate(ReallyMeKemAlgorithm.X_WING_768, keyPair.publicKey)

        assertEquals(1_216, keyPair.publicKey.size)
        assertEquals(ReallyMeXWing.SECRET_KEY_LENGTH, keyPair.secretKey.size)
        assertEquals(ReallyMeXWing.SHARED_SECRET_LENGTH, encapsulation.sharedSecret.size)
        assertEquals(1_120, encapsulation.ciphertext.size)
        assertContentEquals(
            encapsulation.sharedSecret,
            ReallyMeCrypto.decapsulate(
                ReallyMeKemAlgorithm.X_WING_768,
                encapsulation.ciphertext,
                keyPair.secretKey,
            ),
        )
    }

    @Test
    fun xWingRejectsMalformedInputs() {
        val publicKey = vectorCaseField("x_wing.json", "x_wing_768", "public_key")
        val ciphertext = vectorCaseField("x_wing.json", "x_wing_768", "ciphertext")
        val secretKey = vectorCaseField("x_wing.json", "x_wing_768", "secret_key")

        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeXWing.derivePublicKey(ReallyMeKemAlgorithm.X_WING_768, ByteArray(31))
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.encapsulate(ReallyMeKemAlgorithm.X_WING_768, publicKey.copyOf(publicKey.size - 1))
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.decapsulate(
                ReallyMeKemAlgorithm.X_WING_768,
                ciphertext.copyOf(ciphertext.size - 1),
                secretKey,
            )
        }
    }

    @Test
    fun xWingLowOrderDecapsulationMatchesRustAndEncapsulationRejects() {
        val secretKey = vectorCaseField("x_wing.json", "x_wing_768", "secret_key")
        val publicKey = vectorCaseField("x_wing.json", "x_wing_768", "public_key")
        val encapsulationSeed = vectorCaseField("x_wing.json", "x_wing_768", "encaps_seed")
        val ciphertext = vectorCaseField("x_wing.json", "x_wing_768", "ciphertext")
        val orderEightPoint = bytes(
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"
        )
        // These expected secrets are pinned by the matching Rust primitive
        // test. Sharing the KAT outcomes makes an adversarial, length-valid
        // ciphertext produce byte-for-byte identical results across lanes.
        val lowOrderCases = listOf(
            Pair(
                ByteArray(32),
                bytes("a293a5fbf5b7c27782ab8dfad8c05ac6aab9d960d2b8c3dbe2887f6e1911eb0d"),
            ),
            Pair(
                orderEightPoint,
                bytes("dbbda70c3a15ffddf213d8abd918c30ffff602d67fd67e65a01bf0404bf05a78"),
            ),
        )

        for ((lowOrderPoint, expectedSharedSecret) in lowOrderCases) {
            val adversarialCiphertext = ciphertext.copyOf()
            lowOrderPoint.copyInto(
                adversarialCiphertext,
                destinationOffset = adversarialCiphertext.size - lowOrderPoint.size,
            )
            assertContentEquals(
                expectedSharedSecret,
                ReallyMeCrypto.decapsulate(
                    ReallyMeKemAlgorithm.X_WING_768,
                    adversarialCiphertext,
                    secretKey,
                ),
            )

            val nonContributoryPublicKey = publicKey.copyOf()
            lowOrderPoint.copyInto(
                nonContributoryPublicKey,
                destinationOffset = nonContributoryPublicKey.size - lowOrderPoint.size,
            )
            assertFailsWith<ReallyMeCryptoException.InvalidInput> {
                ReallyMeXWing.encapsulateDeterministicForTest(
                    ReallyMeKemAlgorithm.X_WING_768,
                    nonContributoryPublicKey,
                    encapsulationSeed,
                )
            }
        }
    }

    @Test
    fun mlDsaVectorsVerifyCommittedSignatures() {
        validateMlDsaVector("ml_dsa_44.json", ReallyMeSignatureAlgorithm.ML_DSA_44)
        validateMlDsaVector("ml_dsa_65.json", ReallyMeSignatureAlgorithm.ML_DSA_65)
        validateMlDsaVector("ml_dsa_87.json", ReallyMeSignatureAlgorithm.ML_DSA_87)
    }

    @Test
    fun mlDsaFacadeSignsCommittedVectorAndGeneratesKeys() {
        val secretSeed = vectorField("ml_dsa_44.json", "secret_key")
        val message = vectorField("ml_dsa_44.json", "message")
        val signature = vectorField("ml_dsa_44.json", "signature")

        assertContentEquals(signature, ReallyMeCrypto.sign(ReallyMeSignatureAlgorithm.ML_DSA_44, message, secretSeed))

        val generated = ReallyMeCrypto.generateKeyPair(ReallyMeSignatureAlgorithm.ML_DSA_44)
        assertEquals(1_312, generated.publicKey.size)
        assertEquals(ReallyMeMlDsa.SECRET_SEED_LENGTH, generated.secretKey.size)
    }

    @Test
    fun mlDsaDerivesKeyPairFromSuppliedSeed() {
        val secretSeed = ByteArray(ReallyMeMlDsa.SECRET_SEED_LENGTH) { 0x31.toByte() }
        val keyPair = ReallyMeCrypto.deriveMlDsaKeyPair(ReallyMeSignatureAlgorithm.ML_DSA_65, secretSeed)
        val repeatedKeyPair = ReallyMeCrypto.deriveMlDsaKeyPair(ReallyMeSignatureAlgorithm.ML_DSA_65, secretSeed)

        assertEquals(1_952, keyPair.publicKey.size)
        assertContentEquals(keyPair.publicKey, repeatedKeyPair.publicKey)
        assertContentEquals(secretSeed, keyPair.secretKey)
    }

    @Test
    fun mlDsaRejectsMalformedInputs() {
        val publicKey = vectorField("ml_dsa_44.json", "public_key")
        val signature = vectorField("ml_dsa_44.json", "signature")
        val message = vectorField("ml_dsa_44.json", "message")

        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeMlDsa.derivePublicKey(ReallyMeSignatureAlgorithm.ML_DSA_44, ByteArray(31))
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.deriveMlDsaKeyPair(ReallyMeSignatureAlgorithm.ML_DSA_44, ByteArray(31))
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.verify(
                ReallyMeSignatureAlgorithm.ML_DSA_44,
                signature,
                message,
                publicKey.copyOf(publicKey.size - 1),
            )
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.verify(
                ReallyMeSignatureAlgorithm.ML_DSA_44,
                signature.copyOf(signature.size - 1),
                message,
                publicKey,
            )
        }
    }

    @Test
    fun slhDsaVectorDerivesSignsAndVerifies() {
        val skSeed = vectorField("slh_dsa_sha2_128s.json", "keygen_sk_seed")
        val skPrf = vectorField("slh_dsa_sha2_128s.json", "keygen_sk_prf")
        val pkSeed = vectorField("slh_dsa_sha2_128s.json", "keygen_pk_seed")
        val publicKey = vectorField("slh_dsa_sha2_128s.json", "public_key")
        val secretKey = vectorField("slh_dsa_sha2_128s.json", "secret_key")
        val message = vectorField("slh_dsa_sha2_128s.json", "message")
        val signature = vectorField("slh_dsa_sha2_128s.json", "signature")
        val derivedKeyPair = ReallyMeSlhDsa.deriveKeyPair(
            ReallyMeSignatureAlgorithm.SLH_DSA_SHA2_128S,
            skSeed,
            skPrf,
            pkSeed,
        )

        assertContentEquals(publicKey, derivedKeyPair.first)
        assertContentEquals(secretKey, derivedKeyPair.second)
        assertContentEquals(
            signature,
            ReallyMeCrypto.sign(
                ReallyMeSignatureAlgorithm.SLH_DSA_SHA2_128S,
                message,
                secretKey,
            ),
        )
        ReallyMeCrypto.verify(
            ReallyMeSignatureAlgorithm.SLH_DSA_SHA2_128S,
            signature,
            message,
            publicKey,
        )

        val tamperedSignature = signature.copyOf()
        tamperedSignature[0] = (tamperedSignature[0].toInt() xor 0x01).toByte()
        assertFailsWith<ReallyMeCryptoException.InvalidSignature> {
            ReallyMeCrypto.verify(
                ReallyMeSignatureAlgorithm.SLH_DSA_SHA2_128S,
                tamperedSignature,
                message,
                publicKey,
            )
        }
    }

    @Test
    fun slhDsaGenerateKeyPairAndRejectMalformedInputs() {
        val keyPair = ReallyMeCrypto.generateKeyPair(ReallyMeSignatureAlgorithm.SLH_DSA_SHA2_128S)
        val message = "ReallyMe SLH-DSA generated key smoke test".toByteArray()
        val signature = ReallyMeCrypto.sign(
            ReallyMeSignatureAlgorithm.SLH_DSA_SHA2_128S,
            message,
            keyPair.secretKey,
        )

        assertEquals(ReallyMeSlhDsa.PUBLIC_KEY_LENGTH, keyPair.publicKey.size)
        assertEquals(ReallyMeSlhDsa.SECRET_KEY_LENGTH, keyPair.secretKey.size)
        assertEquals(ReallyMeSlhDsa.SIGNATURE_LENGTH, signature.size)
        ReallyMeCrypto.verify(
            ReallyMeSignatureAlgorithm.SLH_DSA_SHA2_128S,
            signature,
            message,
            keyPair.publicKey,
        )
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeSlhDsa.deriveKeyPair(
                ReallyMeSignatureAlgorithm.SLH_DSA_SHA2_128S,
                ByteArray(15),
                ByteArray(16),
                ByteArray(16),
            )
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.sign(
                ReallyMeSignatureAlgorithm.SLH_DSA_SHA2_128S,
                message,
                ByteArray(ReallyMeSlhDsa.SECRET_KEY_LENGTH - 1),
            )
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.verify(
                ReallyMeSignatureAlgorithm.SLH_DSA_SHA2_128S,
                signature.copyOf(signature.size - 1),
                message,
                keyPair.publicKey,
            )
        }
    }

    @Test
    fun hpkeVectorsOpenAndDeterministicallySeal() {
        validateHpkeVector(
            "p256_sha256_aes256gcm",
            ReallyMeHpkeSuite.DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_256_GCM,
        )
        validateHpkeVector(
            "x25519_sha256_chacha20poly1305",
            ReallyMeHpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305,
        )
    }

    @Test
    fun hpkeSealRoundTripsAndRejectsMalformedInputs() {
        val publicKey = vectorCaseField("hpke.json", "x25519_sha256_chacha20poly1305", "recipient_public_key")
        val privateKey = vectorCaseField("hpke.json", "x25519_sha256_chacha20poly1305", "recipient_secret_key")
        val info = "reallyme-hpke-info".toByteArray()
        val aad = "reallyme-hpke-aad".toByteArray()
        val plaintext = "reallyme hpke package smoke test".toByteArray()
        val sealed = ReallyMeCrypto.sealHpke(
            ReallyMeHpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305,
            publicKey,
            info,
            aad,
            plaintext,
        )

        assertEquals(publicKey.size, sealed.encapsulatedKey.size)
        assertEquals(plaintext.size + 16, sealed.ciphertext.size)
        assertContentEquals(
            plaintext,
            ReallyMeCrypto.openHpke(
                ReallyMeHpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305,
                privateKey,
                sealed.encapsulatedKey,
                info,
                aad,
                sealed.ciphertext,
            ),
        )
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.sealHpke(
                ReallyMeHpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305,
                ByteArray(publicKey.size - 1),
                info,
                aad,
                plaintext,
            )
        }

        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.sealHpke(
                ReallyMeHpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305,
                ByteArray(32),
                info,
                aad,
                plaintext,
            )
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.openHpke(
                ReallyMeHpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305,
                privateKey,
                ByteArray(32),
                info,
                aad,
                sealed.ciphertext,
            )
        }
    }

    private fun validateMlKemVector(vectorName: String, algorithm: ReallyMeKemAlgorithm) {
        val publicKey = vectorField(vectorName, "public_key")
        val secretKey = vectorField(vectorName, "secret_key")
        val ciphertext = vectorField(vectorName, "ciphertext")
        val sharedSecret = vectorField(vectorName, "shared_secret")
        val tamperedCiphertext = vectorField(vectorName, "tampered_ciphertext")
        val tamperedSharedSecret = vectorField(vectorName, "tampered_shared_secret")

        assertContentEquals(publicKey, ReallyMeMlKem.derivePublicKey(algorithm, secretKey))
        assertContentEquals(sharedSecret, ReallyMeCrypto.decapsulate(algorithm, ciphertext, secretKey))
        assertContentEquals(tamperedSharedSecret, ReallyMeCrypto.decapsulate(algorithm, tamperedCiphertext, secretKey))
    }

    private fun validateXWingVector(caseName: String, algorithm: ReallyMeKemAlgorithm) {
        val secretKey = vectorCaseField("x_wing.json", caseName, "secret_key")
        val publicKey = vectorCaseField("x_wing.json", caseName, "public_key")
        val encapsulationSeed = vectorCaseField("x_wing.json", caseName, "encaps_seed")
        val ciphertext = vectorCaseField("x_wing.json", caseName, "ciphertext")
        val sharedSecret = vectorCaseField("x_wing.json", caseName, "shared_secret")
        val encapsulation = ReallyMeXWing.encapsulateDeterministicForTest(
            algorithm,
            publicKey,
            encapsulationSeed,
        )

        assertContentEquals(publicKey, ReallyMeXWing.derivePublicKey(algorithm, secretKey))
        assertContentEquals(ciphertext, encapsulation.ciphertext)
        assertContentEquals(sharedSecret, encapsulation.sharedSecret)
        assertContentEquals(sharedSecret, ReallyMeCrypto.decapsulate(algorithm, ciphertext, secretKey))
    }

    private fun validateMlDsaVector(vectorName: String, algorithm: ReallyMeSignatureAlgorithm) {
        val secretSeed = vectorField(vectorName, "secret_key")
        val publicKey = vectorField(vectorName, "public_key")
        val message = vectorField(vectorName, "message")
        val signature = vectorField(vectorName, "signature")
        val tamperedSignature = signature.copyOf()
        tamperedSignature[0] = (tamperedSignature[0].toInt() xor 0x01).toByte()

        assertContentEquals(publicKey, ReallyMeMlDsa.derivePublicKey(algorithm, secretSeed))
        assertContentEquals(signature, ReallyMeCrypto.sign(algorithm, message, secretSeed))
        ReallyMeCrypto.verify(algorithm, signature, message, publicKey)
        assertFailsWith<ReallyMeCryptoException.InvalidSignature> {
            ReallyMeCrypto.verify(algorithm, tamperedSignature, message, publicKey)
        }
    }

    private fun validateHpkeVector(caseName: String, suite: ReallyMeHpkeSuite) {
        val recipientSecretKey = vectorCaseField("hpke.json", caseName, "recipient_secret_key")
        val recipientPublicKey = vectorCaseField("hpke.json", caseName, "recipient_public_key")
        val encapsulationSeed = vectorCaseField("hpke.json", caseName, "encaps_seed")
        val info = vectorCaseField("hpke.json", caseName, "info")
        val aad = vectorCaseField("hpke.json", caseName, "aad")
        val plaintext = vectorCaseField("hpke.json", caseName, "plaintext")
        val encapsulatedKey = vectorCaseField("hpke.json", caseName, "encapsulated_key")
        val ciphertext = vectorCaseField("hpke.json", caseName, "ciphertext")
        val tamperedCiphertext = vectorCaseField("hpke.json", caseName, "tampered_ciphertext")
        val sealed = ReallyMeHpke.sealDeterministicForTest(
            suite,
            recipientPublicKey,
            encapsulationSeed,
            info,
            aad,
            plaintext,
        )

        assertContentEquals(encapsulatedKey, sealed.encapsulatedKey)
        assertContentEquals(ciphertext, sealed.ciphertext)
        assertContentEquals(
            plaintext,
            ReallyMeCrypto.openHpke(suite, recipientSecretKey, encapsulatedKey, info, aad, ciphertext),
        )
        assertFailsWith<ReallyMeCryptoException.AuthenticationFailed> {
            ReallyMeCrypto.openHpke(suite, recipientSecretKey, encapsulatedKey, info, aad, tamperedCiphertext)
        }
    }
}
