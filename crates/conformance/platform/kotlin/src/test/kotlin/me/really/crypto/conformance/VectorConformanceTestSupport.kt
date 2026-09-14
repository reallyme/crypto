// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto.conformance

import fr.acinq.secp256k1.Secp256k1
import java.math.BigInteger
import java.nio.file.Files
import java.security.GeneralSecurityException
import java.util.Arrays
import java.security.MessageDigest
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.security.spec.RSAPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.Digest
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.digests.SHA384Digest
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.digests.SHA3Digest
import org.bouncycastle.crypto.digests.SHAKEDigest
import org.bouncycastle.crypto.kems.MLKEMExtractor
import org.bouncycastle.crypto.kems.MLKEMGenerator
import org.bouncycastle.crypto.macs.KMAC
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.params.MLDSAParameters
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters
import org.bouncycastle.crypto.params.MLKEMParameters
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters
import org.bouncycastle.crypto.signers.MLDSASigner
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import kotlin.io.path.Path
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

internal abstract class VectorConformanceTestSupport {
    protected fun validateP256Shape() {
        val vector = JsonObject.parse(readVector("p256.json"))
        val secretKey = Base64Url.decode(vector.requiredString("secret_key"))
        val compressedPublicKey = Base64Url.decode(vector.requiredString("public_key_compressed"))
        val uncompressedPublicKey = Base64Url.decode(vector.requiredString("public_key_uncompressed"))
        val peerSecretKey = Base64Url.decode(vector.requiredString("peer_secret_key"))
        val peerCompressedPublicKey = Base64Url.decode(vector.requiredString("peer_public_key_compressed"))
        val peerUncompressedPublicKey = Base64Url.decode(vector.requiredString("peer_public_key_uncompressed"))
        val sharedSecret = Base64Url.decode(vector.requiredString("shared_secret"))

        assertEquals(32, secretKey.size)
        assertEquals(33, compressedPublicKey.size)
        assertTrue(compressedPublicKey[0] == 0x02.toByte() || compressedPublicKey[0] == 0x03.toByte())
        assertEquals(65, uncompressedPublicKey.size)
        assertEquals(0x04.toByte(), uncompressedPublicKey[0])
        assertEquals(32, peerSecretKey.size)
        assertEquals(33, peerCompressedPublicKey.size)
        assertTrue(peerCompressedPublicKey[0] == 0x02.toByte() || peerCompressedPublicKey[0] == 0x03.toByte())
        assertEquals(65, peerUncompressedPublicKey.size)
        assertEquals(0x04.toByte(), peerUncompressedPublicKey[0])
        assertEquals(32, sharedSecret.size)
        secretKey.fill(0)
        peerSecretKey.fill(0)
        sharedSecret.fill(0)
    }

    protected fun validateSec1EcdsaShape(
        vectorName: String,
        secretKeyLength: Int,
        compressedLength: Int,
        uncompressedLength: Int,
    ) {
        val vector = JsonObject.parse(readVector(vectorName))
        val secretKey = Base64Url.decode(vector.requiredString("secret_key"))
        val compressedPublicKey = Base64Url.decode(vector.requiredString("public_key_compressed"))
        val uncompressedPublicKey = Base64Url.decode(vector.requiredString("public_key_uncompressed"))
        val message = Base64Url.decode(vector.requiredString("message"))
        val signature = Base64Url.decode(vector.requiredString("signature_der"))

        assertEquals(secretKeyLength, secretKey.size)
        assertEquals(compressedLength, compressedPublicKey.size)
        assertTrue(compressedPublicKey[0] == 0x02.toByte() || compressedPublicKey[0] == 0x03.toByte())
        assertEquals(uncompressedLength, uncompressedPublicKey.size)
        assertEquals(0x04.toByte(), uncompressedPublicKey[0])
        assertTrue(message.isNotEmpty())
        assertTrue(signature.isNotEmpty())
        secretKey.fill(0)
    }

    protected fun validateEd25519Shape() {
        val vector = JsonObject.parse(readVector("ed25519.json"))
        val secretKey = Base64Url.decode(vector.requiredString("secret_key"))
        val publicKey = Base64Url.decode(vector.requiredString("public_key"))
        val message = Base64Url.decode(vector.requiredString("message"))
        val signature = Base64Url.decode(vector.requiredString("signature"))

        assertEquals(32, secretKey.size)
        assertEquals(32, publicKey.size)
        assertTrue(message.isNotEmpty())
        assertEquals(64, signature.size)
        secretKey.fill(0)
    }

    protected fun validateSecp256k1Shape() {
        val vector = JsonObject.parse(readVector("secp256k1.json"))
        val secretKey = Base64Url.decode(vector.requiredString("secret_key"))
        val compressedPublicKey = Base64Url.decode(vector.requiredString("public_key_compressed"))

        assertEquals(32, secretKey.size)
        assertEquals(33, compressedPublicKey.size)
        assertTrue(compressedPublicKey[0] == 0x02.toByte() || compressedPublicKey[0] == 0x03.toByte())
        secretKey.fill(0)
    }

    protected fun validateBip340SchnorrShape() {
        val vector = JsonObject.parse(readVector("bip340_schnorr.json"))
        val secretKey = Base64Url.decode(vector.requiredString("secret_key"))
        val publicKey = Base64Url.decode(vector.requiredString("public_key_xonly"))
        val message = Base64Url.decode(vector.requiredString("message"))
        val auxRand = Base64Url.decode(vector.requiredString("aux_rand"))
        val signature = Base64Url.decode(vector.requiredString("signature"))

        try {
            assertEquals("x-only", vector.requiredString("public_key_format"))
            assertEquals(32, secretKey.size)
            assertEquals(32, publicKey.size)
            assertEquals(32, message.size)
            assertEquals(32, auxRand.size)
            assertEquals(64, signature.size)
        } finally {
            secretKey.fill(0)
            auxRand.fill(0)
        }
    }

    protected fun validateRsaShape() {
        val vector = JsonObject.parse(readVector("rsa.json"))
        val publicKey = Base64Url.decode(vector.requiredString("public_key_der"))
        val message = Base64Url.decode(vector.requiredString("message"))
        val pkcs1Sha1Signature = Base64Url.decode(vector.requiredString("pkcs1v15_sha1_signature"))
        val pkcs1Sha256Signature = Base64Url.decode(vector.requiredString("pkcs1v15_sha256_signature"))
        val pssSignature = Base64Url.decode(vector.requiredString("pss_sha256_mgf1_sha256_signature"))

        assertEquals("PKCS1-DER-RSAPublicKey", vector.requiredString("key_format"))
        assertEquals(0x30.toByte(), publicKey[0])
        assertTrue(message.isNotEmpty())
        assertEquals(256, pkcs1Sha1Signature.size)
        assertEquals(256, pkcs1Sha256Signature.size)
        assertEquals(32, vector.requiredLong("pss_sha256_mgf1_sha256_salt_len").toInt())
        assertEquals(256, pssSignature.size)
    }

    protected fun validateX25519Shape() {
        val vector = JsonObject.parse(readVector("x25519.json"))
        val secretKey = Base64Url.decode(vector.requiredString("secret_key"))
        val publicKey = Base64Url.decode(vector.requiredString("public_key"))
        val peerSecretKey = Base64Url.decode(vector.requiredString("peer_secret_key"))
        val peerPublicKey = Base64Url.decode(vector.requiredString("peer_public_key"))
        val sharedSecret = Base64Url.decode(vector.requiredString("shared_secret"))

        assertEquals(32, secretKey.size)
        assertEquals(32, publicKey.size)
        assertEquals(32, peerSecretKey.size)
        assertEquals(32, peerPublicKey.size)
        assertEquals(32, sharedSecret.size)
        secretKey.fill(0)
        peerSecretKey.fill(0)
    }

    protected fun validateMlDsaShape(vectorName: String, publicKeyLength: Int, signatureLength: Int) {
        val vector = JsonObject.parse(readVector(vectorName))
        val secretKey = Base64Url.decode(vector.requiredString("secret_key"))
        val publicKey = Base64Url.decode(vector.requiredString("public_key"))
        val signature = Base64Url.decode(vector.requiredString("signature"))

        assertEquals("fips-204-seed", vector.requiredString("secret_key_format"))
        assertEquals(32, secretKey.size)
        assertEquals(publicKeyLength, publicKey.size)
        assertEquals(publicKeyLength, vector.requiredLong("public_key_length").toInt())
        assertEquals(signatureLength, signature.size)
        secretKey.fill(0)
    }

    protected fun validateSlhDsaShape() {
        val vector = JsonObject.parse(readVector("slh_dsa_sha2_128s.json"))
        val secretKey = Base64Url.decode(vector.requiredString("secret_key"))
        val publicKey = Base64Url.decode(vector.requiredString("public_key"))
        val skSeed = Base64Url.decode(vector.requiredString("keygen_sk_seed"))
        val skPrf = Base64Url.decode(vector.requiredString("keygen_sk_prf"))
        val pkSeed = Base64Url.decode(vector.requiredString("keygen_pk_seed"))
        val signature = Base64Url.decode(vector.requiredString("signature"))

        assertEquals("fips-205-serialized-secret-key", vector.requiredString("secret_key_format"))
        assertEquals(32, publicKey.size)
        assertEquals(64, secretKey.size)
        assertEquals(16, skSeed.size)
        assertEquals(16, skPrf.size)
        assertEquals(16, pkSeed.size)
        assertEquals(7_856, signature.size)
        assertEquals(publicKey.size, vector.requiredLong("public_key_length").toInt())
        assertEquals(secretKey.size, vector.requiredLong("secret_key_length").toInt())
        assertEquals(signature.size, vector.requiredLong("signature_length").toInt())
        secretKey.fill(0)
        skSeed.fill(0)
        skPrf.fill(0)
        pkSeed.fill(0)
    }

    protected fun validateMlKemShape(vectorName: String, publicKeyLength: Int, secretKeyLength: Int) {
        val vector = JsonObject.parse(readVector(vectorName))
        val secretKey = Base64Url.decode(vector.requiredString("secret_key"))
        val publicKey = Base64Url.decode(vector.requiredString("public_key"))

        assertEquals("fips-203-seed", vector.requiredString("secret_key_format"))
        assertEquals(secretKeyLength, secretKey.size)
        assertEquals(publicKeyLength, publicKey.size)
        assertEquals(publicKeyLength, vector.requiredLong("public_key_length").toInt())
        secretKey.fill(0)
    }

    protected fun validateXWingShape() {
        val vectors = JsonObject.parse(readVector("x_wing.json"))
        validateXWingCase(vectors.requiredObject("x_wing_768"), publicKeyLength = 1_216, ciphertextLength = 1_120)
    }

    protected fun validateXWingCase(vector: JsonObject, publicKeyLength: Int, ciphertextLength: Int) {
        val secretKey = Base64Url.decode(vector.requiredString("secret_key"))
        val publicKey = Base64Url.decode(vector.requiredString("public_key"))
        val encapsSeed = Base64Url.decode(vector.requiredString("encaps_seed"))
        val ciphertext = Base64Url.decode(vector.requiredString("ciphertext"))
        val sharedSecret = Base64Url.decode(vector.requiredString("shared_secret"))

        assertEquals("x-wing-seed", vector.requiredString("secret_key_format"))
        assertEquals(32, secretKey.size)
        assertEquals(publicKeyLength, publicKey.size)
        assertEquals(publicKeyLength, vector.requiredLong("public_key_length").toInt())
        assertEquals(64, encapsSeed.size)
        assertEquals(ciphertextLength, ciphertext.size)
        assertEquals(ciphertextLength, vector.requiredLong("ciphertext_length").toInt())
        assertEquals(32, sharedSecret.size)
        secretKey.fill(0)
        encapsSeed.fill(0)
    }

    protected fun validateHpkeShape() {
        val vectors = JsonObject.parse(readVector("hpke.json"))
        validateHpkeCase(
            vectors.requiredObject("p256_sha256_aes256gcm"),
            kemId = 0x0010,
            kdfId = 0x0001,
            aeadId = 0x0002,
            secretKeyLength = 32,
            publicKeyLength = 65,
            encapsulatedKeyLength = 65,
        )
        validateHpkeCase(
            vectors.requiredObject("x25519_sha256_chacha20poly1305"),
            kemId = 0x0020,
            kdfId = 0x0001,
            aeadId = 0x0003,
            secretKeyLength = 32,
            publicKeyLength = 32,
            encapsulatedKeyLength = 32,
        )
    }

    protected fun validateHpkeCase(
        vector: JsonObject,
        kemId: Int,
        kdfId: Int,
        aeadId: Int,
        secretKeyLength: Int,
        publicKeyLength: Int,
        encapsulatedKeyLength: Int,
    ) {
        val secretKey = Base64Url.decode(vector.requiredString("recipient_secret_key"))
        val publicKey = Base64Url.decode(vector.requiredString("recipient_public_key"))
        val encapsSeed = Base64Url.decode(vector.requiredString("encaps_seed"))
        val info = Base64Url.decode(vector.requiredString("info"))
        val aad = Base64Url.decode(vector.requiredString("aad"))
        val plaintext = Base64Url.decode(vector.requiredString("plaintext"))
        val encapsulatedKey = Base64Url.decode(vector.requiredString("encapsulated_key"))
        val ciphertext = Base64Url.decode(vector.requiredString("ciphertext"))
        val tamperedCiphertext = Base64Url.decode(vector.requiredString("tampered_ciphertext"))

        assertEquals("base", vector.requiredString("mode"))
        assertEquals(kemId, vector.requiredLong("kem_id").toInt())
        assertEquals(kdfId, vector.requiredLong("kdf_id").toInt())
        assertEquals(aeadId, vector.requiredLong("aead_id").toInt())
        assertEquals(secretKeyLength, secretKey.size)
        assertEquals(publicKeyLength, publicKey.size)
        assertEquals(32, encapsSeed.size)
        assertTrue(info.isNotEmpty())
        assertTrue(aad.isNotEmpty())
        assertTrue(plaintext.isNotEmpty())
        assertEquals(encapsulatedKeyLength, encapsulatedKey.size)
        assertEquals(plaintext.size + 16, ciphertext.size)
        assertEquals(ciphertext.size, tamperedCiphertext.size)
        secretKey.fill(0)
        plaintext.fill(0)
    }

    protected fun validateAes256GcmShape() {
        val vector = JsonObject.parse(readVector("aes256gcm.json"))
        assertEquals(32, Base64Url.decode(vector.requiredString("key")).size)
        assertEquals(12, Base64Url.decode(vector.requiredString("nonce")).size)
        assertTrue(Base64Url.decode(vector.requiredString("ciphertext_with_tag")).size >= 16)
    }

    protected fun validateAesKwShape(
        vectorName: String,
        expectedAlgorithm: String,
        kekLength: Int,
        keyDataLength: Int,
    ) {
        val vector = JsonObject.parse(readVector(vectorName))
        val kek = Base64Url.decode(vector.requiredString("kek"))
        val keyData = Base64Url.decode(vector.requiredString("key_data"))
        val wrappedKey = Base64Url.decode(vector.requiredString("wrapped_key"))

        try {
            assertEquals(expectedAlgorithm, vector.requiredString("alg"))
            assertEquals(kekLength, kek.size)
            assertEquals(keyDataLength, keyData.size)
            assertEquals(keyDataLength + 8, wrappedKey.size)
        } finally {
            kek.fill(0)
            keyData.fill(0)
        }
    }

    protected fun validateKmac256Shape() {
        val vector = JsonObject.parse(readVector("kmac256.json"))
        val key = Base64Url.decode(vector.requiredString("key"))
        val context = Base64Url.decode(vector.requiredString("context"))
        val customization = Base64Url.decode(vector.requiredString("customization"))
        val derivedKey = Base64Url.decode(vector.requiredString("derived_key"))

        try {
            assertEquals("KMAC256", vector.requiredString("alg"))
            assertEquals(32, key.size)
            assertTrue(context.isNotEmpty())
            assertTrue(customization.isNotEmpty())
            assertEquals(vector.requiredLong("output_length").toInt(), derivedKey.size)
        } finally {
            key.fill(0)
            derivedKey.fill(0)
        }
    }

    protected fun validateChaCha20Poly1305Shape() {
        val vectors = JsonObject.parse(readVector("chacha20poly1305.json"))
        validateChaCha20Poly1305Case(vectors.requiredObject("chacha20_poly1305"), nonceLength = 12)
        validateChaCha20Poly1305Case(vectors.requiredObject("xchacha20_poly1305"), nonceLength = 24)
    }

    protected fun validateChaCha20Poly1305Case(vector: JsonObject, nonceLength: Int) {
        val key = Base64Url.decode(vector.requiredString("key"))
        val nonce = Base64Url.decode(vector.requiredString("nonce"))
        val ciphertextWithTag = Base64Url.decode(vector.requiredString("ciphertext_with_tag"))

        assertEquals(32, key.size)
        assertEquals(nonceLength, nonce.size)
        assertTrue(ciphertextWithTag.size >= 16)
        key.fill(0)
    }

    protected fun validateHashShape() {
        val vector = JsonObject.parse(readVector("hashes.json"))
        assertTrue(Base64Url.decode(vector.requiredString("message")).isNotEmpty())
        assertEquals(32, Base64Url.decode(vector.requiredString("sha2_256")).size)
        assertEquals(48, Base64Url.decode(vector.requiredString("sha2_384")).size)
        assertEquals(64, Base64Url.decode(vector.requiredString("sha2_512")).size)
        assertEquals(28, Base64Url.decode(vector.requiredString("sha3_224")).size)
        assertEquals(32, Base64Url.decode(vector.requiredString("sha3_256")).size)
        assertEquals(48, Base64Url.decode(vector.requiredString("sha3_384")).size)
        assertEquals(64, Base64Url.decode(vector.requiredString("sha3_512")).size)
    }

    protected fun validateHmacShape() {
        val vectors = JsonObject.parse(readVector("hmac.json"))
        validateHmacShapeCase(vectors.requiredObject("hmac_sha256"), tagLength = 32)
        validateHmacShapeCase(vectors.requiredObject("hmac_sha384"), tagLength = 48)
        validateHmacShapeCase(vectors.requiredObject("hmac_sha512"), tagLength = 64)
    }

    protected fun validateHmacShapeCase(vector: JsonObject, tagLength: Int) {
        val key = Base64Url.decode(vector.requiredString("key"))
        assertTrue(key.isNotEmpty())
        assertTrue(Base64Url.decode(vector.requiredString("message")).isNotEmpty())
        assertEquals(tagLength, Base64Url.decode(vector.requiredString("tag")).size)
        key.fill(0)
    }

    protected fun validateHmacVector(vector: JsonObject, algorithm: String, tagLength: Int) {
        val key = Base64Url.decode(vector.requiredString("key"))
        val message = Base64Url.decode(vector.requiredString("message"))
        val tag = Base64Url.decode(vector.requiredString("tag"))

        try {
            val mac = Mac.getInstance(algorithm)
            mac.init(SecretKeySpec(key, algorithm))
            val computed = mac.doFinal(message)
            assertEquals(tagLength, tag.size)
            assertTrue(computed.contentEquals(tag))
            computed.fill(0)
        } finally {
            key.fill(0)
        }
    }

    protected fun validateHkdfVector(
        vectorName: String,
        digest: Digest,
        expectedAlgorithm: String,
        expectedHash: String,
    ) {
        val vector = JsonObject.parse(readVector(vectorName))
        val inputKeyMaterial = Base64Url.decode(vector.requiredString("ikm"))
        val salt = Base64Url.decode(vector.requiredString("salt"))
        val info = Base64Url.decode(vector.requiredString("info"))
        val expected = Base64Url.decode(vector.requiredString("okm"))
        val outputLength = vector.requiredLong("output_len").toInt()
        val derived = ByteArray(outputLength)

        try {
            assertEquals(expectedAlgorithm, vector.requiredString("alg"))
            assertEquals(expectedHash, vector.requiredString("hash"))
            assertEquals(expected.size, outputLength)
            val generator = HKDFBytesGenerator(digest)
            generator.init(HKDFParameters(inputKeyMaterial, salt, info))
            assertEquals(outputLength, generator.generateBytes(derived, 0, outputLength))
            assertTrue(derived.contentEquals(expected))
        } finally {
            inputKeyMaterial.fill(0)
            salt.fill(0)
            derived.fill(0)
            expected.fill(0)
        }
    }

    protected fun validatePbkdf2Shape() {
        val vectors = JsonObject.parse(readVector("pbkdf2.json"))
        validatePbkdf2Case(vectors.requiredObject("pbkdf2_hmac_sha256"), alg = "PBKDF2-HMAC-SHA-256", outputLength = 32)
        validatePbkdf2Case(vectors.requiredObject("pbkdf2_hmac_sha512"), alg = "PBKDF2-HMAC-SHA-512", outputLength = 64)
    }

    protected fun validatePbkdf2Case(vector: JsonObject, alg: String, outputLength: Int) {
        val password = Base64Url.decode(vector.requiredString("password"))
        val salt = Base64Url.decode(vector.requiredString("salt"))
        val derivedKey = Base64Url.decode(vector.requiredString("derived_key"))

        try {
            assertEquals(alg, vector.requiredString("alg"))
            assertTrue(password.isNotEmpty())
            assertTrue(salt.isNotEmpty())
            assertTrue(vector.requiredLong("iterations") >= 1)
            assertEquals(outputLength, vector.requiredLong("output_len").toInt())
            assertEquals(outputLength, derivedKey.size)
        } finally {
            password.fill(0)
            salt.fill(0)
            derivedKey.fill(0)
        }
    }

    protected fun validatePbkdf2Vector(vector: JsonObject, algorithm: String, alg: String, outputLength: Int) {
        val password = Base64Url.decode(vector.requiredString("password"))
        val salt = Base64Url.decode(vector.requiredString("salt"))
        val derivedKey = Base64Url.decode(vector.requiredString("derived_key"))
        val passwordChars = String(password, Charsets.UTF_8).toCharArray()

        try {
            assertEquals(alg, vector.requiredString("alg"))
            assertEquals(outputLength, vector.requiredLong("output_len").toInt())
            val spec = PBEKeySpec(
                passwordChars,
                salt,
                vector.requiredLong("iterations").toInt(),
                outputLength * 8,
            )
            val computed = SecretKeyFactory.getInstance(algorithm).generateSecret(spec).encoded
            assertTrue(computed.contentEquals(derivedKey))
            computed.fill(0)
            spec.clearPassword()
        } finally {
            java.util.Arrays.fill(passwordChars, '\u0000')
            password.fill(0)
            salt.fill(0)
            derivedKey.fill(0)
        }
    }

    protected fun parsePkcs1RsaPublicKey(publicKeyDer: ByteArray): java.security.PublicKey {
        val sequence = ASN1Sequence.getInstance(publicKeyDer)
        val modulus = ASN1Integer.getInstance(sequence.getObjectAt(0)).positiveValue
        val exponent = ASN1Integer.getInstance(sequence.getObjectAt(1)).positiveValue
        return KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(modulus, exponent))
    }

    protected fun verifyRsaPkcs1v15(
        algorithm: String,
        publicKey: java.security.PublicKey,
        message: ByteArray,
        signatureBytes: ByteArray,
    ): Boolean {
        val verifier = Signature.getInstance(algorithm)
        verifier.initVerify(publicKey)
        verifier.update(message)
        return verifier.verify(signatureBytes)
    }

    protected fun verifyRsaPss(
        publicKey: java.security.PublicKey,
        message: ByteArray,
        signatureBytes: ByteArray,
        saltLength: Int,
    ): Boolean {
        val verifier = Signature.getInstance("RSASSA-PSS")
        verifier.setParameter(PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, saltLength, 1))
        verifier.initVerify(publicKey)
        verifier.update(message)
        return verifier.verify(signatureBytes)
    }

    protected fun verifyBouncyCastleMlKemVector(vectorName: String, parameters: MLKEMParameters, publicKeyLength: Int) {
        val vector = JsonObject.parse(readVector(vectorName))
        val secretSeed = Base64Url.decode(vector.requiredString("secret_key"))
        val expectedPublicKey = Base64Url.decode(vector.requiredString("public_key"))

        try {
            assertEquals("fips-203-seed", vector.requiredString("secret_key_format"))
            assertEquals(64, secretSeed.size)
            assertEquals(publicKeyLength, expectedPublicKey.size)

            val privateKey = MLKEMPrivateKeyParameters(parameters, secretSeed)
            // Keygen KAT: the seed must expand to the committed public key.
            assertTrue(privateKey.publicKey.contentEquals(expectedPublicKey))

            // Cross-implementation KAT: decapsulating the committed
            // ciphertext must yield the committed shared secret. ML-KEM
            // decapsulation is deterministic (FIPS 203), so an independent
            // implementation must reproduce it exactly.
            val committedCiphertext = Base64Url.decode(vector.requiredString("ciphertext"))
            val expectedSharedSecret = Base64Url.decode(vector.requiredString("shared_secret"))
            val extractor = MLKEMExtractor(privateKey)
            val sharedSecret = extractor.extractSecret(committedCiphertext)
            assertTrue(
                sharedSecret.contentEquals(expectedSharedSecret),
                "$vectorName: decapsulation must reproduce the committed shared secret",
            )
            sharedSecret.fill(0)

            // Implicit rejection: a tampered ciphertext must decapsulate to
            // the committed pseudorandom secret (FIPS 203 J), never to an
            // error and never to the real shared secret.
            val tamperedCiphertext = Base64Url.decode(vector.requiredString("tampered_ciphertext"))
            val expectedTamperedSecret = Base64Url.decode(vector.requiredString("tampered_shared_secret"))
            val rejectedSecret = extractor.extractSecret(tamperedCiphertext)
            assertTrue(
                rejectedSecret.contentEquals(expectedTamperedSecret),
                "$vectorName: implicit rejection must reproduce the committed secret",
            )
            assertFalse(
                rejectedSecret.contentEquals(expectedSharedSecret),
                "$vectorName: implicit rejection must not reveal the real shared secret",
            )
            rejectedSecret.fill(0)
        } finally {
            secretSeed.fill(0)
        }
    }

    protected fun verifyBouncyCastleXWingVector(
        vector: JsonObject,
        parameters: MLKEMParameters,
        mlKemPublicKeyLength: Int,
        mlKemCiphertextLength: Int,
    ) {
        val secretSeed = Base64Url.decode(vector.requiredString("secret_key"))
        val publicKey = Base64Url.decode(vector.requiredString("public_key"))
        val encapsSeed = Base64Url.decode(vector.requiredString("encaps_seed"))
        val ciphertext = Base64Url.decode(vector.requiredString("ciphertext"))
        val expectedSharedSecret = Base64Url.decode(vector.requiredString("shared_secret"))
        val xWingLabel = byteArrayOf(0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c)

        try {
            assertEquals("x-wing-seed", vector.requiredString("secret_key_format"))
            assertEquals(32, secretSeed.size)
            assertEquals(64, encapsSeed.size)
            assertEquals(mlKemPublicKeyLength + 32, publicKey.size)
            assertEquals(mlKemCiphertextLength + 32, ciphertext.size)
            assertEquals(32, expectedSharedSecret.size)

            val expanded = xofShake256(secretSeed, outputLength = 96)
            val mlKemSeed = expanded.copyOfRange(0, 64)
            val xWingSecret = expanded.copyOfRange(64, 96)
            val privateKey = MLKEMPrivateKeyParameters(parameters, mlKemSeed)
            val x25519PrivateKey = X25519PrivateKeyParameters(xWingSecret, 0)
            val x25519PublicKey = x25519PrivateKey.generatePublicKey().encoded
            val generatedPublicKey = concat(privateKey.publicKey, x25519PublicKey)
            assertTrue(generatedPublicKey.contentEquals(publicKey))

            val mlKemPublicKey = publicKey.copyOfRange(0, mlKemPublicKeyLength)
            val receiverX25519PublicKey = publicKey.copyOfRange(mlKemPublicKeyLength, publicKey.size)
            val mlKemRandomness = encapsSeed.copyOfRange(0, 32)
            val ephemeralX25519Secret = encapsSeed.copyOfRange(32, 64)
            val mlKemEncapsulated = MLKEMGenerator.internalGenerateEncapsulated(
                MLKEMPublicKeyParameters(parameters, mlKemPublicKey),
                mlKemRandomness,
            )
            val ephemeralPrivateKey = X25519PrivateKeyParameters(ephemeralX25519Secret, 0)
            val x25519Ciphertext = ephemeralPrivateKey.generatePublicKey().encoded
            val x25519SharedSecret = ByteArray(32)
            ephemeralPrivateKey.generateSecret(X25519PublicKeyParameters(receiverX25519PublicKey, 0), x25519SharedSecret, 0)

            val derivedCiphertext = concat(mlKemEncapsulated.encapsulation, x25519Ciphertext)
            val derivedSharedSecret = sha3_256(
                concat(
                    mlKemEncapsulated.secret,
                    x25519SharedSecret,
                    x25519Ciphertext,
                    receiverX25519PublicKey,
                    xWingLabel,
                ),
            )
            assertTrue(derivedCiphertext.contentEquals(ciphertext))
            assertTrue(derivedSharedSecret.contentEquals(expectedSharedSecret))

            val decapsulatedMlKem = MLKEMExtractor(privateKey)
                .extractSecret(ciphertext.copyOfRange(0, mlKemCiphertextLength))
            val decapsulatedX25519 = ByteArray(32)
            x25519PrivateKey.generateSecret(
                X25519PublicKeyParameters(ciphertext.copyOfRange(mlKemCiphertextLength, ciphertext.size), 0),
                decapsulatedX25519,
                0,
            )
            val decapsulated = sha3_256(
                concat(
                    decapsulatedMlKem,
                    decapsulatedX25519,
                    ciphertext.copyOfRange(mlKemCiphertextLength, ciphertext.size),
                    receiverX25519PublicKey,
                    xWingLabel,
                ),
            )
            assertTrue(decapsulated.contentEquals(expectedSharedSecret))

            Arrays.fill(expanded, 0)
            Arrays.fill(mlKemSeed, 0)
            Arrays.fill(xWingSecret, 0)
            Arrays.fill(mlKemRandomness, 0)
            Arrays.fill(ephemeralX25519Secret, 0)
            Arrays.fill(x25519SharedSecret, 0)
            Arrays.fill(decapsulatedMlKem, 0)
            Arrays.fill(decapsulatedX25519, 0)
        } finally {
            secretSeed.fill(0)
            encapsSeed.fill(0)
        }
    }
}
