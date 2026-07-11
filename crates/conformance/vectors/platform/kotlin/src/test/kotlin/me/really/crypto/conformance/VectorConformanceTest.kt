// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

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
import org.bouncycastle.crypto.digests.SHA384Digest
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.digests.SHA3Digest
import org.bouncycastle.crypto.digests.SHAKEDigest
import org.bouncycastle.crypto.kems.MLKEMExtractor
import org.bouncycastle.crypto.kems.MLKEMGenerator
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

class VectorConformanceTest {
    @Test
    fun manifestListsEverySharedVector() {
        val manifest = JsonObject.parse(readVector("manifest.json"))
        assertEquals(
            listOf(
                "p256.json",
                "p384.json",
                "p521.json",
                "ed25519.json",
                "secp256k1.json",
                "bip340_schnorr.json",
                "rsa.json",
                "x25519.json",
                "ml_dsa_44.json",
                "ml_dsa_65.json",
                "ml_dsa_87.json",
                "slh_dsa_sha2_128s.json",
                "mlkem512.json",
                "mlkem768.json",
                "mlkem1024.json",
                "x_wing.json",
                "hpke.json",
                "aes256gcm.json",
                "aes256gcmsiv.json",
                "aes256kw.json",
                "argon2id.json",
                "chacha20poly1305.json",
                "hkdf.json",
                "hmac.json",
                "pbkdf2.json",
                "hashes.json",
                "codecs.json",
                "jwk.json",
            ),
            manifest.requiredStringArray("vectors"),
        )
    }

    @Test
    fun aes256GcmVectorDecryptsWithJce() {
        val vector = JsonObject.parse(readVector("aes256gcm.json"))
        val key = Base64Url.decode(vector.requiredString("key"))
        val nonce = Base64Url.decode(vector.requiredString("nonce"))
        val aad = Base64Url.decode(vector.requiredString("aad"))
        val expectedPlaintext = Base64Url.decode(vector.requiredString("plaintext"))
        val ciphertextWithTag = Base64Url.decode(vector.requiredString("ciphertext_with_tag"))

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)

        val plaintext = cipher.doFinal(ciphertextWithTag)
        assertTrue(plaintext.contentEquals(expectedPlaintext))

        val encryptingCipher = Cipher.getInstance("AES/GCM/NoPadding")
        encryptingCipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        encryptingCipher.updateAAD(aad)
        assertTrue(encryptingCipher.doFinal(expectedPlaintext).contentEquals(ciphertextWithTag))

        key.fill(0)
        expectedPlaintext.fill(0)
    }

    @Test
    fun aes256KwVectorWrapsWithJce() {
        val vector = JsonObject.parse(readVector("aes256kw.json"))
        val kek = Base64Url.decode(vector.requiredString("kek"))
        val keyData = Base64Url.decode(vector.requiredString("key_data"))
        val wrappedKey = Base64Url.decode(vector.requiredString("wrapped_key"))

        try {
            assertEquals("AES-256-KW", vector.requiredString("alg"))
            val wrappingCipher = Cipher.getInstance("AESWrap")
            wrappingCipher.init(Cipher.WRAP_MODE, SecretKeySpec(kek, "AES"))
            val wrapped = wrappingCipher.wrap(SecretKeySpec(keyData, "AES"))
            assertTrue(wrapped.contentEquals(wrappedKey))

            val unwrappingCipher = Cipher.getInstance("AESWrap")
            unwrappingCipher.init(Cipher.UNWRAP_MODE, SecretKeySpec(kek, "AES"))
            val unwrapped = unwrappingCipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY)
            assertTrue(unwrapped.encoded.contentEquals(keyData))

            val tampered = wrappedKey.copyOf()
            tampered[0] = (tampered[0].toInt() xor 0x01).toByte()
            assertFailsWith<GeneralSecurityException> {
                unwrappingCipher.unwrap(tampered, "AES", Cipher.SECRET_KEY)
            }
        } finally {
            kek.fill(0)
            keyData.fill(0)
        }
    }

    @Test
    fun chacha20Poly1305VectorDecryptsWithJce() {
        val vectors = JsonObject.parse(readVector("chacha20poly1305.json"))
        val vector = vectors.requiredObject("chacha20_poly1305")
        val key = Base64Url.decode(vector.requiredString("key"))
        val nonce = Base64Url.decode(vector.requiredString("nonce"))
        val aad = Base64Url.decode(vector.requiredString("aad"))
        val expectedPlaintext = Base64Url.decode(vector.requiredString("plaintext"))
        val ciphertextWithTag = Base64Url.decode(vector.requiredString("ciphertext_with_tag"))

        try {
            val cipher = Cipher.getInstance("ChaCha20-Poly1305")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
            cipher.updateAAD(aad)

            val plaintext = cipher.doFinal(ciphertextWithTag)
            try {
                assertTrue(plaintext.contentEquals(expectedPlaintext))
            } finally {
                plaintext.fill(0)
            }

            val encryptingCipher = Cipher.getInstance("ChaCha20-Poly1305")
            encryptingCipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
            encryptingCipher.updateAAD(aad)
            assertTrue(encryptingCipher.doFinal(expectedPlaintext).contentEquals(ciphertextWithTag))
        } finally {
            key.fill(0)
            expectedPlaintext.fill(0)
        }
    }

    @Test
    fun hashVectorsMatchJca() {
        val vector = JsonObject.parse(readVector("hashes.json"))
        val message = Base64Url.decode(vector.requiredString("message"))
        val sha2 = Base64Url.decode(vector.requiredString("sha2_256"))
        val sha2_384 = Base64Url.decode(vector.requiredString("sha2_384"))
        val sha2_512 = Base64Url.decode(vector.requiredString("sha2_512"))
        val sha3_224 = Base64Url.decode(vector.requiredString("sha3_224"))
        val sha3 = Base64Url.decode(vector.requiredString("sha3_256"))
        val sha3_384 = Base64Url.decode(vector.requiredString("sha3_384"))
        val sha3_512 = Base64Url.decode(vector.requiredString("sha3_512"))

        assertTrue(MessageDigest.getInstance("SHA-256").digest(message).contentEquals(sha2))
        assertTrue(MessageDigest.getInstance("SHA-384").digest(message).contentEquals(sha2_384))
        assertTrue(MessageDigest.getInstance("SHA-512").digest(message).contentEquals(sha2_512))
        assertTrue(MessageDigest.getInstance("SHA3-224").digest(message).contentEquals(sha3_224))
        assertTrue(MessageDigest.getInstance("SHA3-256").digest(message).contentEquals(sha3))
        assertTrue(MessageDigest.getInstance("SHA3-384").digest(message).contentEquals(sha3_384))
        assertTrue(MessageDigest.getInstance("SHA3-512").digest(message).contentEquals(sha3_512))
    }

    @Test
    fun hmacVectorsMatchJce() {
        val vectors = JsonObject.parse(readVector("hmac.json"))
        validateHmacVector(vectors.requiredObject("hmac_sha256"), "HmacSHA256", tagLength = 32)
        validateHmacVector(vectors.requiredObject("hmac_sha512"), "HmacSHA512", tagLength = 64)
    }

    @Test
    fun pbkdf2VectorsMatchJce() {
        val vectors = JsonObject.parse(readVector("pbkdf2.json"))
        validatePbkdf2Vector(
            vectors.requiredObject("pbkdf2_hmac_sha256"),
            algorithm = "PBKDF2WithHmacSHA256",
            alg = "PBKDF2-HMAC-SHA-256",
            outputLength = 32,
        )
        validatePbkdf2Vector(
            vectors.requiredObject("pbkdf2_hmac_sha512"),
            algorithm = "PBKDF2WithHmacSHA512",
            alg = "PBKDF2-HMAC-SHA-512",
            outputLength = 64,
        )
    }

    @Test
    fun allVectorShapesLoadAndValidate() {
        validateP256Shape()
        validateSec1EcdsaShape("p384.json", secretKeyLength = 48, compressedLength = 49, uncompressedLength = 97)
        validateSec1EcdsaShape("p521.json", secretKeyLength = 66, compressedLength = 67, uncompressedLength = 133)
        validateEd25519Shape()
        validateSecp256k1Shape()
        validateBip340SchnorrShape()
        validateRsaShape()
        validateX25519Shape()
        validateMlDsaShape("ml_dsa_44.json", publicKeyLength = 1_312, signatureLength = 2_420)
        validateMlDsaShape("ml_dsa_65.json", publicKeyLength = 1_952, signatureLength = 3_309)
        validateMlDsaShape("ml_dsa_87.json", publicKeyLength = 2_592, signatureLength = 4_627)
        validateSlhDsaShape()
        validateMlKemShape("mlkem512.json", publicKeyLength = 800, secretKeyLength = 64)
        validateMlKemShape("mlkem768.json", publicKeyLength = 1_184, secretKeyLength = 64)
        validateMlKemShape("mlkem1024.json", publicKeyLength = 1_568, secretKeyLength = 64)
        validateXWingShape()
        validateHpkeShape()
        validateAes256GcmShape()
        validateAes256KwShape()
        validateChaCha20Poly1305Shape()
        validateHmacShape()
        validatePbkdf2Shape()
        validateHashShape()
        validateCodecShape()
    }

    @Test
    fun libSecp256k1ProviderMatchesSecp256k1Vector() {
        val vector = JsonObject.parse(readVector("secp256k1.json"))
        val secretKey = Base64Url.decode(vector.requiredString("secret_key"))
        val expectedPublicKey = Base64Url.decode(vector.requiredString("public_key_compressed"))

        try {
            val derivedPublicKey = LibSecp256k1Vectors.deriveSecp256k1PublicKey(secretKey)
            assertTrue(derivedPublicKey.contentEquals(expectedPublicKey))
        } finally {
            secretKey.fill(0)
        }
    }

    @Test
    fun jcaMatchesRsaVector() {
        val vector = JsonObject.parse(readVector("rsa.json"))
        val publicKeyDer = Base64Url.decode(vector.requiredString("public_key_der"))
        val message = Base64Url.decode(vector.requiredString("message"))
        val pkcs1Sha1Signature = Base64Url.decode(vector.requiredString("pkcs1v15_sha1_signature"))
        val pkcs1Sha256Signature = Base64Url.decode(vector.requiredString("pkcs1v15_sha256_signature"))
        val pssSignature = Base64Url.decode(vector.requiredString("pss_sha256_mgf1_sha256_signature"))

        val publicKey = parsePkcs1RsaPublicKey(publicKeyDer)
        assertTrue(verifyRsaPkcs1v15("SHA1withRSA", publicKey, message, pkcs1Sha1Signature))
        assertTrue(verifyRsaPkcs1v15("SHA256withRSA", publicKey, message, pkcs1Sha256Signature))
        assertTrue(
            verifyRsaPss(
                publicKey,
                message,
                pssSignature,
                vector.requiredLong("pss_sha256_mgf1_sha256_salt_len").toInt(),
            ),
        )

        val tampered = pssSignature.copyOf()
        tampered[0] = (tampered[0].toInt() xor 0x01).toByte()
        assertFalse(
            verifyRsaPss(
                publicKey,
                message,
                tampered,
                vector.requiredLong("pss_sha256_mgf1_sha256_salt_len").toInt(),
            ),
        )
    }

    @Test
    fun bouncyCastleProviderMatchesEd25519Vector() {
        val vector = JsonObject.parse(readVector("ed25519.json"))
        val secretKey = Base64Url.decode(vector.requiredString("secret_key"))
        val expectedPublicKey = Base64Url.decode(vector.requiredString("public_key"))
        val message = Base64Url.decode(vector.requiredString("message"))
        val expectedSignature = Base64Url.decode(vector.requiredString("signature"))

        try {
            // Keygen KAT.
            assertTrue(BouncyCastleVectors.deriveEd25519PublicKey(secretKey).contentEquals(expectedPublicKey))
            // Ed25519 is deterministic (RFC 8032): signing must reproduce
            // the committed signature exactly.
            assertTrue(
                BouncyCastleVectors.signEd25519(secretKey, message).contentEquals(expectedSignature),
                "Ed25519 signature must match the committed KAT",
            )
            // The committed signature must verify; a tampered one must not.
            assertTrue(BouncyCastleVectors.verifyEd25519(expectedPublicKey, message, expectedSignature))
            val tampered = expectedSignature.copyOf()
            tampered[0] = (tampered[0].toInt() xor 0x01).toByte()
            assertFalse(BouncyCastleVectors.verifyEd25519(expectedPublicKey, message, tampered))
        } finally {
            secretKey.fill(0)
        }
    }

    @Test
    fun bouncyCastleProviderMatchesX25519Vector() {
        val vector = JsonObject.parse(readVector("x25519.json"))
        val secretKey = Base64Url.decode(vector.requiredString("secret_key"))
        val publicKey = Base64Url.decode(vector.requiredString("public_key"))
        val peerSecretKey = Base64Url.decode(vector.requiredString("peer_secret_key"))
        val peerPublicKey = Base64Url.decode(vector.requiredString("peer_public_key"))
        val expectedSharedSecret = Base64Url.decode(vector.requiredString("shared_secret"))

        try {
            // Keygen KAT for both sides.
            assertTrue(BouncyCastleVectors.deriveX25519PublicKey(secretKey).contentEquals(publicKey))
            assertTrue(BouncyCastleVectors.deriveX25519PublicKey(peerSecretKey).contentEquals(peerPublicKey))
            // ECDH KAT: both directions agree on the committed shared secret.
            val a = BouncyCastleVectors.x25519SharedSecret(secretKey, peerPublicKey)
            val b = BouncyCastleVectors.x25519SharedSecret(peerSecretKey, publicKey)
            assertTrue(a.contentEquals(expectedSharedSecret))
            assertTrue(b.contentEquals(expectedSharedSecret))
            a.fill(0)
            b.fill(0)
        } finally {
            secretKey.fill(0)
            peerSecretKey.fill(0)
        }
    }

    @Test
    fun bouncyCastleProviderMatchesP256Vector() {
        val vector = JsonObject.parse(readVector("p256.json"))
        val secretKey = Base64Url.decode(vector.requiredString("secret_key"))
        val expectedCompressed = Base64Url.decode(vector.requiredString("public_key_compressed"))
        val expectedUncompressed = Base64Url.decode(vector.requiredString("public_key_uncompressed"))
        val peerSecretKey = Base64Url.decode(vector.requiredString("peer_secret_key"))
        val expectedPeerCompressed = Base64Url.decode(vector.requiredString("peer_public_key_compressed"))
        val expectedPeerUncompressed = Base64Url.decode(vector.requiredString("peer_public_key_uncompressed"))
        val expectedSharedSecret = Base64Url.decode(vector.requiredString("shared_secret"))

        try {
            // Keygen KAT: derived public key matches both encodings.
            assertTrue(
                BouncyCastleVectors.deriveP256PublicKey(secretKey, compressed = true).contentEquals(expectedCompressed),
            )
            assertTrue(
                BouncyCastleVectors.deriveP256PublicKey(secretKey, compressed = false).contentEquals(expectedUncompressed),
            )
            assertTrue(
                BouncyCastleVectors.deriveP256PublicKey(peerSecretKey, compressed = true)
                    .contentEquals(expectedPeerCompressed),
            )
            assertTrue(
                BouncyCastleVectors.deriveP256PublicKey(peerSecretKey, compressed = false)
                    .contentEquals(expectedPeerUncompressed),
            )
            val sharedSecret = BouncyCastleVectors.deriveP256SharedSecret(secretKey, expectedPeerCompressed)
            val peerSharedSecret = BouncyCastleVectors.deriveP256SharedSecret(peerSecretKey, expectedCompressed)
            assertTrue(sharedSecret.contentEquals(expectedSharedSecret))
            assertTrue(peerSharedSecret.contentEquals(expectedSharedSecret))
            sharedSecret.fill(0)
            peerSharedSecret.fill(0)
        } finally {
            secretKey.fill(0)
            peerSecretKey.fill(0)
            expectedSharedSecret.fill(0)
        }
    }

    @Test
    fun bouncyCastleProviderMatchesP384AndP521Vectors() {
        verifyBouncyCastleSec1EcdsaVector("p384.json", curveName = "secp384r1")
        verifyBouncyCastleSec1EcdsaVector("p521.json", curveName = "secp521r1")
    }

    private fun verifyBouncyCastleSec1EcdsaVector(vectorName: String, curveName: String) {
        val vector = JsonObject.parse(readVector(vectorName))
        val secretKey = Base64Url.decode(vector.requiredString("secret_key"))
        val expectedCompressed = Base64Url.decode(vector.requiredString("public_key_compressed"))
        val expectedUncompressed = Base64Url.decode(vector.requiredString("public_key_uncompressed"))
        val message = Base64Url.decode(vector.requiredString("message"))
        val signature = Base64Url.decode(vector.requiredString("signature_der"))

        try {
            assertTrue(
                BouncyCastleVectors.deriveSec1PublicKey(curveName, secretKey, compressed = true)
                    .contentEquals(expectedCompressed),
            )
            assertTrue(
                BouncyCastleVectors.deriveSec1PublicKey(curveName, secretKey, compressed = false)
                    .contentEquals(expectedUncompressed),
            )
            assertTrue(BouncyCastleVectors.verifySec1Ecdsa(curveName, expectedCompressed, message, signature))

            val tampered = signature.copyOf()
            tampered[0] = (tampered[0].toInt() xor 0x01).toByte()
            assertFalse(BouncyCastleVectors.verifySec1Ecdsa(curveName, expectedCompressed, message, tampered))
        } finally {
            secretKey.fill(0)
        }
    }

    @Test
    fun bouncyCastleProviderMatchesMlDsaVectors() {
        verifyBouncyCastleMlDsaVector("ml_dsa_44.json", MLDSAParameters.ml_dsa_44)
        verifyBouncyCastleMlDsaVector("ml_dsa_65.json", MLDSAParameters.ml_dsa_65)
        verifyBouncyCastleMlDsaVector("ml_dsa_87.json", MLDSAParameters.ml_dsa_87)
    }

    private fun verifyBouncyCastleMlDsaVector(vectorName: String, parameters: MLDSAParameters) {
        val vector = JsonObject.parse(readVector(vectorName))
        val secretSeed = Base64Url.decode(vector.requiredString("secret_key"))
        val expectedPublicKey = Base64Url.decode(vector.requiredString("public_key"))
        val message = Base64Url.decode(vector.requiredString("message"))
        val committedSignature = Base64Url.decode(vector.requiredString("signature"))

        try {
            assertEquals("fips-204-seed", vector.requiredString("secret_key_format"))
            val privateKey = MLDSAPrivateKeyParameters(parameters, secretSeed)
            // Keygen KAT: the seed must expand to the committed public key.
            assertTrue(privateKey.publicKey.contentEquals(expectedPublicKey))

            // Cross-implementation KAT: an independent implementation
            // (Bouncy Castle) must ACCEPT the committed deterministic
            // signature the Rust and noble oracles produced. We verify
            // rather than regenerate because Bouncy Castle may sign with
            // the hedged (randomized) variant, whereas the committed
            // signature is the deterministic one — but verification is
            // scheme-agnostic, so a conformant verifier must accept it.
            val verifier = MLDSASigner()
            verifier.init(false, privateKey.publicKeyParameters)
            verifier.update(message, 0, message.size)
            assertTrue(
                verifier.verifySignature(committedSignature),
                "$vectorName: Bouncy Castle must accept the committed ML-DSA signature",
            )

            // A tampered signature must be rejected (fail closed).
            val tampered = committedSignature.copyOf()
            tampered[0] = (tampered[0].toInt() xor 0x01).toByte()
            val tamperVerifier = MLDSASigner()
            tamperVerifier.init(false, privateKey.publicKeyParameters)
            tamperVerifier.update(message, 0, message.size)
            assertFalse(
                tamperVerifier.verifySignature(tampered),
                "$vectorName: Bouncy Castle must reject a tampered ML-DSA signature",
            )
        } finally {
            secretSeed.fill(0)
        }
    }

    @Test
    fun bouncyCastleProviderMatchesMlKemVectors() {
        verifyBouncyCastleMlKemVector("mlkem512.json", MLKEMParameters.ml_kem_512, publicKeyLength = 800)
        verifyBouncyCastleMlKemVector("mlkem768.json", MLKEMParameters.ml_kem_768, publicKeyLength = 1_184)
        verifyBouncyCastleMlKemVector("mlkem1024.json", MLKEMParameters.ml_kem_1024, publicKeyLength = 1_568)
    }

    @Test
    fun bouncyCastleProviderMatchesXWingVectors() {
        val vectors = JsonObject.parse(readVector("x_wing.json"))
        verifyBouncyCastleXWingVector(
            vectors.requiredObject("x_wing_768"),
            MLKEMParameters.ml_kem_768,
            mlKemPublicKeyLength = 1_184,
            mlKemCiphertextLength = 1_088,
        )
        verifyBouncyCastleXWingVector(
            vectors.requiredObject("x_wing_1024"),
            MLKEMParameters.ml_kem_1024,
            mlKemPublicKeyLength = 1_568,
            mlKemCiphertextLength = 1_568,
        )
    }

    @Test
    fun manifestDeclaresKotlinBouncyCastleExecutableCoverage() {
        val manifest = JsonObject.parse(readVector("manifest.json"))
        val lane = manifest.requiredObjectArray("runtime_lanes")
            .first { it.requiredString("name") == "kotlin-native-jvm" }

        assertEquals("executable", lane.requiredString("status"))
        assertEquals(
            "cd crates/conformance/vectors/platform/kotlin && ./gradlew test --rerun-tasks",
            lane.requiredString("harness"),
        )
        assertEquals(
            listOf(
                "P-256",
                "P-384",
                "P-521",
                "Ed25519",
                "secp256k1",
                "BIP-340-Schnorr",
                "RSA",
                "X25519",
                "ML-DSA-44",
                "ML-DSA-65",
                "ML-DSA-87",
                "SLH-DSA-SHA2-128s",
                "ML-KEM-512",
                "ML-KEM-768",
                "ML-KEM-1024",
                "X-Wing-768",
                "X-Wing-1024",
                "HPKE-P256-SHA256-AES256GCM",
                "HPKE-X25519-SHA256-CHACHA20POLY1305",
                "AES-256-GCM",
                "AES-256-KW",
                "ChaCha20-Poly1305",
                "HMAC-SHA-256",
                "HMAC-SHA-512",
                "PBKDF2-HMAC-SHA-256",
                "PBKDF2-HMAC-SHA-512",
                "SHA2-256",
                "SHA2-384",
                "SHA2-512",
                "SHA3-224",
                "SHA3-256",
                "SHA3-384",
                "SHA3-512",
                "JWK",
                "JWK-Multikey",
            ),
            lane.requiredStringArray("algorithms"),
        )
        val notes = lane.requiredStringArray("notes").joinToString(separator = "\n")
        assertContains(notes, "Bouncy Castle bcprov-jdk18on 1.84")
        assertContains(notes, "--rerun-tasks")
    }

    @Test
    fun nativeJwkVectorsMatchRustContract() {
        val vectorFile = JsonObject.parse(readVector("jwk.json"))
        val vectors = vectorFile.requiredObjectArray("vectors")
        assertEquals(13, vectors.size)
        for (vector in vectors) {
            val alg = vector.requiredString("alg")
            val publicKey = Base64Url.decode(vector.requiredString("public_key"))
            assertEquals(vector.requiredLong("public_key_length").toInt(), publicKey.size)
            assertEquals(vector.requiredString("jwk_jcs"), KotlinJwk.toJcs(alg, publicKey))
            val parsed = KotlinJwk.fromJcs(vector.requiredString("jwk_jcs"))
            assertEquals(alg, parsed.alg)
            assertTrue(parsed.publicKey.contentEquals(publicKey))

            when (vector.requiredString("multikey_status")) {
                "supported" -> assertTrue(vector.optionalString("multikey")?.startsWith("z") == true)
                "multicodec-missing" -> assertEquals(null, vector.optionalString("multikey"))
                else -> error("invalid JWK multikey status")
            }
            publicKey.fill(0)
            parsed.publicKey.fill(0)
        }
    }


    private fun verifyBouncyCastleMlKemVector(vectorName: String, parameters: MLKEMParameters, publicKeyLength: Int) {
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

    private fun verifyBouncyCastleXWingVector(
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

    private fun validateP256Shape() {
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

    private fun validateSec1EcdsaShape(
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

    private fun validateEd25519Shape() {
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

    private fun validateSecp256k1Shape() {
        val vector = JsonObject.parse(readVector("secp256k1.json"))
        val secretKey = Base64Url.decode(vector.requiredString("secret_key"))
        val compressedPublicKey = Base64Url.decode(vector.requiredString("public_key_compressed"))

        assertEquals(32, secretKey.size)
        assertEquals(33, compressedPublicKey.size)
        assertTrue(compressedPublicKey[0] == 0x02.toByte() || compressedPublicKey[0] == 0x03.toByte())
        secretKey.fill(0)
    }

    private fun validateBip340SchnorrShape() {
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

    private fun validateRsaShape() {
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

    private fun validateX25519Shape() {
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

    private fun validateMlDsaShape(vectorName: String, publicKeyLength: Int, signatureLength: Int) {
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

    private fun validateSlhDsaShape() {
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

    private fun validateMlKemShape(vectorName: String, publicKeyLength: Int, secretKeyLength: Int) {
        val vector = JsonObject.parse(readVector(vectorName))
        val secretKey = Base64Url.decode(vector.requiredString("secret_key"))
        val publicKey = Base64Url.decode(vector.requiredString("public_key"))

        assertEquals("fips-203-seed", vector.requiredString("secret_key_format"))
        assertEquals(secretKeyLength, secretKey.size)
        assertEquals(publicKeyLength, publicKey.size)
        assertEquals(publicKeyLength, vector.requiredLong("public_key_length").toInt())
        secretKey.fill(0)
    }

    private fun validateXWingShape() {
        val vectors = JsonObject.parse(readVector("x_wing.json"))
        validateXWingCase(vectors.requiredObject("x_wing_768"), publicKeyLength = 1_216, ciphertextLength = 1_120)
        validateXWingCase(vectors.requiredObject("x_wing_1024"), publicKeyLength = 1_600, ciphertextLength = 1_600)
    }

    private fun validateXWingCase(vector: JsonObject, publicKeyLength: Int, ciphertextLength: Int) {
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

    private fun validateHpkeShape() {
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

    private fun validateHpkeCase(
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

    private fun validateAes256GcmShape() {
        val vector = JsonObject.parse(readVector("aes256gcm.json"))
        assertEquals(32, Base64Url.decode(vector.requiredString("key")).size)
        assertEquals(12, Base64Url.decode(vector.requiredString("nonce")).size)
        assertTrue(Base64Url.decode(vector.requiredString("ciphertext_with_tag")).size >= 16)
    }

    private fun validateAes256KwShape() {
        val vector = JsonObject.parse(readVector("aes256kw.json"))
        val kek = Base64Url.decode(vector.requiredString("kek"))
        val keyData = Base64Url.decode(vector.requiredString("key_data"))
        val wrappedKey = Base64Url.decode(vector.requiredString("wrapped_key"))

        try {
            assertEquals("AES-256-KW", vector.requiredString("alg"))
            assertEquals(32, kek.size)
            assertEquals(32, keyData.size)
            assertEquals(40, wrappedKey.size)
        } finally {
            kek.fill(0)
            keyData.fill(0)
        }
    }

    private fun validateChaCha20Poly1305Shape() {
        val vectors = JsonObject.parse(readVector("chacha20poly1305.json"))
        validateChaCha20Poly1305Case(vectors.requiredObject("chacha20_poly1305"), nonceLength = 12)
        validateChaCha20Poly1305Case(vectors.requiredObject("xchacha20_poly1305"), nonceLength = 24)
    }

    private fun validateChaCha20Poly1305Case(vector: JsonObject, nonceLength: Int) {
        val key = Base64Url.decode(vector.requiredString("key"))
        val nonce = Base64Url.decode(vector.requiredString("nonce"))
        val ciphertextWithTag = Base64Url.decode(vector.requiredString("ciphertext_with_tag"))

        assertEquals(32, key.size)
        assertEquals(nonceLength, nonce.size)
        assertTrue(ciphertextWithTag.size >= 16)
        key.fill(0)
    }

    private fun validateHashShape() {
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

    private fun validateHmacShape() {
        val vectors = JsonObject.parse(readVector("hmac.json"))
        validateHmacShapeCase(vectors.requiredObject("hmac_sha256"), tagLength = 32)
        validateHmacShapeCase(vectors.requiredObject("hmac_sha512"), tagLength = 64)
    }

    private fun validateHmacShapeCase(vector: JsonObject, tagLength: Int) {
        val key = Base64Url.decode(vector.requiredString("key"))
        assertTrue(key.isNotEmpty())
        assertTrue(Base64Url.decode(vector.requiredString("message")).isNotEmpty())
        assertEquals(tagLength, Base64Url.decode(vector.requiredString("tag")).size)
        key.fill(0)
    }

    private fun validateHmacVector(vector: JsonObject, algorithm: String, tagLength: Int) {
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

    private fun validatePbkdf2Shape() {
        val vectors = JsonObject.parse(readVector("pbkdf2.json"))
        validatePbkdf2Case(vectors.requiredObject("pbkdf2_hmac_sha256"), alg = "PBKDF2-HMAC-SHA-256", outputLength = 32)
        validatePbkdf2Case(vectors.requiredObject("pbkdf2_hmac_sha512"), alg = "PBKDF2-HMAC-SHA-512", outputLength = 64)
    }

    private fun validatePbkdf2Case(vector: JsonObject, alg: String, outputLength: Int) {
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

    private fun validatePbkdf2Vector(vector: JsonObject, algorithm: String, alg: String, outputLength: Int) {
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

    private fun parsePkcs1RsaPublicKey(publicKeyDer: ByteArray): java.security.PublicKey {
        val sequence = ASN1Sequence.getInstance(publicKeyDer)
        val modulus = ASN1Integer.getInstance(sequence.getObjectAt(0)).positiveValue
        val exponent = ASN1Integer.getInstance(sequence.getObjectAt(1)).positiveValue
        return KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(modulus, exponent))
    }

    private fun verifyRsaPkcs1v15(
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

    private fun verifyRsaPss(
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

    private fun validateCodecShape() {
        val vector = JsonObject.parse(readVector("codecs.json"))
        assertTrue(Base64Url.decode(vector.requiredString("raw")).isNotEmpty())
        assertTrue(vector.requiredString("base64url").isNotEmpty())
        assertTrue(vector.requiredString("multibase_base64url").startsWith("u"))
        assertTrue(vector.requiredString("multibase_base58btc").startsWith("z"))
        assertTrue(Base64Url.decode(vector.requiredString("dag_cbor")).isNotEmpty())
        assertTrue(vector.requiredString("dag_cbor_cid").isNotEmpty())
        assertTrue(vector.requiredString("multikey").isNotEmpty())
    }
}

private fun readVector(name: String): String {
    val configured = System.getProperty("reallyme.crypto.vectors.dir")
    val vectorsDir = if (configured.isNullOrBlank()) {
        Path("../../../../../vectors")
    } else {
        Path(configured)
    }
    return Files.readString(vectorsDir.resolve(name))
}

private fun concat(vararg parts: ByteArray): ByteArray {
    val totalLength = parts.fold(0) { acc, part -> acc + part.size }
    val out = ByteArray(totalLength)
    var offset = 0
    for (part in parts) {
        part.copyInto(out, destinationOffset = offset)
        offset += part.size
    }
    return out
}

private fun xofShake256(input: ByteArray, outputLength: Int): ByteArray {
    val digest = SHAKEDigest(256)
    digest.update(input, 0, input.size)
    val out = ByteArray(outputLength)
    digest.doOutput(out, 0, out.size)
    return out
}

private fun sha3_256(input: ByteArray): ByteArray {
    val digest = SHA3Digest(256)
    digest.update(input, 0, input.size)
    val out = ByteArray(32)
    digest.doFinal(out, 0)
    return out
}

private object Base64Url {
    fun decode(value: String): ByteArray {
        require(value.all { it.isLetterOrDigit() || it == '-' || it == '_' })
        return java.util.Base64.getUrlDecoder().decode(value)
    }

    fun encode(value: ByteArray): String =
        java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(value)
}

private data class KotlinJwkSpec(
    val alg: String,
    val crv: String,
    val kty: String,
    val keyUse: String,
    val publicKeyLength: Int,
)

private data class ParsedKotlinJwk(val alg: String, val publicKey: ByteArray)

private object KotlinJwk {
    fun toJcs(alg: String, publicKey: ByteArray): String {
        val spec = spec(alg)
        require(publicKey.size == spec.publicKeyLength)
        return if (spec.kty == "EC") {
            val uncompressed = BouncyCastleVectors.decompressEcPublicKey(curveName(alg), publicKey)
            val x = Base64Url.encode(uncompressed.copyOfRange(1, 33))
            val y = Base64Url.encode(uncompressed.copyOfRange(33, 65))
            """{"alg":${jsonString(spec.alg)},"crv":${jsonString(spec.crv)},"kty":"EC","use":"sig","x":${jsonString(x)},"y":${jsonString(y)}}"""
        } else {
            val encodedPublicKey = Base64Url.encode(publicKey)
            if (spec.kty == "AKP") {
                """{"alg":${jsonString(spec.alg)},"kty":"AKP","pub":${jsonString(encodedPublicKey)},"use":${jsonString(spec.keyUse)}}"""
            } else {
                """{"alg":${jsonString(spec.alg)},"crv":${jsonString(spec.crv)},"kty":"OKP","use":${jsonString(spec.keyUse)},"x":${jsonString(encodedPublicKey)}}"""
            }
        }
    }

    fun fromJcs(value: String): ParsedKotlinJwk {
        val jwk = JsonObject.parse(value)
        val kty = jwk.requiredString("kty")
        val keyIdentifier = if (kty == "AKP") jwk.requiredString("alg") else jwk.requiredString("crv")
        val spec = spec(keyIdentifier)
        require(jwk.requiredString("kty") == spec.kty)
        require(jwk.requiredString("alg") == spec.alg)
        require(jwk.requiredString("use") == spec.keyUse)

        val publicKey = if (spec.kty == "EC") {
            BouncyCastleVectors.compressEcPublicKey(
                curveName(keyIdentifier),
                Base64Url.decode(jwk.requiredString("x")),
                Base64Url.decode(jwk.requiredString("y")),
            )
        } else if (spec.kty == "AKP") {
            Base64Url.decode(jwk.requiredString("pub"))
        } else {
            Base64Url.decode(jwk.requiredString("x"))
        }
        require(publicKey.size == spec.publicKeyLength)
        return ParsedKotlinJwk(keyIdentifier, publicKey)
    }

    private fun spec(alg: String): KotlinJwkSpec = when (alg) {
        "Ed25519" -> KotlinJwkSpec("EdDSA", "Ed25519", "OKP", "sig", 32)
        "X25519" -> KotlinJwkSpec("ECDH-ES", "X25519", "OKP", "enc", 32)
        "P-256" -> KotlinJwkSpec("ES256", "P-256", "EC", "sig", 33)
        "secp256k1" -> KotlinJwkSpec("ES256K", "secp256k1", "EC", "sig", 33)
        "ML-DSA-44" -> KotlinJwkSpec(alg, alg, "AKP", "sig", 1_312)
        "ML-DSA-65" -> KotlinJwkSpec(alg, alg, "AKP", "sig", 1_952)
        "ML-DSA-87" -> KotlinJwkSpec(alg, alg, "AKP", "sig", 2_592)
        "ML-KEM-512" -> KotlinJwkSpec(alg, alg, "AKP", "enc", 800)
        "ML-KEM-768" -> KotlinJwkSpec(alg, alg, "AKP", "enc", 1_184)
        "ML-KEM-1024" -> KotlinJwkSpec(alg, alg, "AKP", "enc", 1_568)
        "SLH-DSA-SHA2-128s" -> KotlinJwkSpec(alg, alg, "AKP", "sig", 32)
        "X-Wing-768" -> KotlinJwkSpec(alg, alg, "AKP", "enc", 1_216)
        "X-Wing-1024" -> KotlinJwkSpec(alg, alg, "AKP", "enc", 1_600)
        else -> error("unsupported JWK algorithm")
    }

    private fun curveName(alg: String): String = when (alg) {
        "P-256" -> "secp256r1"
        "secp256k1" -> "secp256k1"
        else -> error("unsupported EC JWK algorithm")
    }

    private fun jsonString(value: String): String =
        buildString {
            append('"')
            for (char in value) {
                when (char) {
                    '"' -> append("\\\"")
                    '\\' -> append("\\\\")
                    '\b' -> append("\\b")
                    '\u000C' -> append("\\f")
                    '\n' -> append("\\n")
                    '\r' -> append("\\r")
                    '\t' -> append("\\t")
                    else -> append(char)
                }
            }
            append('"')
        }
}

private class JsonObject private constructor(private val fields: Map<String, Any?>) {
    fun requiredString(name: String): String =
        fields[name] as? String ?: error("missing string field $name")

    fun optionalString(name: String): String? =
        fields[name] as? String

    fun requiredLong(name: String): Long =
        fields[name] as? Long ?: error("missing number field $name")

    fun requiredStringArray(name: String): List<String> =
        (fields[name] as? List<*>)?.map { it as? String ?: error("invalid string array $name") }
            ?: error("missing string array $name")

    fun requiredObject(name: String): JsonObject {
        @Suppress("UNCHECKED_CAST")
        return JsonObject(fields[name] as? Map<String, Any?> ?: error("missing object field $name"))
    }

    fun requiredObjectArray(name: String): List<JsonObject> =
        (fields[name] as? List<*>)?.map {
            @Suppress("UNCHECKED_CAST")
            JsonObject(it as? Map<String, Any?> ?: error("invalid object array $name"))
        } ?: error("missing object array $name")

    companion object {
        fun parse(input: String): JsonObject {
            val parser = JsonParser(input)
            val value = parser.parseValue()
            parser.requireEnd()

            @Suppress("UNCHECKED_CAST")
            return JsonObject(value as? Map<String, Any?> ?: error("expected object"))
        }
    }
}

private class JsonParser(private val input: String) {
    private var offset: Int = 0

    fun parseValue(): Any? {
        skipWhitespace()
        return when (peek()) {
            '{' -> parseObject()
            '[' -> parseArray()
            '"' -> parseString()
            't' -> parseLiteral("true", true)
            'f' -> parseLiteral("false", false)
            'n' -> parseLiteral("null", null)
            else -> parseNumber()
        }
    }

    fun requireEnd() {
        skipWhitespace()
        require(offset == input.length)
    }

    private fun parseObject(): Map<String, Any?> {
        consume('{')
        val result = linkedMapOf<String, Any?>()
        skipWhitespace()
        if (tryConsume('}')) {
            return result
        }

        while (true) {
            val key = parseString()
            consume(':')
            result[key] = parseValue()
            if (tryConsume('}')) {
                return result
            }
            consume(',')
        }
    }

    private fun parseArray(): List<Any?> {
        consume('[')
        val result = mutableListOf<Any?>()
        skipWhitespace()
        if (tryConsume(']')) {
            return result
        }

        while (true) {
            result.add(parseValue())
            if (tryConsume(']')) {
                return result
            }
            consume(',')
        }
    }

    private fun parseString(): String {
        consume('"')
        val builder = StringBuilder()
        while (offset < input.length) {
            val char = input[offset++]
            when (char) {
                '"' -> return builder.toString()
                '\\' -> builder.append(parseEscape())
                else -> builder.append(char)
            }
        }
        error("unterminated string")
    }

    private fun parseEscape(): Char {
        require(offset < input.length)
        return when (val escaped = input[offset++]) {
            '"', '\\', '/' -> escaped
            'b' -> '\b'
            'f' -> '\u000C'
            'n' -> '\n'
            'r' -> '\r'
            't' -> '\t'
            'u' -> parseUnicodeEscape()
            else -> error("invalid escape")
        }
    }

    private fun parseUnicodeEscape(): Char {
        require(offset + 4 <= input.length)
        val value = input.substring(offset, offset + 4).toInt(16)
        offset += 4
        return value.toChar()
    }

    private fun parseLiteral(token: String, value: Any?): Any? {
        require(input.startsWith(token, offset))
        offset += token.length
        return value
    }

    private fun parseNumber(): Number {
        val start = offset
        if (peek() == '-') {
            offset += 1
        }
        while (offset < input.length && input[offset].isDigit()) {
            offset += 1
        }
        return input.substring(start, offset).toLong()
    }

    private fun consume(expected: Char) {
        skipWhitespace()
        require(offset < input.length && input[offset] == expected)
        offset += 1
    }

    private fun tryConsume(expected: Char): Boolean {
        skipWhitespace()
        if (offset < input.length && input[offset] == expected) {
            offset += 1
            return true
        }
        return false
    }

    private fun peek(): Char {
        require(offset < input.length)
        return input[offset]
    }

    private fun skipWhitespace() {
        while (offset < input.length && input[offset].isWhitespace()) {
            offset += 1
        }
    }
}

private object LibSecp256k1Vectors {
    private val provider: Secp256k1 by lazy {
        Secp256k1.get()
    }

    fun deriveSecp256k1PublicKey(secretKey: ByteArray): ByteArray {
        require(secretKey.size == 32)
        return provider.pubKeyCompress(provider.pubkeyCreate(secretKey))
    }
}

private object BouncyCastleVectors {
    private val p256Domain: ECDomainParameters by lazy {
        ECDomainParameters(SECNamedCurves.getByName("secp256r1"))
    }

    private fun domain(curveName: String): ECDomainParameters =
        ECDomainParameters(SECNamedCurves.getByName(curveName))

    /// Returns the P-256 public key derived from `secretKey`, SEC1-encoded
    /// (`compressed = true` -> 33 bytes, else 65 bytes uncompressed).
    fun deriveP256PublicKey(secretKey: ByteArray, compressed: Boolean): ByteArray {
        require(secretKey.size == 32)
        val scalar = p256Domain.validatePrivateScalar(BigInteger(1, secretKey))
        return p256Domain.g.multiply(scalar).normalize().getEncoded(compressed)
    }

    fun deriveP256SharedSecret(secretKey: ByteArray, publicKey: ByteArray): ByteArray {
        require(secretKey.size == 32)
        val scalar = p256Domain.validatePrivateScalar(BigInteger(1, secretKey))
        val point = p256Domain.curve.decodePoint(publicKey).multiply(scalar).normalize()
        return point.affineXCoord.encoded
    }

    fun deriveSec1PublicKey(curveName: String, secretKey: ByteArray, compressed: Boolean): ByteArray {
        val curveDomain = domain(curveName)
        val scalar = curveDomain.validatePrivateScalar(BigInteger(1, secretKey))
        return curveDomain.g.multiply(scalar).normalize().getEncoded(compressed)
    }

    fun decompressEcPublicKey(curveName: String, publicKey: ByteArray): ByteArray {
        val curveDomain = domain(curveName)
        return curveDomain.curve.decodePoint(publicKey).normalize().getEncoded(false)
    }

    fun compressEcPublicKey(curveName: String, x: ByteArray, y: ByteArray): ByteArray {
        require(x.size == 32)
        require(y.size == 32)
        return decompressEcPublicKey(curveName, concat(byteArrayOf(0x04), x, y))
            .let { uncompressed ->
                val curveDomain = domain(curveName)
                curveDomain.curve.decodePoint(uncompressed).normalize().getEncoded(true)
            }
    }

    fun verifySec1Ecdsa(
        curveName: String,
        publicKeySec1: ByteArray,
        message: ByteArray,
        signatureDer: ByteArray,
    ): Boolean {
        val curveDomain = domain(curveName)
        val publicPoint = curveDomain.curve.decodePoint(publicKeySec1)
        val publicKey = ECPublicKeyParameters(publicPoint, curveDomain)
        val digest = when (curveName) {
            "secp384r1" -> {
                val out = ByteArray(48)
                val digest = SHA384Digest()
                digest.update(message, 0, message.size)
                digest.doFinal(out, 0)
                out
            }
            "secp521r1" -> {
                val out = ByteArray(64)
                val digest = SHA512Digest()
                digest.update(message, 0, message.size)
                digest.doFinal(out, 0)
                out
            }
            else -> return false
        }
        val sequence = try {
            ASN1Sequence.getInstance(signatureDer)
        } catch (_: RuntimeException) {
            return false
        }
        if (sequence.size() != 2) {
            return false
        }
        val r = try {
            ASN1Integer.getInstance(sequence.getObjectAt(0)).positiveValue
        } catch (_: RuntimeException) {
            return false
        }
        val s = try {
            ASN1Integer.getInstance(sequence.getObjectAt(1)).positiveValue
        } catch (_: RuntimeException) {
            return false
        }
        val verifier = ECDSASigner()
        verifier.init(false, publicKey)
        return verifier.verifySignature(digest, r, s)
    }

    fun deriveEd25519PublicKey(secretKey: ByteArray): ByteArray =
        Ed25519PrivateKeyParameters(secretKey, 0).generatePublicKey().encoded

    /// RFC 8032 Ed25519 is deterministic, so this reproduces the committed
    /// signature exactly.
    fun signEd25519(secretKey: ByteArray, message: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(secretKey, 0))
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    fun verifyEd25519(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        val verifier = Ed25519Signer()
        verifier.init(false, Ed25519PublicKeyParameters(publicKey, 0))
        verifier.update(message, 0, message.size)
        return verifier.verifySignature(signature)
    }

    fun deriveX25519PublicKey(secretKey: ByteArray): ByteArray =
        X25519PrivateKeyParameters(secretKey, 0).generatePublicKey().encoded

    fun x25519SharedSecret(secretKey: ByteArray, peerPublicKey: ByteArray): ByteArray {
        val agreement = X25519Agreement()
        agreement.init(X25519PrivateKeyParameters(secretKey, 0))
        val out = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(X25519PublicKeyParameters(peerPublicKey, 0), out, 0)
        return out
    }
}
