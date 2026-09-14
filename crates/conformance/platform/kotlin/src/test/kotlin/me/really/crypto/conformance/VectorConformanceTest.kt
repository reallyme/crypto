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

internal class VectorConformanceTest : VectorConformanceTestSupport() {
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
                "aes128gcm.json",
                "aes192gcm.json",
                "aes256gcm.json",
                "aes256gcmsiv.json",
                "aes128kw.json",
                "aes192kw.json",
                "aes256kw.json",
                "argon2id.json",
                "kmac256.json",
                "chacha20poly1305.json",
                "hkdf.json",
                "hkdf_sha384.json",
                "concat_kdf.json",
                "hmac.json",
                "pbkdf2.json",
                "hashes.json",
                "operation_response.json",
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
    fun aesKwVectorsWrapWithJce() {
        verifyAesKwVector("aes128kw.json", expectedAlgorithm = "AES-128-KW")
        verifyAesKwVector("aes192kw.json", expectedAlgorithm = "AES-192-KW")
        verifyAesKwVector("aes256kw.json", expectedAlgorithm = "AES-256-KW")
    }

    private fun verifyAesKwVector(vectorName: String, expectedAlgorithm: String) {
        val vector = JsonObject.parse(readVector(vectorName))
        val kek = Base64Url.decode(vector.requiredString("kek"))
        val keyData = Base64Url.decode(vector.requiredString("key_data"))
        val wrappedKey = Base64Url.decode(vector.requiredString("wrapped_key"))

        try {
            assertEquals(expectedAlgorithm, vector.requiredString("alg"))
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
    fun kmac256VectorMatchesBouncyCastle() {
        val vector = JsonObject.parse(readVector("kmac256.json"))
        val key = Base64Url.decode(vector.requiredString("key"))
        val context = Base64Url.decode(vector.requiredString("context"))
        val customization = Base64Url.decode(vector.requiredString("customization"))
        val derivedKey = Base64Url.decode(vector.requiredString("derived_key"))
        val outputLength = vector.requiredLong("output_length").toInt()

        try {
            assertEquals("KMAC256", vector.requiredString("alg"))
            val kmac = KMAC(256, customization)
            kmac.init(org.bouncycastle.crypto.params.KeyParameter(key))
            kmac.update(context, 0, context.size)
            val out = ByteArray(outputLength)
            kmac.doFinal(out, 0, outputLength)
            try {
                assertTrue(out.contentEquals(derivedKey))
            } finally {
                out.fill(0)
            }
        } finally {
            key.fill(0)
            derivedKey.fill(0)
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
        validateHmacVector(vectors.requiredObject("hmac_sha384"), "HmacSHA384", tagLength = 48)
        validateHmacVector(vectors.requiredObject("hmac_sha512"), "HmacSHA512", tagLength = 64)
    }

    @Test
    fun hkdfVectorsMatchBouncyCastle() {
        validateHkdfVector("hkdf.json", SHA256Digest(), "HKDF-SHA256", "SHA-256")
        validateHkdfVector("hkdf_sha384.json", SHA384Digest(), "HKDF-SHA384", "SHA-384")
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
        validateAesKwShape("aes128kw.json", expectedAlgorithm = "AES-128-KW", kekLength = 16, keyDataLength = 16)
        validateAesKwShape("aes192kw.json", expectedAlgorithm = "AES-192-KW", kekLength = 24, keyDataLength = 16)
        validateAesKwShape("aes256kw.json", expectedAlgorithm = "AES-256-KW", kekLength = 32, keyDataLength = 32)
        validateChaCha20Poly1305Shape()
        validateHmacShape()
        validatePbkdf2Shape()
        validateKmac256Shape()
        validateHashShape()
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
    }

    @Test
    fun manifestDeclaresKotlinBouncyCastleExecutableCoverage() {
        val manifest = JsonObject.parse(readVector("manifest.json"))
        val lane = manifest.requiredObjectArray("runtime_lanes")
            .first { it.requiredString("name") == "kotlin-native-jvm" }

        assertEquals("executable", lane.requiredString("status"))
        assertEquals(
            "cd crates/conformance/platform/kotlin && ./gradlew test --rerun-tasks",
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
                "HPKE-P256-SHA256-AES256GCM",
                "HPKE-X25519-SHA256-CHACHA20POLY1305",
                "AES-128-GCM",
                "AES-192-GCM",
                "AES-256-GCM",
                "AES-128-KW",
                "AES-192-KW",
                "AES-256-KW",
                "ChaCha20-Poly1305",
                "HMAC-SHA-256",
                "HMAC-SHA-384",
                "HMAC-SHA-512",
                "HKDF-SHA256",
                "HKDF-SHA384",
                "JWA-CONCAT-KDF-SHA256",
                "KMAC256",
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
        assertContains(notes, "Bouncy Castle bcprov-jdk18on 1.85.2")
        assertContains(notes, "--rerun-tasks")
    }

}
