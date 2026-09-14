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

class ReallyMeCryptoSymmetricTest : ReallyMeCryptoTestSupport() {
    @Test
    fun sha256KnownAnswer() {
        val digest = ReallyMeDigest.sha256("abc".toByteArray())
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            digest.joinToString("") { "%02x".format(it) },
        )
    }

    @Test
    fun genericFacadeHashesSupportedSha2() {
        val bytes = "abc".toByteArray()

        assertContentEquals(
            ReallyMeDigest.sha256(bytes),
            ReallyMeCrypto.hash(ReallyMeHashAlgorithm.SHA2_256, bytes),
        )
        assertContentEquals(
            ReallyMeDigest.sha384(bytes),
            ReallyMeCrypto.hash(ReallyMeHashAlgorithm.SHA2_384, bytes),
        )
        assertContentEquals(
            ReallyMeDigest.sha512(bytes),
            ReallyMeCrypto.hash(ReallyMeHashAlgorithm.SHA2_512, bytes),
        )
    }

    @Test
    fun genericFacadeHashesSupportedSha3KnownAnswers() {
        val bytes = "abc".toByteArray()

        assertEquals(
            "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
            ReallyMeCrypto.hash(ReallyMeHashAlgorithm.SHA3_224, bytes).toHex(),
        )
        assertEquals(
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
            ReallyMeCrypto.hash(ReallyMeHashAlgorithm.SHA3_256, bytes).toHex(),
        )
        assertEquals(
            "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2" +
                "98d88cea927ac7f539f1edf228376d25",
            ReallyMeCrypto.hash(ReallyMeHashAlgorithm.SHA3_384, bytes).toHex(),
        )
        assertEquals(
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e" +
                "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
            ReallyMeCrypto.hash(ReallyMeHashAlgorithm.SHA3_512, bytes).toHex(),
        )
    }

    // HMAC key/message/tags are vectors/hmac.json (RFC 4231 test case 1) —
    // the same KAT the conformance lanes prove.
    @Test
    fun genericFacadeHmacKnownAnswers() {
        val key = bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        val message = bytes("4869205468657265")
        val sha256Tag = ReallyMeCrypto.authenticate(
            ReallyMeMacAlgorithm.HMAC_SHA256,
            key,
            message,
        )
        val sha384Tag = ReallyMeCrypto.authenticate(
            ReallyMeMacAlgorithm.HMAC_SHA384,
            key,
            message,
        )
        val sha512Tag = ReallyMeCrypto.authenticate(
            ReallyMeMacAlgorithm.HMAC_SHA512,
            key,
            message,
        )

        assertContentEquals(
            bytes(
                "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c" +
                    "faea9ea9076ede7f4af152e8b2fa9cb6",
            ),
            sha384Tag,
        )
        assertContentEquals(
            bytes("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
            sha256Tag,
        )
        assertContentEquals(
            bytes(
                "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cd" +
                    "edaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
            ),
            sha512Tag,
        )
        assertTrue(ReallyMeCrypto.verifyMac(ReallyMeMacAlgorithm.HMAC_SHA256, sha256Tag, key, message))
        assertTrue(ReallyMeCrypto.verifyMac(ReallyMeMacAlgorithm.HMAC_SHA384, sha384Tag, key, message))
        assertTrue(ReallyMeCrypto.verifyMac(ReallyMeMacAlgorithm.HMAC_SHA512, sha512Tag, key, message))
    }

    @Test
    fun genericFacadeHmacRejectsInvalidInputAndTampering() {
        val key = bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        val message = bytes("4869205468657265")
        val tag = ReallyMeCrypto.authenticate(ReallyMeMacAlgorithm.HMAC_SHA256, key, message)
        tag[0] = (tag[0].toInt() xor 0x01).toByte()

        assertFalse(ReallyMeCrypto.verifyMac(ReallyMeMacAlgorithm.HMAC_SHA256, tag, key, message))
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.authenticate(ReallyMeMacAlgorithm.HMAC_SHA256, ByteArray(0), message)
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.verifyMac(ReallyMeMacAlgorithm.HMAC_SHA256, ByteArray(1), key, message)
        }
    }

    @Test
    fun genericFacadeAes128GcmKnownAnswerAndTampering() {
        val key = vectorField("aes128gcm.json", "key")
        val nonce = vectorField("aes128gcm.json", "nonce")
        val aad = vectorField("aes128gcm.json", "aad")
        val plaintext = vectorField("aes128gcm.json", "plaintext")
        val ciphertext = vectorField("aes128gcm.json", "ciphertext_with_tag")

        assertContentEquals(
            ciphertext,
            ReallyMeCrypto.seal(ReallyMeAeadAlgorithm.AES_128_GCM, key, nonce, aad, plaintext),
        )
        assertContentEquals(
            plaintext,
            ReallyMeCrypto.open(ReallyMeAeadAlgorithm.AES_128_GCM, key, nonce, aad, ciphertext),
        )

        val tampered = ciphertext.copyOf()
        tampered[0] = (tampered[0].toInt() xor 0x01).toByte()
        assertFailsWith<ReallyMeCryptoException.AuthenticationFailed> {
            ReallyMeCrypto.open(ReallyMeAeadAlgorithm.AES_128_GCM, key, nonce, aad, tampered)
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.seal(
                ReallyMeAeadAlgorithm.AES_128_GCM,
                ByteArray(32),
                nonce,
                aad,
                plaintext,
            )
        }
    }

    @Test
    fun genericFacadeAes192GcmKnownAnswerAndTampering() {
        val key = vectorField("aes192gcm.json", "key")
        val nonce = vectorField("aes192gcm.json", "nonce")
        val aad = vectorField("aes192gcm.json", "aad")
        val plaintext = vectorField("aes192gcm.json", "plaintext")
        val ciphertext = vectorField("aes192gcm.json", "ciphertext_with_tag")

        assertContentEquals(
            ciphertext,
            ReallyMeCrypto.seal(ReallyMeAeadAlgorithm.AES_192_GCM, key, nonce, aad, plaintext),
        )
        assertContentEquals(
            plaintext,
            ReallyMeCrypto.open(ReallyMeAeadAlgorithm.AES_192_GCM, key, nonce, aad, ciphertext),
        )

        val tampered = ciphertext.copyOf()
        tampered[0] = (tampered[0].toInt() xor 0x01).toByte()
        assertFailsWith<ReallyMeCryptoException.AuthenticationFailed> {
            ReallyMeCrypto.open(ReallyMeAeadAlgorithm.AES_192_GCM, key, nonce, aad, tampered)
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.open(
                ReallyMeAeadAlgorithm.AES_192_GCM,
                key,
                nonce,
                aad,
                ByteArray(ReallyMeAesGcm.TAG_LENGTH - 1),
            )
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.seal(
                ReallyMeAeadAlgorithm.AES_192_GCM,
                ByteArray(16),
                nonce,
                aad,
                plaintext,
            )
        }
    }

    @Test
    fun genericFacadeAes256GcmKnownAnswerAndTampering() {
        val key = base64UrlBytes("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
        val nonce = base64UrlBytes("oKGio6Slpqeoqaqr")
        val aad = base64UrlBytes("cmVhbGx5bWUtY3J5cHRvLXZlY3Rvci1hYWQ")
        val plaintext = base64UrlBytes("UmVhbGx5TWUgQUVTLTI1Ni1HQ00gY29uZm9ybWFuY2UgdmVjdG9y")
        val ciphertext = base64UrlBytes(
            "tH0dQSmyT9pCJMKAKkj16F3rGl2y1C0C-mFU6x7FFmTyACKc200hQ-HjxbBMVxDl2Nsc_KOsUQ",
        )

        assertContentEquals(
            ciphertext,
            ReallyMeCrypto.seal(ReallyMeAeadAlgorithm.AES_256_GCM, key, nonce, aad, plaintext),
        )
        assertContentEquals(
            plaintext,
            ReallyMeCrypto.open(ReallyMeAeadAlgorithm.AES_256_GCM, key, nonce, aad, ciphertext),
        )

        val tampered = ciphertext.copyOf()
        tampered[0] = (tampered[0].toInt() xor 0x01).toByte()
        assertFailsWith<ReallyMeCryptoException.AuthenticationFailed> {
            ReallyMeCrypto.open(ReallyMeAeadAlgorithm.AES_256_GCM, key, nonce, aad, tampered)
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.seal(ReallyMeAeadAlgorithm.AES_256_GCM, byteArrayOf(0x00), nonce, aad, plaintext)
        }
    }

    @Test
    fun rustAeadProviderKnownAnswersWhenLoaded() {
        val libraryPath = System.getenv("REALLYME_CRYPTO_FFI_LIBRARY_PATH")
        if (libraryPath.isNullOrEmpty()) {
            return
        }

        ReallyMeRustNativeProvider.loadLibrary(libraryPath)
        assertRustAeadRoundTrip(
            algorithm = ReallyMeAeadAlgorithm.AES_256_GCM_SIV,
            key = base64UrlBytes("MDEyMzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk8"),
            nonce = base64UrlBytes("0NHS09TV1tfY2drb"),
            aad = base64UrlBytes("cmVhbGx5bWUtY3J5cHRvLWdjbS1zaXYtdmVjdG9yLWFhZA"),
            plaintext = base64UrlBytes("UmVhbGx5TWUgQUVTLTI1Ni1HQ00tU0lWIGNvbmZvcm1hbmNlIHZlY3Rvcg"),
            ciphertext = base64UrlBytes(
                "830aIA-5lFFihlRNK2QIUHoFRAQXaaBqX2nDndhvyVq-EcnpsGqtqHVZC1bTdM8kugkvV_o3Ve9HQq4",
            ),
        )
        assertRustAeadRoundTrip(
            algorithm = ReallyMeAeadAlgorithm.CHACHA20_POLY1305,
            key = base64UrlBytes("EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8"),
            nonce = base64UrlBytes("oKGio6Slpqeoqaqr"),
            aad = base64UrlBytes("cmVhbGx5bWUtY3J5cHRvLWNoYWNoYS12ZWN0b3ItYWFk"),
            plaintext = base64UrlBytes("UmVhbGx5TWUgQ2hhQ2hhMjAtUG9seTEzMDUgY29uZm9ybWFuY2UgdmVjdG9y"),
            ciphertext = base64UrlBytes(
                "Qjm7Nj2eiPvYGaooqr38rmuSA9awZt2Pvin_CzaZZG0nma6M1z9ITx4vTrjiBaAlakwqodWU2VostKbbVg",
            ),
        )
        assertRustAeadRoundTrip(
            algorithm = ReallyMeAeadAlgorithm.XCHACHA20_POLY1305,
            key = base64UrlBytes("EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8"),
            nonce = base64UrlBytes("sLGys7S1tre4ubq7vL2-v8DBwsPExcbH"),
            aad = base64UrlBytes("cmVhbGx5bWUtY3J5cHRvLWNoYWNoYS12ZWN0b3ItYWFk"),
            plaintext = base64UrlBytes("UmVhbGx5TWUgQ2hhQ2hhMjAtUG9seTEzMDUgY29uZm9ybWFuY2UgdmVjdG9y"),
            ciphertext = base64UrlBytes(
                "PaGz1pCJhIoCzTRgbz_xBf2PIGFhWUpptCP_BgisAl_zRTk565yv62NWfuEFOpomXSETJ68qwZAH1Zjoxg",
            ),
        )
    }

    @Test
    fun rustNativeFacadesRejectOversizedInputsBeforeDispatch() {
        val oversizedAeadInput = ByteArray(ReallyMeRustAead.MAX_INPUT_LENGTH + 1)
        val oversizedAeadCiphertext =
            ByteArray(ReallyMeRustAead.MAX_INPUT_LENGTH + ReallyMeRustAead.TAG_LENGTH + 1)
        val oversizedArgonSecret = ByteArray(ReallyMeArgon2id.SECRET_MAX_LENGTH + 1)
        val key = ByteArray(ReallyMeRustAead.KEY_LENGTH)
        val nonce = ByteArray(ReallyMeRustAead.AES_GCM_SIV_NONCE_LENGTH)
        val salt = ByteArray(ReallyMeArgon2id.SALT_MIN_LENGTH)

        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeRustAead.sealAes256GcmSiv(key, nonce, ByteArray(0), oversizedAeadInput)
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeRustAead.openAes256GcmSiv(key, nonce, ByteArray(0), oversizedAeadCiphertext)
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeArgon2id.deriveKey(ReallyMeArgon2id.V1, oversizedArgonSecret, salt)
        }

        oversizedAeadInput.fill(0)
        oversizedAeadCiphertext.fill(0)
        oversizedArgonSecret.fill(0)
        key.fill(0)
        salt.fill(0)
    }

    @Test
    fun genericFacadeAesKwKnownAnswersAndTampering() {
        val vectors = listOf(
            Triple(
                ReallyMeKeyWrapAlgorithm.AES_128_KW,
                "aes128kw.json",
                "AES-128-KW",
            ),
            Triple(
                ReallyMeKeyWrapAlgorithm.AES_192_KW,
                "aes192kw.json",
                "AES-192-KW",
            ),
            Triple(
                ReallyMeKeyWrapAlgorithm.AES_256_KW,
                "aes256kw.json",
                "AES-256-KW",
            ),
        )

        for ((algorithm, vectorName, expectedAlgorithm) in vectors) {
            val kek = vectorField(vectorName, "kek")
            val keyData = vectorField(vectorName, "key_data")
            val wrappedKey = vectorField(vectorName, "wrapped_key")

            assertEquals(expectedAlgorithm, vectorString(vectorName, "alg"))
            val producedWrappedKey = ReallyMeCrypto.wrapKey(algorithm, kek, keyData)
            assertEquals(keyData.size + ReallyMeAesKw.INTEGRITY_LENGTH, producedWrappedKey.size)
            assertContentEquals(wrappedKey, producedWrappedKey)
            val producedKeyData = ReallyMeCrypto.unwrapKey(algorithm, kek, wrappedKey)
            assertEquals(wrappedKey.size - ReallyMeAesKw.INTEGRITY_LENGTH, producedKeyData.size)
            assertContentEquals(keyData, producedKeyData)

            val tampered = wrappedKey.copyOf()
            tampered[0] = (tampered[0].toInt() xor 0x01).toByte()
            assertFailsWith<ReallyMeCryptoException.AuthenticationFailed> {
                ReallyMeCrypto.unwrapKey(algorithm, kek, tampered)
            }
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.wrapKey(
                ReallyMeKeyWrapAlgorithm.AES_256_KW,
                byteArrayOf(0x00),
                vectorField("aes256kw.json", "key_data"),
            )
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.wrapKey(
                ReallyMeKeyWrapAlgorithm.AES_256_KW,
                vectorField("aes256kw.json", "kek"),
                ByteArray(8),
            )
        }
    }

    @Test
    fun kmac256RustNativeProviderKnownAnswerWhenLoaded() {
        if (loadCryptoProviderForTestOrReturn() == null) {
            return
        }
        val key = vectorField("kmac256.json", "key")
        val context = vectorField("kmac256.json", "context")
        val customization = vectorField("kmac256.json", "customization")
        val expected = vectorField("kmac256.json", "derived_key")

        assertEquals("KMAC256", vectorString("kmac256.json", "alg"))
        assertContentEquals(
            expected,
            ReallyMeCrypto.deriveKmac256(
                ReallyMeKdfAlgorithm.KMAC256,
                key,
                context,
                customization,
                expected.size,
            ),
        )
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.deriveKmac256(
                ReallyMeKdfAlgorithm.KMAC256,
                key.copyOf(31),
                context,
                customization,
                64,
            )
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.deriveKmac256(
                ReallyMeKdfAlgorithm.KMAC256,
                key,
                ByteArray(ReallyMeKmac.MAX_CONTEXT_LENGTH + 1),
                customization,
                64,
            )
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.deriveKmac256(
                ReallyMeKdfAlgorithm.KMAC256,
                key,
                context,
                ByteArray(ReallyMeKmac.MAX_CUSTOMIZATION_LENGTH + 1),
                64,
            )
        }
    }

    @Test
    fun genericFacadePbkdf2KnownAnswers() {
        val password = "password".toByteArray()
        val salt = "salt".toByteArray()

        assertContentEquals(
            bytes("0394a2ede332c9a13eb82e9b24631604c31df978b4e2f0fbd2c549944f9d79a5"),
            ReallyMeCrypto.deriveKey(
                ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA256,
                password,
                salt,
                100_000u,
                32,
            ),
        )
        assertContentEquals(
            bytes(
                "f5d17022c96af46c0a1dc49a58bbe654a28e98104883e4af4de974cda2c74122" +
                    "dd082f4105a93fc80692ca4eb1a784cfeda81bfaa33f5192cc9143d818bd7581",
            ),
            ReallyMeCrypto.deriveKey(
                ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA512,
                password,
                salt,
                100_000u,
                64,
            ),
        )
    }

    @Test
    fun genericFacadePbkdf2RejectsInvalidInputsAndUnsupportedKdf() {
        val password = "password".toByteArray()
        val salt = "salt".toByteArray()

        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.deriveKey(
                ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA256,
                ByteArray(0),
                salt,
                100_000u,
                32,
            )
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.deriveKey(
                ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA256,
                password,
                ByteArray(0),
                100_000u,
                32,
            )
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.deriveKey(
                ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA256,
                password,
                salt,
                0u,
                32,
            )
        }
        assertFailsWith<ReallyMeCryptoException.UnsupportedAlgorithm> {
            ReallyMeCrypto.deriveKey(
                ReallyMeKdfAlgorithm.HKDF_SHA256,
                password,
                salt,
                1u,
                32,
            )
        }
        try {
            assertContentEquals(
                bytes("53334265f014b5a46f2b3fce4de2c965669b6cd3a4879366385dfc301c234757"),
                ReallyMeCrypto.deriveArgon2id(
                    1u,
                    password,
                    "somesaltvalue1234".toByteArray(),
                ),
            )
        } catch (_: ReallyMeCryptoException.ProviderFailure) {
            // The default test lane intentionally leaves the explicit Rust
            // provider unloaded. Provider-enabled matrix jobs execute and
            // assert the same known answer instead.
        }
    }

    @Test
    fun pbkdf2IterationConversionEnforcesPublicWorkBounds() {
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMePbkdf2.checkedIterationCount(1u)
        }
        assertEquals(
            ReallyMePbkdf2.MIN_ITERATIONS.toInt(),
            ReallyMePbkdf2.checkedIterationCount(ReallyMePbkdf2.MIN_ITERATIONS),
        )
        assertEquals(
            ReallyMePbkdf2.MAX_ITERATIONS.toInt(),
            ReallyMePbkdf2.checkedIterationCount(ReallyMePbkdf2.MAX_ITERATIONS),
        )
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMePbkdf2.checkedIterationCount(ReallyMePbkdf2.MAX_ITERATIONS + 1u)
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMePbkdf2.checkedIterationCount(UInt.MAX_VALUE)
        }
    }

    @Test
    fun argon2idRustNativeProviderKnownAnswerWhenLoaded() {
        val libraryPath = System.getenv("REALLYME_CRYPTO_FFI_LIBRARY_PATH")
        if (libraryPath.isNullOrEmpty()) {
            return
        }

        ReallyMeRustNativeProvider.loadLibrary(libraryPath)
        val secret = "password".toByteArray()
        val salt = "somesaltvalue1234".toByteArray()
        val expected = bytes("53334265f014b5a46f2b3fce4de2c965669b6cd3a4879366385dfc301c234757")

        assertContentEquals(expected, ReallyMeArgon2id.deriveKey(1u, secret, salt))
        assertContentEquals(expected, ReallyMeCrypto.deriveArgon2id(1u, secret, salt))

        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeArgon2id.deriveKey(99u, secret, salt)
        }
        assertFailsWith<ReallyMeCryptoException.UnsupportedAlgorithm> {
            ReallyMeCrypto.deriveKey(ReallyMeKdfAlgorithm.ARGON2ID, secret, salt, 1u, 32)
        }
    }

    @Test
    fun genericFacadeHkdfKnownAnswer() {
        val inputKeyMaterial = bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        val salt = bytes("000102030405060708090a0b0c")
        val info = bytes("f0f1f2f3f4f5f6f7f8f9")

        assertContentEquals(
            bytes(
                "3cb25f25faacd57a90434f64d0362f2a" +
                    "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
                    "34007208d5b887185865",
            ),
            ReallyMeCrypto.deriveHkdf(
                ReallyMeKdfAlgorithm.HKDF_SHA256,
                inputKeyMaterial,
                salt,
                info,
                42,
            ),
        )
        assertContentEquals(
            bytes(
                "9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f7" +
                    "48b6457763e4f0204fc5",
            ),
            ReallyMeCrypto.deriveHkdf(
                ReallyMeKdfAlgorithm.HKDF_SHA384,
                inputKeyMaterial,
                salt,
                info,
                42,
            ),
        )
    }

    @Test
    fun genericFacadeHkdfRejectsInvalidInputsAndUnsupportedKdf() {
        val salt = bytes("000102030405060708090a0b0c")
        val info = bytes("f0f1f2f3f4f5f6f7f8f9")

        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.deriveHkdf(
                ReallyMeKdfAlgorithm.HKDF_SHA256,
                ByteArray(0),
                salt,
                info,
                42,
            )
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.deriveHkdf(
                ReallyMeKdfAlgorithm.HKDF_SHA256,
                byteArrayOf(0x0b),
                salt,
                info,
                0,
            )
        }
        assertFailsWith<ReallyMeCryptoException.UnsupportedAlgorithm> {
            ReallyMeCrypto.deriveHkdf(
                ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA256,
                byteArrayOf(0x0b),
                salt,
                info,
                42,
            )
        }
    }

    @Test
    fun genericFacadeJwaConcatKdfMatchesSharedVector() {
        val sharedSecret = vectorField("concat_kdf.json", "shared_secret")
        val algorithmId = vectorField("concat_kdf.json", "algorithm_id")
        val partyUInfo = vectorField("concat_kdf.json", "party_u_info")
        val partyVInfo = vectorField("concat_kdf.json", "party_v_info")
        val outputLength = vectorNumber("concat_kdf.json", "output_len")
        val derivedKey = vectorField("concat_kdf.json", "derived_key")

        assertContentEquals(
            derivedKey,
            ReallyMeJwaConcatKdf.deriveSha256(
                sharedSecret,
                algorithmId,
                partyUInfo,
                partyVInfo,
                outputLength,
            ),
        )
        assertContentEquals(
            derivedKey,
            ReallyMeCrypto.deriveJwaConcatKdfSha256(
                ReallyMeKdfAlgorithm.JWA_CONCAT_KDF_SHA256,
                sharedSecret,
                algorithmId,
                partyUInfo,
                partyVInfo,
                outputLength,
            ),
        )
    }

    @Test
    fun genericFacadeJwaConcatKdfRejectsInvalidInputsAndUnsupportedKdf() {
        val sharedSecret = vectorField("concat_kdf.json", "shared_secret")
        val algorithmId = vectorField("concat_kdf.json", "algorithm_id")
        val partyUInfo = vectorField("concat_kdf.json", "party_u_info")
        val partyVInfo = vectorField("concat_kdf.json", "party_v_info")
        val outputLength = vectorNumber("concat_kdf.json", "output_len")

        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.deriveJwaConcatKdfSha256(
                ReallyMeKdfAlgorithm.JWA_CONCAT_KDF_SHA256,
                ByteArray(0),
                algorithmId,
                partyUInfo,
                partyVInfo,
                outputLength,
            )
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.deriveJwaConcatKdfSha256(
                ReallyMeKdfAlgorithm.JWA_CONCAT_KDF_SHA256,
                sharedSecret,
                ByteArray(0),
                partyUInfo,
                partyVInfo,
                outputLength,
            )
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.deriveJwaConcatKdfSha256(
                ReallyMeKdfAlgorithm.JWA_CONCAT_KDF_SHA256,
                sharedSecret,
                algorithmId,
                partyUInfo,
                partyVInfo,
                0,
            )
        }
        assertFailsWith<ReallyMeCryptoException.UnsupportedAlgorithm> {
            ReallyMeCrypto.deriveJwaConcatKdfSha256(
                ReallyMeKdfAlgorithm.HKDF_SHA256,
                sharedSecret,
                algorithmId,
                partyUInfo,
                partyVInfo,
                outputLength,
            )
        }
    }

}
