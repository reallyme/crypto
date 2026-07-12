// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import java.math.BigInteger
import java.nio.file.Files
import java.nio.file.Path
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ReallyMeCryptoTest {
    @Test
    fun providerCatalogIsExplicit() {
        assertEquals(
            listOf(
                ReallyMeCryptoProvider.KOTLIN_JDK_STDLIB,
                ReallyMeCryptoProvider.JCA_JCE,
                ReallyMeCryptoProvider.BOUNCY_CASTLE,
                ReallyMeCryptoProvider.LIBSECP256K1,
                ReallyMeCryptoProvider.RUST_C_ABI,
            ),
            ReallyMeCryptoProviderCatalog.compiledProviders,
        )
    }

    @Test
    fun multicodecPrefixVectorsMatchSharedContract() {
        codecPrefixVectors()
            .mapNotNull { entry ->
                try {
                    ReallyMeMulticodec.algorithmForCodecName(entry.name) to entry
                } catch (_: ReallyMeCryptoException.UnsupportedAlgorithm) {
                    null
                }
            }
            .forEach { (algorithm, entry) ->
                assertEquals(entry.name, ReallyMeMulticodec.codecName(algorithm))
                assertEquals(entry.alg, ReallyMeMulticodec.algorithmName(algorithm))
                assertContentEquals(entry.prefix, ReallyMeMulticodec.prefix(algorithm), entry.name)
            }
    }

    @Test
    fun multikeyVectorRoundTrips() {
        val codecName = vectorString("codecs.json", "multicodec_name")
        val algorithmName = vectorString("codecs.json", "multicodec_alg")
        val multikey = vectorString("codecs.json", "multikey")
        val parsed = ReallyMeMultikey.parse(multikey)

        assertEquals(codecName, parsed.algorithm.codecName)
        assertEquals(algorithmName, parsed.algorithmName)
        assertEquals(32, parsed.expectedPublicKeyLength)
        assertEquals(32, parsed.publicKey.size)
        assertEquals(multikey, ReallyMeMultikey.encode(parsed.algorithm, parsed.publicKey))
    }

    @Test
    fun jwkVectorsMatchPackageFacade() {
        jwkVectors().forEach { vector ->
            val algorithm = ReallyMeJwkAlgorithm.entries.first { it.algorithmName == vector.alg }
            val publicKey = base64UrlBytes(vector.publicKey)
            assertEquals(vector.publicKeyLength, publicKey.size)

            val jwk = ReallyMeJwk.toJwk(algorithm, publicKey)
            assertEquals(vector.jwkJcs, ReallyMeJwk.toJcs(jwk))

            val parsed = ReallyMeJwk.fromJwkJson(vector.jwkJcs)
            assertEquals(algorithm, parsed.algorithm)
            assertContentEquals(publicKey, parsed.publicKey)
            assertEquals(vector.jwkJcs, ReallyMeJwk.toJcs(parsed.jwk))
        }
    }

    @Test
    fun multikeyRejectsMalformedInputs() {
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeMultikey.parse("")
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeMultikey.parse("uAAAA")
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeMultikey.parse("z0")
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeMultikey.parse("z2")
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeMultikey.encode(
                ReallyMeMulticodecKeyAlgorithm.ED25519_PUBLIC_KEY,
                ByteArray(31),
            )
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeMultikey.encode(ReallyMeMulticodecKeyAlgorithm.RSA_PUBLIC_KEY, ByteArray(0))
        }
        assertFailsWith<ReallyMeCryptoException.UnsupportedAlgorithm> {
            ReallyMeMulticodec.algorithmForCodecName("not-a-codec")
        }
    }

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
        val sha512Tag = ReallyMeCrypto.authenticate(
            ReallyMeMacAlgorithm.HMAC_SHA512,
            key,
            message,
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
    fun genericFacadeAes256KwKnownAnswerAndTampering() {
        val kek = base64UrlBytes("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
        val keyData = base64UrlBytes("ABEiM0RVZneImaq7zN3u_wABAgMEBQYHCAkKCwwNDg8")
        val wrappedKey = base64UrlBytes("KMn0BMS4EPTLzLNc-4f4Jj9XhuLYDtMmy8fw5xqZ9Dv7mIubegLdIQ")

        assertContentEquals(wrappedKey, ReallyMeCrypto.wrapKey(ReallyMeKeyWrapAlgorithm.AES_256_KW, kek, keyData))
        assertContentEquals(keyData, ReallyMeCrypto.unwrapKey(ReallyMeKeyWrapAlgorithm.AES_256_KW, kek, wrappedKey))

        val tampered = wrappedKey.copyOf()
        tampered[0] = (tampered[0].toInt() xor 0x01).toByte()
        assertFailsWith<ReallyMeCryptoException.AuthenticationFailed> {
            ReallyMeCrypto.unwrapKey(ReallyMeKeyWrapAlgorithm.AES_256_KW, kek, tampered)
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.wrapKey(ReallyMeKeyWrapAlgorithm.AES_256_KW, byteArrayOf(0x00), keyData)
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.wrapKey(ReallyMeKeyWrapAlgorithm.AES_256_KW, kek, ByteArray(8))
        }
    }

    @Test
    fun genericFacadePbkdf2KnownAnswers() {
        val password = "password".toByteArray()
        val salt = "salt".toByteArray()

        assertContentEquals(
            bytes("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"),
            ReallyMeCrypto.deriveKey(
                ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA256,
                password,
                salt,
                4096u,
                32,
            ),
        )
        assertContentEquals(
            bytes(
                "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5" +
                    "143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5",
            ),
            ReallyMeCrypto.deriveKey(
                ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA512,
                password,
                salt,
                4096u,
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
                4096u,
                32,
            )
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.deriveKey(
                ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA256,
                password,
                ByteArray(0),
                4096u,
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
        assertFailsWith<ReallyMeCryptoException.ProviderFailure> {
            ReallyMeCrypto.deriveKey(
                ReallyMeKdfAlgorithm.ARGON2ID,
                password,
                "somesaltvalue1234".toByteArray(),
                1u,
                ReallyMeArgon2id.DERIVED_KEY_LENGTH,
            )
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
        assertContentEquals(
            expected,
            ReallyMeCrypto.deriveKey(
                ReallyMeKdfAlgorithm.ARGON2ID,
                secret,
                salt,
                1u,
                ReallyMeArgon2id.DERIVED_KEY_LENGTH,
            ),
        )

        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeArgon2id.deriveKey(99u, secret, salt)
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.deriveKey(
                ReallyMeKdfAlgorithm.ARGON2ID,
                secret,
                salt,
                1u,
                ReallyMeArgon2id.DERIVED_KEY_LENGTH - 1,
            )
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

    @Test
    fun genericFacadeRemainingFamiliesReturnTypedUnsupportedAlgorithm() {
        val empty = ByteArray(0)

        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.seal(ReallyMeAeadAlgorithm.AES_256_GCM_SIV, empty, empty, empty, empty)
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.seal(ReallyMeAeadAlgorithm.CHACHA20_POLY1305, empty, empty, empty, empty)
        }
        assertEquals(5, ReallyMeKemAlgorithm.entries.size)
    }

    @Test
    fun genericFacadeSupportedAlgorithmSetsAreExplicit() {
        assertEquals(
            setOf(
                ReallyMeHashAlgorithm.SHA2_256,
                ReallyMeHashAlgorithm.SHA2_384,
                ReallyMeHashAlgorithm.SHA2_512,
                ReallyMeHashAlgorithm.SHA3_224,
                ReallyMeHashAlgorithm.SHA3_256,
                ReallyMeHashAlgorithm.SHA3_384,
                ReallyMeHashAlgorithm.SHA3_512,
            ),
            ReallyMeHashAlgorithm.entries.toSet(),
        )
        assertEquals(
            setOf(ReallyMeMacAlgorithm.HMAC_SHA256, ReallyMeMacAlgorithm.HMAC_SHA512),
            ReallyMeMacAlgorithm.entries.toSet(),
        )
        assertEquals(
            setOf(
                ReallyMeKeyAgreementAlgorithm.X25519,
                ReallyMeKeyAgreementAlgorithm.P256_ECDH,
                ReallyMeKeyAgreementAlgorithm.P384_ECDH,
                ReallyMeKeyAgreementAlgorithm.P521_ECDH,
            ),
            ReallyMeKeyAgreementAlgorithm.entries.toSet(),
        )
    }

    @Test
    fun genericFacadeUnsupportedSignaturesAreExhaustive() {
        val empty = ByteArray(0)
        val generationSupported = setOf(
            ReallyMeSignatureAlgorithm.ED25519,
            ReallyMeSignatureAlgorithm.ECDSA_P256_SHA256,
            ReallyMeSignatureAlgorithm.ECDSA_P384_SHA384,
            ReallyMeSignatureAlgorithm.ECDSA_P521_SHA512,
            ReallyMeSignatureAlgorithm.ECDSA_SECP256K1_SHA256,
            ReallyMeSignatureAlgorithm.BIP340_SCHNORR_SECP256K1_SHA256,
            ReallyMeSignatureAlgorithm.ML_DSA_44,
            ReallyMeSignatureAlgorithm.ML_DSA_65,
            ReallyMeSignatureAlgorithm.ML_DSA_87,
            ReallyMeSignatureAlgorithm.SLH_DSA_SHA2_128S,
        )
        val signingSupported = setOf(
            ReallyMeSignatureAlgorithm.ED25519,
            ReallyMeSignatureAlgorithm.ECDSA_P256_SHA256,
            ReallyMeSignatureAlgorithm.ECDSA_P384_SHA384,
            ReallyMeSignatureAlgorithm.ECDSA_P521_SHA512,
            ReallyMeSignatureAlgorithm.ECDSA_SECP256K1_SHA256,
            ReallyMeSignatureAlgorithm.ML_DSA_44,
            ReallyMeSignatureAlgorithm.ML_DSA_65,
            ReallyMeSignatureAlgorithm.ML_DSA_87,
            ReallyMeSignatureAlgorithm.SLH_DSA_SHA2_128S,
        )
        val verificationSupported = generationSupported

        ReallyMeSignatureAlgorithm.entries
            .filter { algorithm -> !generationSupported.contains(algorithm) }
            .forEach { algorithm ->
                assertFailsWith<ReallyMeCryptoException.UnsupportedAlgorithm>(message = algorithm.algorithmName) {
                    ReallyMeCrypto.generateKeyPair(algorithm)
                }
            }

        ReallyMeSignatureAlgorithm.entries
            .filter { algorithm -> !signingSupported.contains(algorithm) }
            .forEach { algorithm ->
                assertFailsWith<ReallyMeCryptoException.UnsupportedAlgorithm>(message = algorithm.algorithmName) {
                    ReallyMeCrypto.sign(algorithm, empty, empty)
                }
            }

        ReallyMeSignatureAlgorithm.entries
            .filter { algorithm -> !verificationSupported.contains(algorithm) }
            .forEach { algorithm ->
                assertFailsWith<ReallyMeCryptoException.UnsupportedAlgorithm>(message = algorithm.algorithmName) {
                    ReallyMeCrypto.verify(algorithm, empty, empty, empty)
                }
            }
    }

    @Test
    fun genericFacadeUnsupportedReservedFamiliesAreExhaustive() {
        val empty = ByteArray(0)
        val providerAwareAeadAlgorithms = setOf(
            ReallyMeAeadAlgorithm.AES_256_GCM_SIV,
            ReallyMeAeadAlgorithm.CHACHA20_POLY1305,
            ReallyMeAeadAlgorithm.XCHACHA20_POLY1305,
        )

        ReallyMeAeadAlgorithm.entries
            .filter { algorithm -> providerAwareAeadAlgorithms.contains(algorithm) }
            .forEach { algorithm ->
                assertFailsWith<ReallyMeCryptoException.InvalidInput>(message = algorithm.algorithmName) {
                    ReallyMeCrypto.seal(algorithm, empty, empty, empty, empty)
                }
                assertFailsWith<ReallyMeCryptoException.InvalidInput>(message = algorithm.algorithmName) {
                    ReallyMeCrypto.open(algorithm, empty, empty, empty, empty)
                }
            }

        assertEquals(2, ReallyMeHpkeSuite.entries.size)
    }

    @Test
    fun genericFacadeUnsupportedKdfRoutesAreExhaustive() {
        val empty = ByteArray(0)
        val deriveKeySupported = setOf(
            ReallyMeKdfAlgorithm.ARGON2ID,
            ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA256,
            ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA512,
        )
        val deriveHkdfSupported = setOf(ReallyMeKdfAlgorithm.HKDF_SHA256)
        val deriveJwaConcatKdfSupported = setOf(ReallyMeKdfAlgorithm.JWA_CONCAT_KDF_SHA256)

        ReallyMeKdfAlgorithm.entries
            .filter { algorithm -> !deriveKeySupported.contains(algorithm) }
            .forEach { algorithm ->
                assertFailsWith<ReallyMeCryptoException.UnsupportedAlgorithm>(message = algorithm.algorithmName) {
                    ReallyMeCrypto.deriveKey(algorithm, empty, empty, 1u, 1)
                }
            }

        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.deriveKey(ReallyMeKdfAlgorithm.ARGON2ID, empty, empty, 1u, 1)
        }

        ReallyMeKdfAlgorithm.entries
            .filter { algorithm -> !deriveHkdfSupported.contains(algorithm) }
            .forEach { algorithm ->
                assertFailsWith<ReallyMeCryptoException.UnsupportedAlgorithm>(message = algorithm.algorithmName) {
                    ReallyMeCrypto.deriveHkdf(algorithm, empty, empty, empty, 1)
                }
            }

        ReallyMeKdfAlgorithm.entries
            .filter { algorithm -> !deriveJwaConcatKdfSupported.contains(algorithm) }
            .forEach { algorithm ->
                assertFailsWith<ReallyMeCryptoException.UnsupportedAlgorithm>(message = algorithm.algorithmName) {
                    ReallyMeCrypto.deriveJwaConcatKdfSha256(algorithm, empty, empty, empty, empty, 1)
                }
            }
    }

    // Keypair from vectors/ed25519.json — the same KAT every lane proves.
    private val ed25519SecretKey =
        bytes("9b712355c46a089f4182701852cdef4322116da07e394abcd85f132692a1be77")
    private val ed25519PublicKey =
        bytes("6ddffbec369caae216a5fb99080a6ce013799d8bea00d39804d7a90d73502d82")
    private val ed25519Message =
        bytes("5265616c6c794d65207369676e617475726520636f6e666f726d616e636520766563746f72")
    private val ed25519Signature =
        bytes(
            "69d360b839583ce3632021e8ca6b382533f68e8c53f4996cd84dfda548273659" +
                "3646588752e7d8d22a84cdccdc4cb84e6b8c781e672745aca5ace2443cccde03",
        )

    @Test
    fun ed25519DerivePublicKeyKnownAnswer() {
        assertContentEquals(
            ed25519PublicKey,
            ReallyMeEd25519.derivePublicKey(ed25519SecretKey),
        )
        val keyPair = ReallyMeCrypto.deriveKeyPair(ReallyMeSignatureAlgorithm.ED25519, ed25519SecretKey)
        assertContentEquals(ed25519PublicKey, keyPair.publicKey)
        assertContentEquals(ed25519SecretKey, keyPair.secretKey)
    }

    @Test
    fun ed25519SignIsDeterministicAndVerifies() {
        val first = ReallyMeEd25519.sign(ed25519Message, ed25519SecretKey)
        val second = ReallyMeEd25519.sign(ed25519Message, ed25519SecretKey)

        assertContentEquals(first, second, "Ed25519 signatures must be deterministic")
        assertEquals(ReallyMeEd25519.SIGNATURE_LENGTH, first.size)
        assertContentEquals(ed25519Signature, first)
        ReallyMeEd25519.verify(first, ed25519Message, ed25519PublicKey)
    }

    @Test
    fun genericFacadeEd25519KnownAnswer() {
        val signature = ReallyMeCrypto.sign(
            ReallyMeSignatureAlgorithm.ED25519,
            ed25519Message,
            ed25519SecretKey,
        )

        assertContentEquals(ed25519Signature, signature)
        ReallyMeCrypto.verify(
            ReallyMeSignatureAlgorithm.ED25519,
            signature,
            ed25519Message,
            ed25519PublicKey,
        )
    }

    @Test
    fun ed25519RejectsTamperedSignatureAndMessage() {
        assertFailsWith<ReallyMeCryptoException.InvalidSignature> {
            ReallyMeEd25519.verify(ed25519Signature, ed25519Message + 0x00, ed25519PublicKey)
        }

        val flipped = ed25519Signature.copyOf()
        flipped[10] = (flipped[10].toInt() xor 0xff).toByte()
        assertFailsWith<ReallyMeCryptoException.InvalidSignature> {
            ReallyMeEd25519.verify(flipped, ed25519Message, ed25519PublicKey)
        }
    }

    @Test
    fun ed25519RejectsMalformedInputs() {
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeEd25519.sign(ed25519Message, byteArrayOf(0x01, 0x02))
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeEd25519.derivePublicKey(byteArrayOf(0x01, 0x02))
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.deriveKeyPair(ReallyMeSignatureAlgorithm.ED25519, byteArrayOf(0x01, 0x02))
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeEd25519.verify(ByteArray(ReallyMeEd25519.SIGNATURE_LENGTH - 1), ed25519Message, ed25519PublicKey)
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeEd25519.verify(ed25519Signature, ed25519Message, ByteArray(ReallyMeEd25519.PUBLIC_KEY_LENGTH - 1))
        }
    }

    @Test
    fun ed25519GenerateKeyPairRoundTrip() {
        val keyPair = ReallyMeCrypto.generateKeyPair(ReallyMeSignatureAlgorithm.ED25519)
        assertEquals(ReallyMeEd25519.SECRET_KEY_LENGTH, keyPair.secretKey.size)
        assertEquals(ReallyMeEd25519.PUBLIC_KEY_LENGTH, keyPair.publicKey.size)

        val signature = ReallyMeCrypto.sign(
            ReallyMeSignatureAlgorithm.ED25519,
            ed25519Message,
            keyPair.secretKey,
        )
        ReallyMeCrypto.verify(
            ReallyMeSignatureAlgorithm.ED25519,
            signature,
            ed25519Message,
            keyPair.publicKey,
        )
    }

    private val p256EcdsaSecretKey =
        bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    private val p256EcdsaPublicKey =
        bytes("027a593180860c4037c83c12749845c8ee1424dd297fadcb895e358255d2c7d2b2")
    private val p256EcdsaMessage =
        bytes("48656c6c6f2c20502d32353621")
    private val p256EcdsaSignatureDer =
        bytes(
            "304402204bd4ee72b48883a4d1817e0371c66b6412117183794c6b220fb13590b7f98097" +
                "0220316c6251e714b87c65fd161dd1823e888b1c66d9075ff8cd7ade89d166e935de",
        )

    @Test
    fun p256EcdsaKnownAnswer() {
        assertContentEquals(p256EcdsaPublicKey, ReallyMeP256Ecdsa.derivePublicKey(p256EcdsaSecretKey))
        assertContentEquals(
            p256EcdsaPublicKey,
            ReallyMeCrypto.deriveKeyPair(
                ReallyMeSignatureAlgorithm.ECDSA_P256_SHA256,
                p256EcdsaSecretKey,
            ).publicKey,
        )
        assertContentEquals(p256EcdsaSignatureDer, ReallyMeP256Ecdsa.sign(p256EcdsaMessage, p256EcdsaSecretKey))
        ReallyMeP256Ecdsa.verify(p256EcdsaSignatureDer, p256EcdsaMessage, p256EcdsaPublicKey)
    }

    @Test
    fun genericFacadeP256EcdsaKnownAnswer() {
        val signature = ReallyMeCrypto.sign(
            ReallyMeSignatureAlgorithm.ECDSA_P256_SHA256,
            p256EcdsaMessage,
            p256EcdsaSecretKey,
        )

        assertContentEquals(p256EcdsaSignatureDer, signature)
        ReallyMeCrypto.verify(
            ReallyMeSignatureAlgorithm.ECDSA_P256_SHA256,
            signature,
            p256EcdsaMessage,
            p256EcdsaPublicKey,
        )
    }

    @Test
    fun p256EcdsaRejectsMalformedInputsAndTampering() {
        assertFailsWith<ReallyMeCryptoException.InvalidSignature> {
            ReallyMeP256Ecdsa.verify(p256EcdsaSignatureDer, p256EcdsaMessage + 0x00, p256EcdsaPublicKey)
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeP256Ecdsa.sign(p256EcdsaMessage, byteArrayOf(0x01, 0x02))
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeP256Ecdsa.verify(ByteArray(8), p256EcdsaMessage, p256EcdsaPublicKey)
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeP256Ecdsa.verify(p256EcdsaSignatureDer, p256EcdsaMessage, ByteArray(ReallyMeP256Ecdsa.COMPRESSED_PUBLIC_KEY_LENGTH))
        }
    }

    @Test
    fun p256EcdsaGenerateKeyPairRoundTrip() {
        val keyPair = ReallyMeCrypto.generateKeyPair(ReallyMeSignatureAlgorithm.ECDSA_P256_SHA256)
        assertEquals(ReallyMeP256Ecdsa.SECRET_KEY_LENGTH, keyPair.secretKey.size)
        assertEquals(ReallyMeP256Ecdsa.COMPRESSED_PUBLIC_KEY_LENGTH, keyPair.publicKey.size)

        val signature = ReallyMeCrypto.sign(
            ReallyMeSignatureAlgorithm.ECDSA_P256_SHA256,
            p256EcdsaMessage,
            keyPair.secretKey,
        )
        ReallyMeCrypto.verify(
            ReallyMeSignatureAlgorithm.ECDSA_P256_SHA256,
            signature,
            p256EcdsaMessage,
            keyPair.publicKey,
        )
    }

    @Test
    fun p384EcdsaKnownAnswerAndFacadeParity() {
        assertNistEcdsaProvider(
            algorithm = ReallyMeSignatureAlgorithm.ECDSA_P384_SHA384,
            vectorFile = "p384.json",
            secretKeyLength = ReallyMeP384Ecdsa.SECRET_KEY_LENGTH,
            publicKeyLength = ReallyMeP384Ecdsa.COMPRESSED_PUBLIC_KEY_LENGTH,
            derivePublicKey = ReallyMeP384Ecdsa::derivePublicKey,
            sign = ReallyMeP384Ecdsa::sign,
            verify = ReallyMeP384Ecdsa::verify,
        )
    }

    @Test
    fun p521EcdsaKnownAnswerAndFacadeParity() {
        assertNistEcdsaProvider(
            algorithm = ReallyMeSignatureAlgorithm.ECDSA_P521_SHA512,
            vectorFile = "p521.json",
            secretKeyLength = ReallyMeP521Ecdsa.SECRET_KEY_LENGTH,
            publicKeyLength = ReallyMeP521Ecdsa.COMPRESSED_PUBLIC_KEY_LENGTH,
            derivePublicKey = ReallyMeP521Ecdsa::derivePublicKey,
            sign = ReallyMeP521Ecdsa::sign,
            verify = ReallyMeP521Ecdsa::verify,
        )
    }

    @Test
    fun rsaVerifyKnownAnswers() {
        val publicKeyDer = base64UrlBytes(
            "MIIBCgKCAQEAtLGfC3GxzVAbnFDLYwUlIB52PJUl3yVGcY2X-3vFcQsbOhdYKVW7Ug1G0-adGVsz7Sl4" +
                "CAVZCgDy9LVawN6Wl5TUj8_obkDrtKv9srFmUm0OfYP4REpZq0OBKAs6jf5E5aHqe09edvsO3LOJt" +
                "VqhHgtFM_xvobGr4TtaPGSoFjssvzJ9YVyK08xDOhCaT4K6ukKlaKBTiOjgVxUtmDRnzct--bNxkh" +
                "J88ObqNyJTbp78FWKMsKNfJCTVnKnQIdDMCCQgS6AIXm_d2bPK6FrvDphqfem9ysGQaqPeZjCCoEU9" +
                "lF9ha_v29bQn6CPxzT7cCYW8V-J_mqhOIwqocTI7jQIDAQAB",
        )
        val message = base64UrlBytes("UmVhbGx5TWUgc2lnbmF0dXJlIGNvbmZvcm1hbmNlIHZlY3Rvcg")
        val pkcs1v15Sha256Signature = base64UrlBytes(
            "Re77CuddLv7YajqprynKArLWsc_5tMp5UOAgi1M4cHgj9lKJ14VuI78Lx4if-ngxz4hDxwbRMOh0" +
                "V50DkRYcd_oyfdzecsqo-SisuGGGer5gWJ8h2_8wyrKuSXroNt2CyPUGv5Jn6K5I9krL6Cx0U7_" +
                "MyE6HZJNSVH1w6VpxNsf8iNvp-p_eFkt8dEVuBFxsNlGQV3ltFNVg99kBDOiammOuXIrkCf_V67" +
                "xy3Hc2RkptbmNHTnlC8hw8WBoMH5ds5UcYMuHVgRr8CmXr4YNX9Vel46L7UV69FN5xcJNTLEW0_" +
                "Ylo9N_Csh8urYUbupfvZ49uWMOzyReMg4tzu90lSw",
        )
        val pssSha256Signature = base64UrlBytes(
            "bYeyCHaW_4vy7QDQlAtm7fY5CV9XH4Kt0eINKPRd9E1YFrvI2KLaVgG7-T0uGPu8P_t3BV0n_" +
                "FJJBRxMlSySqFqT_VllgzXuBJ3A7fC_pFyMPK6A3XZ0Y_3rWShvjeZnBf_doMSjoGuWFSaB0K4" +
                "IOAiyjyoJ3RGea6ikt-5nGPvaiFb6K3YXZTJXavH8AKu3J19V2kTrUGHZ6Lf5RuqWHFyzFsEz" +
                "NPcp13ezECkVMZHQEwLxt9Li_mWqXDhPF4bpPCUpGljfmsgqo0RBYogEau7YxqaS15-HhLhWT" +
                "aJYGEcvWBL9burCgU4nlqfEt9gU0m2EDhhUGR38CS86RSiwEw",
        )
        // Cross-lane RSA KATs: the exact signatures the RustCrypto generator
        // committed to vectors/rsa.json. BouncyCastle/JCA must accept each.
        val pkcs1v15Sha384Signature = base64UrlBytes(
            "UPPRJw8CyERJsI7PW5_9WbhZmmIe2wie3bt1FuZz_8ShFfgaFXwQfwn_YS4QtkPEAn6q438r05M25U-IYQXa" +
                "DiisXSocMxRE06nqMvvrCgO6p6O-2_xWW8V8xhDox1aPqWdp54Ba6A0s3dywUe5zQpOAL-xQ8KLIZpIE" +
                "118xKwhouFMGZBvCNJDDMMVTxIyp-EpThhiE5EFxL5vp9hVx4euaEfgQhw5MXnJmxKW4Pt9sSdMlvoP8" +
                "aFrW5st9rLfvknJz4EwgIVevM5XYaWsrjZfJOKY5CmCVmvW-evOMjumMRRU9t2OOOf5NHszKzK3qtUvz" +
                "CbXUz8F1FNFJeZ_GaA",
        )
        val pkcs1v15Sha512Signature = base64UrlBytes(
            "MQ0UP3caVxnjq72kvCzRSvEbk2msNM0l76lv84OPjuA7Xu0EAb6H4WjoDnwqCy1aJe0wZQVVXEQyT8ch3AmD" +
                "sY7_zCYlayZ8147Jno7n7qda8D0d8Q9SWZRK3Ir4HW6Ex5psmZaAhqSMAnku6On8oWIuofGKOOgMVn7A" +
                "YDeehlh3f5NscqAtrEebrZ47B-d6XDHuyAe4zxsJPbBj0ef1vvRAA6wXnPIJ7Kvmajb8P4N8dCcjwjA7" +
                "P9VbyZz_fY2HNpyAGAEFkjOO8uo05u30cHn6TLSYTCsKH2PCqkgH_-UEgjgp8IdBl5PzIHYac8wffRQ3" +
                "9G8LMZR07cll8HaPGA",
        )
        val pssSha1Signature = base64UrlBytes(
            "rM_td9L0bEnDyo8_7wxbYy2R7b-td3ZB69TFvaoFfm3VLBBELVOpYjHzcW3SKoiKkW56qQ8ZhOfCbWabUVvE" +
                "mi85l0cf1fjX9Uk1n7tLDRjZwQyBGR3LS5JmOI5TpXZCb9d_wzS4F_wo2x_HTix_fkX7aysINa8RBABl" +
                "kE9SlofwRWpgn7GTGnnc59WPVKuUUfnNEchm683eyUzi78Mfv5sKLgP7odUYMtMsaQsAN25MYrkmfoRK" +
                "S-RzQKSV0m7NdGawT2JfPVYV-Q5ZwUtgj_n5FmoCqU7N-Rs2OJMojEvbFfMaAdFFDnyK8pblY0Nt-4ep" +
                "H8U6dPriTdtFa2g_Tw",
        )
        val pssSha384Signature = base64UrlBytes(
            "MEnKhv7atsfMZOREi-0Ta-jDTPNHW6U1lz0_WgIkvWLJ2fohqgy2nwyBBfU-JtSZrVEaPEbIElu15F0NKHyo" +
                "NUGU1WY_bwZVVSPCKWIHjbrQwK8whZw3H8NCP9G5zRJhzpFtIYBdG6H4oOzIYHSNvk7_-suOgiaTsSg0" +
                "eg-ZxXypXYCGBp-mE1iJ4hRYnOVv-_Sbje00qbFCGL6WwP7Jxnucp11p4Plli25GBkggZu1gTGEhGRnU" +
                "2j9NTZKxbT2Q-MTZ3mTuQohsVvUNMfF6r2ns9FEQIrsApAu2bryJcPVZkulkyBmVTW2XopOFXI-MlkQp" +
                "mekoLB7ZHP6enlefBQ",
        )
        val pssSha512Signature = base64UrlBytes(
            "rzU-aGeM1kEp6mvkQgaJ9myGNXyGtP6r18iBfZNEXf0viVvOjL_ebVE2nD3MUEtiPbxD7TAH-4JXfD-STG3B" +
                "aGDjH0uVu5KCgSPjKRcskEZuOSzhmJ485fP5oc8yRnrl9lIy-RD0ItX5NWU6g40otuC7LmsrH2vWB2Ko" +
                "OKeWQFgCQD_KP8mssSWVuhwml-S3egN8-S6cprMbwHvJsn1KDpWn_pp0gM9FWyNoHqivekcgGJKz0iVc" +
                "LzHUbxI5lhj51djBuw32bNrU7jB8dQwf847J9ZDr4cAz_vbP5oCTdXOibPG2J0joYR4mpbRgeernoZGx" +
                "If44p7HJX75J-WxE0Q",
        )

        ReallyMeCrypto.verify(
            ReallyMeSignatureAlgorithm.RSA_PKCS1V15_SHA256,
            pkcs1v15Sha256Signature,
            message,
            publicKeyDer,
            ReallyMeRsaPublicKeyDerEncoding.PKCS1,
        )
        ReallyMeCrypto.verify(
            ReallyMeSignatureAlgorithm.RSA_PSS_SHA256_MGF1_SHA256,
            pssSha256Signature,
            message,
            publicKeyDer,
            ReallyMeRsaPublicKeyDerEncoding.PKCS1,
        )
        val additionalRsaCases = listOf(
            ReallyMeSignatureAlgorithm.RSA_PKCS1V15_SHA384 to pkcs1v15Sha384Signature,
            ReallyMeSignatureAlgorithm.RSA_PKCS1V15_SHA512 to pkcs1v15Sha512Signature,
            ReallyMeSignatureAlgorithm.RSA_PSS_SHA1_MGF1_SHA1 to pssSha1Signature,
            ReallyMeSignatureAlgorithm.RSA_PSS_SHA384_MGF1_SHA384 to pssSha384Signature,
            ReallyMeSignatureAlgorithm.RSA_PSS_SHA512_MGF1_SHA512 to pssSha512Signature,
        )
        for ((algorithm, signature) in additionalRsaCases) {
            ReallyMeCrypto.verify(
                algorithm,
                signature,
                message,
                publicKeyDer,
                ReallyMeRsaPublicKeyDerEncoding.PKCS1,
            )
            assertFailsWith<ReallyMeCryptoException.InvalidSignature>(message = algorithm.algorithmName) {
                ReallyMeCrypto.verify(
                    algorithm,
                    signature,
                    message + 0x00,
                    publicKeyDer,
                    ReallyMeRsaPublicKeyDerEncoding.PKCS1,
                )
            }
        }
        assertFailsWith<ReallyMeCryptoException.InvalidSignature> {
            ReallyMeCrypto.verify(
                ReallyMeSignatureAlgorithm.RSA_PKCS1V15_SHA256,
                pkcs1v15Sha256Signature,
                message + 0x00,
                publicKeyDer,
                ReallyMeRsaPublicKeyDerEncoding.PKCS1,
            )
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.verify(
                ReallyMeSignatureAlgorithm.RSA_PKCS1V15_SHA256,
                pkcs1v15Sha256Signature,
                message,
                ByteArray(0),
                ReallyMeRsaPublicKeyDerEncoding.PKCS1,
            )
        }
    }

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
        validateXWingVector("x_wing_1024", ReallyMeKemAlgorithm.X_WING_1024)
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

    // Key agreement case from vectors/x25519.json — the same KAT every lane proves.
    private val x25519SecretKey =
        bytes("13b40e434329c8395922a66d6fb8c50d3b35263f8e5c06cac624a86527d3b304")
    private val x25519PublicKey =
        bytes("cbbec1ce67440087d03bfd8536ea3f7fa922cf529abc66578b62f3bf5ab26141")
    private val x25519PeerSecretKey =
        bytes("73806939b0f9e8d2ae4c3d70a4b725933687d2858ca5d08960a9e25450ef50ae")
    private val x25519PeerPublicKey =
        bytes("4444a8bf80ad7e56fc28dbc826d9f44fc49bd945f3ba2626138f791d7a55180b")
    private val x25519SharedSecret =
        bytes("e00c4d62a8beeeedc0d7d0aca78e4c94395a063539a8204ce8fc11120e8dbc18")

    @Test
    fun x25519DerivePublicKeyKnownAnswer() {
        assertContentEquals(
            x25519PublicKey,
            ReallyMeX25519.derivePublicKey(x25519SecretKey),
        )
        assertContentEquals(
            x25519PeerPublicKey,
            ReallyMeX25519.derivePublicKey(x25519PeerSecretKey),
        )
        val keyPair = ReallyMeCrypto.deriveKeyAgreementKeyPair(
            ReallyMeKeyAgreementAlgorithm.X25519,
            x25519SecretKey,
        )
        assertContentEquals(x25519PublicKey, keyPair.publicKey)
        assertContentEquals(x25519SecretKey, keyPair.secretKey)
    }

    @Test
    fun x25519DeriveSharedSecretKnownAnswer() {
        assertContentEquals(
            x25519SharedSecret,
            ReallyMeX25519.deriveSharedSecret(x25519PeerPublicKey, x25519SecretKey),
        )
        assertContentEquals(
            x25519SharedSecret,
            ReallyMeCrypto.deriveSharedSecret(
                ReallyMeKeyAgreementAlgorithm.X25519,
                x25519PublicKey,
                x25519PeerSecretKey,
            ),
        )
    }

    @Test
    fun x25519RejectsMalformedInputs() {
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeX25519.derivePublicKey(byteArrayOf(0x01, 0x02))
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.deriveKeyAgreementKeyPair(ReallyMeKeyAgreementAlgorithm.X25519, byteArrayOf(0x01, 0x02))
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeX25519.deriveSharedSecret(ByteArray(ReallyMeX25519.PUBLIC_KEY_LENGTH - 1), x25519SecretKey)
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeX25519.deriveSharedSecret(ByteArray(ReallyMeX25519.PUBLIC_KEY_LENGTH), x25519SecretKey)
        }
    }

    @Test
    fun x25519GenerateKeyPairRoundTrip() {
        val alice = ReallyMeX25519.generateKeyPair()
        val bob = ReallyMeX25519.generateKeyPair()
        val aliceSecret = ReallyMeCrypto.deriveSharedSecret(
            ReallyMeKeyAgreementAlgorithm.X25519,
            bob.first,
            alice.second,
        )
        val bobSecret = ReallyMeCrypto.deriveSharedSecret(
            ReallyMeKeyAgreementAlgorithm.X25519,
            alice.first,
            bob.second,
        )

        assertEquals(ReallyMeX25519.PUBLIC_KEY_LENGTH, alice.first.size)
        assertEquals(ReallyMeX25519.SECRET_KEY_LENGTH, alice.second.size)
        assertEquals(ReallyMeX25519.SHARED_SECRET_LENGTH, aliceSecret.size)
        assertContentEquals(aliceSecret, bobSecret)
    }

    private val p256EcdhSecretKey =
        bytes("214f8b6ca29d3310954766127283afee0d19415b7c22d439518ab0652f91c344")
    private val p256EcdhPublicKey =
        bytes("0207fccb4345096f9621726fc4e437be0cf81c431081f328e554967239ac5522ee")
    private val p256EcdhPeerSecretKey =
        bytes("6a1045f2339e8012ab74c628de91075b49ef3218842dbc6013a577c90e4b26d1")
    private val p256EcdhPeerPublicKey =
        bytes("0258bec98966c3f75836e02cd69aeef19954aab428ba10280652785bfccf9e1121")
    private val p256EcdhSharedSecret =
        bytes("88e56575ee9a990409e3e406cd82c84ca5d529d2dac781ece3a15eb0b876fe71")

    @Test
    fun p256EcdhKnownAnswer() {
        assertContentEquals(p256EcdhPublicKey, ReallyMeP256Ecdh.derivePublicKey(p256EcdhSecretKey))
        val keyPair = ReallyMeCrypto.deriveKeyAgreementKeyPair(
            ReallyMeKeyAgreementAlgorithm.P256_ECDH,
            p256EcdhSecretKey,
        )
        assertContentEquals(p256EcdhPublicKey, keyPair.publicKey)
        assertContentEquals(p256EcdhSecretKey, keyPair.secretKey)
        assertContentEquals(
            p256EcdhSharedSecret,
            ReallyMeP256Ecdh.deriveSharedSecret(p256EcdhPeerPublicKey, p256EcdhSecretKey),
        )
        assertContentEquals(
            p256EcdhSharedSecret,
            ReallyMeCrypto.deriveSharedSecret(
                ReallyMeKeyAgreementAlgorithm.P256_ECDH,
                p256EcdhPublicKey,
                p256EcdhPeerSecretKey,
            ),
        )
    }

    @Test
    fun p256EcdhRejectsMalformedInputs() {
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeP256Ecdh.derivePublicKey(byteArrayOf(0x01, 0x02))
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeP256Ecdh.deriveSharedSecret(ByteArray(ReallyMeP256Ecdh.COMPRESSED_PUBLIC_KEY_LENGTH), p256EcdhSecretKey)
        }
    }

    @Test
    fun p256EcdhGenerateKeyPairRoundTrip() {
        val alice = ReallyMeP256Ecdh.generateKeyPair()
        val bob = ReallyMeP256Ecdh.generateKeyPair()
        val aliceSecret = ReallyMeCrypto.deriveSharedSecret(
            ReallyMeKeyAgreementAlgorithm.P256_ECDH,
            bob.first,
            alice.second,
        )
        val bobSecret = ReallyMeCrypto.deriveSharedSecret(
            ReallyMeKeyAgreementAlgorithm.P256_ECDH,
            alice.first,
            bob.second,
        )

        assertEquals(ReallyMeP256Ecdh.SHARED_SECRET_LENGTH, aliceSecret.size)
        assertContentEquals(aliceSecret, bobSecret)
    }

    @Test
    fun p384EcdhKnownAnswer() {
        val secretKey = vectorField("p384.json", "secret_key")
        val publicKey = vectorField("p384.json", "public_key_compressed")
        val peerSecretKey = vectorField("p384.json", "peer_secret_key")
        val peerPublicKey = vectorField("p384.json", "peer_public_key_compressed")
        val sharedSecret = vectorField("p384.json", "shared_secret")

        assertContentEquals(publicKey, ReallyMeP384Ecdh.derivePublicKey(secretKey))
        val keyPair = ReallyMeCrypto.deriveKeyAgreementKeyPair(
            ReallyMeKeyAgreementAlgorithm.P384_ECDH,
            secretKey,
        )
        assertContentEquals(publicKey, keyPair.publicKey)
        assertContentEquals(secretKey, keyPair.secretKey)
        assertContentEquals(
            sharedSecret,
            ReallyMeP384Ecdh.deriveSharedSecret(peerPublicKey, secretKey),
        )
        assertContentEquals(
            sharedSecret,
            ReallyMeCrypto.deriveSharedSecret(
                ReallyMeKeyAgreementAlgorithm.P384_ECDH,
                publicKey,
                peerSecretKey,
            ),
        )
    }

    @Test
    fun p384EcdhRejectsMalformedInputs() {
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeP384Ecdh.derivePublicKey(byteArrayOf(0x01, 0x02))
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeP384Ecdh.deriveSharedSecret(ByteArray(ReallyMeP384Ecdh.COMPRESSED_PUBLIC_KEY_LENGTH), ByteArray(ReallyMeP384Ecdh.SECRET_KEY_LENGTH))
        }
    }

    @Test
    fun p384EcdhGenerateKeyPairRoundTrip() {
        val alice = ReallyMeP384Ecdh.generateKeyPair()
        val bob = ReallyMeP384Ecdh.generateKeyPair()
        val aliceSecret = ReallyMeCrypto.deriveSharedSecret(
            ReallyMeKeyAgreementAlgorithm.P384_ECDH,
            bob.first,
            alice.second,
        )
        val bobSecret = ReallyMeCrypto.deriveSharedSecret(
            ReallyMeKeyAgreementAlgorithm.P384_ECDH,
            alice.first,
            bob.second,
        )

        assertEquals(ReallyMeP384Ecdh.SHARED_SECRET_LENGTH, aliceSecret.size)
        assertContentEquals(aliceSecret, bobSecret)
    }

    @Test
    fun p521EcdhKnownAnswer() {
        val secretKey = vectorField("p521.json", "secret_key")
        val publicKey = vectorField("p521.json", "public_key_compressed")
        val peerSecretKey = vectorField("p521.json", "peer_secret_key")
        val peerPublicKey = vectorField("p521.json", "peer_public_key_compressed")
        val sharedSecret = vectorField("p521.json", "shared_secret")

        assertContentEquals(publicKey, ReallyMeP521Ecdh.derivePublicKey(secretKey))
        val keyPair = ReallyMeCrypto.deriveKeyAgreementKeyPair(
            ReallyMeKeyAgreementAlgorithm.P521_ECDH,
            secretKey,
        )
        assertContentEquals(publicKey, keyPair.publicKey)
        assertContentEquals(secretKey, keyPair.secretKey)
        assertContentEquals(
            sharedSecret,
            ReallyMeP521Ecdh.deriveSharedSecret(peerPublicKey, secretKey),
        )
        assertContentEquals(
            sharedSecret,
            ReallyMeCrypto.deriveSharedSecret(
                ReallyMeKeyAgreementAlgorithm.P521_ECDH,
                publicKey,
                peerSecretKey,
            ),
        )
    }

    @Test
    fun p521EcdhRejectsMalformedInputs() {
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeP521Ecdh.derivePublicKey(byteArrayOf(0x01, 0x02))
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeP521Ecdh.deriveSharedSecret(ByteArray(ReallyMeP521Ecdh.COMPRESSED_PUBLIC_KEY_LENGTH), ByteArray(ReallyMeP521Ecdh.SECRET_KEY_LENGTH))
        }
    }

    @Test
    fun p521EcdhGenerateKeyPairRoundTrip() {
        val alice = ReallyMeP521Ecdh.generateKeyPair()
        val bob = ReallyMeP521Ecdh.generateKeyPair()
        val aliceSecret = ReallyMeCrypto.deriveSharedSecret(
            ReallyMeKeyAgreementAlgorithm.P521_ECDH,
            bob.first,
            alice.second,
        )
        val bobSecret = ReallyMeCrypto.deriveSharedSecret(
            ReallyMeKeyAgreementAlgorithm.P521_ECDH,
            alice.first,
            bob.second,
        )

        assertEquals(ReallyMeP521Ecdh.SHARED_SECRET_LENGTH, aliceSecret.size)
        assertContentEquals(aliceSecret, bobSecret)
    }

    // Keypair from vectors/secp256k1.json — the same KAT every lane proves.
    private val vectorSecretKey =
        bytes("4e390c72a5d15f209963812e37af04bce156489a2f730d8451c63b09f528617d")
    private val vectorPublicKey =
        bytes("02e1517f97e1877f63fee722a687ddaefc3ec7cce1d27360aeec02091f04e18dd4")

    @Test
    fun secp256k1DerivePublicKeyKnownAnswer() {
        assertContentEquals(
            vectorPublicKey,
            ReallyMeSecp256k1.derivePublicKey(vectorSecretKey),
        )
        assertContentEquals(
            vectorPublicKey,
            ReallyMeCrypto.deriveKeyPair(
                ReallyMeSignatureAlgorithm.ECDSA_SECP256K1_SHA256,
                vectorSecretKey,
            ).publicKey,
        )
    }

    @Test
    fun secp256k1SignIsDeterministicAndVerifies() {
        val message = "reallyme secp256k1 contract".toByteArray()

        val first = ReallyMeSecp256k1.sign(message, vectorSecretKey)
        val second = ReallyMeSecp256k1.sign(message, vectorSecretKey)
        assertContentEquals(first, second, "RFC 6979 signatures must be deterministic")
        assertEquals(ReallyMeSecp256k1.SIGNATURE_LENGTH, first.size)

        // Cross-lane KAT: the same bytes @noble/curves 2.2.0 (TS lane oracle)
        // and libsecp256k1 (Swift lane) produce for this message and key.
        assertContentEquals(
            bytes(
                "b94d52260da1d40bbc404432860437ac166781f2da4340086508a26db5e7d14d" +
                    "371dfc9f3c1908fa0980a28182a75bc8d3b80cf53a58d0c8e179f966bb79b3ee",
            ),
            first,
        )

        ReallyMeSecp256k1.verify(first, message, vectorPublicKey)
    }

    @Test
    fun genericFacadeSecp256k1KnownAnswer() {
        val message = "reallyme secp256k1 contract".toByteArray()
        val signature = ReallyMeCrypto.sign(
            ReallyMeSignatureAlgorithm.ECDSA_SECP256K1_SHA256,
            message,
            vectorSecretKey,
        )

        assertContentEquals(
            bytes(
                "b94d52260da1d40bbc404432860437ac166781f2da4340086508a26db5e7d14d" +
                    "371dfc9f3c1908fa0980a28182a75bc8d3b80cf53a58d0c8e179f966bb79b3ee",
            ),
            signature,
        )
        ReallyMeCrypto.verify(
            ReallyMeSignatureAlgorithm.ECDSA_SECP256K1_SHA256,
            signature,
            message,
            vectorPublicKey,
        )
    }

    @Test
    fun secp256k1SignatureIsLowS() {
        val halfOrder = BigInteger(
            "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
            16,
        )
        val signature = ReallyMeSecp256k1.sign("low-s check".toByteArray(), vectorSecretKey)
        val s = BigInteger(1, signature.copyOfRange(32, 64))
        assertTrue(s <= halfOrder, "signature s component must be low-S normalized")
    }

    @Test
    fun secp256k1RejectsTamperedSignatureAndMessage() {
        val message = "tamper check".toByteArray()
        val signature = ReallyMeSecp256k1.sign(message, vectorSecretKey)

        assertFailsWith<ReallyMeCryptoException.InvalidSignature> {
            ReallyMeSecp256k1.verify(signature, message + 0x00, vectorPublicKey)
        }

        val flipped = signature.copyOf()
        flipped[10] = (flipped[10].toInt() xor 0xff).toByte()
        assertFailsWith<ReallyMeCryptoException.InvalidSignature> {
            ReallyMeSecp256k1.verify(flipped, message, vectorPublicKey)
        }
    }

    @Test
    fun secp256k1RejectsMalformedInputs() {
        val message = "shape check".toByteArray()

        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeSecp256k1.sign(message, byteArrayOf(0x01, 0x02))
        }

        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeSecp256k1.derivePublicKey(ByteArray(ReallyMeSecp256k1.SECRET_KEY_LENGTH))
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.deriveKeyPair(
                ReallyMeSignatureAlgorithm.ECDSA_SECP256K1_SHA256,
                ByteArray(ReallyMeSecp256k1.SECRET_KEY_LENGTH),
            )
        }

        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeSecp256k1.verify(ByteArray(63), message, vectorPublicKey)
        }

        val invalidKey = vectorPublicKey.copyOf()
        invalidKey[0] = 0x07 // not a valid SEC1 compressed prefix
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeSecp256k1.verify(
                ByteArray(ReallyMeSecp256k1.SIGNATURE_LENGTH),
                message,
                invalidKey,
            )
        }
    }

    @Test
    fun secp256k1RejectsHighSMalleatedTwin() {
        val curveOrder = BigInteger(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            16,
        )
        val message = "malleability check".toByteArray()
        val signature = ReallyMeSecp256k1.sign(message, vectorSecretKey)
        ReallyMeSecp256k1.verify(signature, message, vectorPublicKey)

        // (r, n - s) verifies under raw ECDSA but must be rejected (BIP 0062).
        val s = BigInteger(1, signature.copyOfRange(32, 64))
        val highS = curveOrder.subtract(s).toByteArray().let { raw ->
            val out = ByteArray(32)
            val start = if (raw.size > 32) raw.size - 32 else 0
            val length = raw.size - start
            System.arraycopy(raw, start, out, 32 - length, length)
            out
        }
        val malleated = signature.copyOfRange(0, 32) + highS
        assertFailsWith<ReallyMeCryptoException.InvalidSignature> {
            ReallyMeSecp256k1.verify(malleated, message, vectorPublicKey)
        }
    }

    @Test
    fun secp256k1GenerateKeyPairRoundTrip() {
        val (publicKey, secretKey) = ReallyMeSecp256k1.generateKeyPair()
        assertEquals(ReallyMeSecp256k1.SECRET_KEY_LENGTH, secretKey.size)
        assertEquals(ReallyMeSecp256k1.COMPRESSED_PUBLIC_KEY_LENGTH, publicKey.size)

        val message = "fresh keypair".toByteArray()
        val signature = ReallyMeSecp256k1.sign(message, secretKey)
        ReallyMeSecp256k1.verify(signature, message, publicKey)
    }

    @Test
    fun bip340SchnorrKnownAnswerAndFacadeSignVerify() {
        val secretKey = vectorField("bip340_schnorr.json", "secret_key")
        val publicKey = vectorField("bip340_schnorr.json", "public_key_xonly")
        val message = vectorField("bip340_schnorr.json", "message")
        val auxRand = vectorField("bip340_schnorr.json", "aux_rand")
        val signature = vectorField("bip340_schnorr.json", "signature")

        assertContentEquals(publicKey, ReallyMeBip340Schnorr.derivePublicKey(secretKey))
        assertContentEquals(
            publicKey,
            ReallyMeCrypto.deriveKeyPair(
                ReallyMeSignatureAlgorithm.BIP340_SCHNORR_SECP256K1_SHA256,
                secretKey,
            ).publicKey,
        )
        assertContentEquals(signature, ReallyMeBip340Schnorr.sign(message, secretKey, auxRand))
        assertContentEquals(signature, ReallyMeCrypto.signBip340Schnorr(message, secretKey, auxRand))
        ReallyMeBip340Schnorr.verify(signature, message, publicKey)
        ReallyMeCrypto.verify(
            ReallyMeSignatureAlgorithm.BIP340_SCHNORR_SECP256K1_SHA256,
            signature,
            message,
            publicKey,
        )

        val generated = ReallyMeCrypto.generateKeyPair(ReallyMeSignatureAlgorithm.BIP340_SCHNORR_SECP256K1_SHA256)
        assertEquals(ReallyMeBip340Schnorr.PUBLIC_KEY_LENGTH, generated.publicKey.size)
        assertEquals(ReallyMeBip340Schnorr.SECRET_KEY_LENGTH, generated.secretKey.size)
        assertFailsWith<ReallyMeCryptoException.UnsupportedAlgorithm> {
            ReallyMeCrypto.sign(
                ReallyMeSignatureAlgorithm.BIP340_SCHNORR_SECP256K1_SHA256,
                message,
                secretKey,
            )
        }
    }

    @Test
    fun bip340SchnorrRejectsMalformedInputsAndTampering() {
        val secretKey = vectorField("bip340_schnorr.json", "secret_key")
        val publicKey = vectorField("bip340_schnorr.json", "public_key_xonly")
        val message = vectorField("bip340_schnorr.json", "message")
        val auxRand = vectorField("bip340_schnorr.json", "aux_rand")
        val signature = vectorField("bip340_schnorr.json", "signature")
        val tamperedSignature = signature.copyOf()
        tamperedSignature[0] = (tamperedSignature[0].toInt() xor 0x01).toByte()

        assertFailsWith<ReallyMeCryptoException.InvalidSignature> {
            ReallyMeBip340Schnorr.verify(tamperedSignature, message, publicKey)
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeBip340Schnorr.sign(ByteArray(31), secretKey, auxRand)
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeBip340Schnorr.sign(message, secretKey, ByteArray(31))
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeBip340Schnorr.verify(signature.copyOf(signature.size - 1), message, publicKey)
        }
    }

    private fun assertRustAeadRoundTrip(
        algorithm: ReallyMeAeadAlgorithm,
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
        ciphertext: ByteArray,
    ) {
        assertContentEquals(ciphertext, ReallyMeCrypto.seal(algorithm, key, nonce, aad, plaintext))
        assertContentEquals(plaintext, ReallyMeCrypto.open(algorithm, key, nonce, aad, ciphertext))

        val tampered = ciphertext.copyOf()
        tampered[0] = (tampered[0].toInt() xor 0x01).toByte()
        assertFailsWith<ReallyMeCryptoException.AuthenticationFailed>(message = algorithm.algorithmName) {
            ReallyMeCrypto.open(algorithm, key, nonce, aad, tampered)
        }
    }

    private fun assertNistEcdsaProvider(
        algorithm: ReallyMeSignatureAlgorithm,
        vectorFile: String,
        secretKeyLength: Int,
        publicKeyLength: Int,
        derivePublicKey: (ByteArray) -> ByteArray,
        sign: (ByteArray, ByteArray) -> ByteArray,
        verify: (ByteArray, ByteArray, ByteArray) -> Unit,
    ) {
        val secretKey = vectorField(vectorFile, "secret_key")
        val publicKey = vectorField(vectorFile, "public_key_compressed")
        val message = vectorField(vectorFile, "message")
        val signature = vectorField(vectorFile, "signature_der")

        assertContentEquals(publicKey, derivePublicKey(secretKey))
        assertContentEquals(publicKey, ReallyMeCrypto.deriveKeyPair(algorithm, secretKey).publicKey)
        assertContentEquals(signature, sign(message, secretKey))
        verify(signature, message, publicKey)

        val facadeSignature = ReallyMeCrypto.sign(algorithm, message, secretKey)
        assertContentEquals(signature, facadeSignature)
        ReallyMeCrypto.verify(algorithm, signature, message, publicKey)

        val tampered = signature.copyOf()
        tampered[tampered.lastIndex] = (tampered[tampered.lastIndex].toInt() xor 0x01).toByte()
        assertFailsWith<ReallyMeCryptoException.InvalidSignature> {
            verify(tampered, message, publicKey)
        }

        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            sign(message, byteArrayOf(0x01, 0x02))
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            verify(ByteArray(7), message, publicKey)
        }
        val invalidKey = publicKey.copyOf()
        invalidKey[0] = 0x07
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            verify(signature, message, invalidKey)
        }

        val generated = ReallyMeCrypto.generateKeyPair(algorithm)
        assertEquals(secretKeyLength, generated.secretKey.size)
        assertEquals(publicKeyLength, generated.publicKey.size)
        val generatedSignature = ReallyMeCrypto.sign(algorithm, message, generated.secretKey)
        ReallyMeCrypto.verify(algorithm, generatedSignature, message, generated.publicKey)
    }

    private fun bytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { index ->
            hex.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }

    private fun base64UrlBytes(encoded: String): ByteArray = Base64.getUrlDecoder().decode(encoded)

    private fun vectorField(vectorName: String, fieldName: String): ByteArray {
        return base64UrlBytes(vectorString(vectorName, fieldName))
    }

    private fun vectorString(vectorName: String, fieldName: String): String {
        val vectorPath = Path.of("..", "..", "vectors", vectorName)
        val text = Files.readString(vectorPath)
        val match = Regex("\"$fieldName\"\\s*:\\s*\"([^\"]+)\"").find(text)
            ?: throw IllegalStateException("missing vector field")
        return match.groupValues[1]
    }

    private fun vectorNumber(vectorName: String, fieldName: String): Int {
        val vectorPath = Path.of("..", "..", "vectors", vectorName)
        val text = Files.readString(vectorPath)
        val match = Regex("\"$fieldName\"\\s*:\\s*([0-9]+)").find(text)
            ?: throw IllegalStateException("missing vector field")
        return match.groupValues[1].toInt()
    }

    private data class CodecPrefixVector(
        val name: String,
        val alg: String,
        val prefix: ByteArray,
    )

    private data class JwkVector(
        val alg: String,
        val publicKey: String,
        val publicKeyLength: Int,
        val jwkJcs: String,
    )

    private fun codecPrefixVectors(): List<CodecPrefixVector> {
        val vectorPath = Path.of("..", "..", "vectors", "codecs.json")
        val text = Files.readString(vectorPath)
        val entryPattern = Regex(
            "\\{\\s*\"name\"\\s*:\\s*\"([^\"]+)\"\\s*,\\s*" +
                "\"alg\"\\s*:\\s*\"([^\"]+)\"\\s*,\\s*" +
                "\"prefix\"\\s*:\\s*\"([^\"]+)\"",
        )
        return entryPattern.findAll(text).map { match ->
            CodecPrefixVector(
                name = match.groupValues[1],
                alg = match.groupValues[2],
                prefix = base64UrlBytes(match.groupValues[3]),
            )
        }.toList()
    }

    private fun jwkVectors(): List<JwkVector> {
        val vectorPath = Path.of("..", "..", "vectors", "jwk.json")
        val text = Files.readString(vectorPath)
        return topLevelVectorObjects(text).map { entry ->
            JwkVector(
                alg = jsonStringField(entry, "alg"),
                publicKey = jsonStringField(entry, "public_key"),
                publicKeyLength = jsonNumberField(entry, "public_key_length"),
                jwkJcs = jsonStringField(entry, "jwk_jcs"),
            )
        }.toList()
    }

    private fun topLevelVectorObjects(text: String): List<String> {
        val vectorsIndex = text.indexOf("\"vectors\"")
        if (vectorsIndex < 0) {
            throw IllegalStateException("missing jwk vectors array")
        }
        val arrayStart = text.indexOf('[', vectorsIndex)
        if (arrayStart < 0) {
            throw IllegalStateException("missing jwk vectors array")
        }

        val objects = mutableListOf<String>()
        var depth = 0
        var start = -1
        var inString = false
        var escaping = false
        var index = arrayStart + 1
        while (index < text.length) {
            val char = text[index]
            if (inString) {
                if (escaping) {
                    escaping = false
                } else if (char == '\\') {
                    escaping = true
                } else if (char == '"') {
                    inString = false
                }
            } else {
                when (char) {
                    '"' -> inString = true
                    '{' -> {
                        if (depth == 0) {
                            start = index
                        }
                        depth += 1
                    }
                    '}' -> {
                        depth -= 1
                        if (depth == 0 && start >= 0) {
                            objects.add(text.substring(start, index + 1))
                            start = -1
                        }
                    }
                    ']' -> if (depth == 0) {
                        return objects
                    }
                }
            }
            index += 1
        }
        throw IllegalStateException("unterminated jwk vectors array")
    }

    private fun jsonStringField(text: String, fieldName: String): String {
        val fieldIndex = text.indexOf("\"$fieldName\"")
        if (fieldIndex < 0) {
            throw IllegalStateException("missing string field")
        }
        val colon = text.indexOf(':', fieldIndex)
        val firstQuote = text.indexOf('"', colon + 1)
        if (colon < 0 || firstQuote < 0) {
            throw IllegalStateException("missing string field")
        }
        val out = StringBuilder()
        var index = firstQuote + 1
        var escaping = false
        while (index < text.length) {
            val char = text[index]
            if (escaping) {
                out.append(
                    when (char) {
                        '"', '\\', '/' -> char
                        'b' -> '\b'
                        'f' -> '\u000C'
                        'n' -> '\n'
                        'r' -> '\r'
                        't' -> '\t'
                        else -> throw IllegalStateException("unsupported escape")
                    },
                )
                escaping = false
            } else if (char == '\\') {
                escaping = true
            } else if (char == '"') {
                return out.toString()
            } else {
                out.append(char)
            }
            index += 1
        }
        throw IllegalStateException("unterminated string field")
    }

    private fun jsonNumberField(text: String, fieldName: String): Int {
        val fieldIndex = text.indexOf("\"$fieldName\"")
        if (fieldIndex < 0) {
            throw IllegalStateException("missing number field")
        }
        val colon = text.indexOf(':', fieldIndex)
        if (colon < 0) {
            throw IllegalStateException("missing number field")
        }
        var index = colon + 1
        while (index < text.length && text[index].isWhitespace()) {
            index += 1
        }
        val start = index
        while (index < text.length && text[index].isDigit()) {
            index += 1
        }
        return text.substring(start, index).toInt()
    }

    private fun vectorCaseField(vectorName: String, caseName: String, fieldName: String): ByteArray {
        val vectorPath = Path.of("..", "..", "vectors", vectorName)
        val text = Files.readString(vectorPath)
        val caseIndex = text.indexOf("\"$caseName\"")
        if (caseIndex < 0) {
            throw IllegalStateException("missing vector case")
        }
        val match = Regex("\"$fieldName\"\\s*:\\s*\"([^\"]+)\"").find(text, caseIndex)
            ?: throw IllegalStateException("missing vector field")
        return base64UrlBytes(match.groupValues[1])
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
