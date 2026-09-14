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

class ReallyMeCryptoSignatureTest : ReallyMeCryptoTestSupport() {
    @Test
    fun genericFacadeRemainingFamiliesReturnTypedUnsupportedAlgorithm() {
        val empty = ByteArray(0)

        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.seal(ReallyMeAeadAlgorithm.AES_256_GCM_SIV, empty, empty, empty, empty)
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeCrypto.seal(ReallyMeAeadAlgorithm.CHACHA20_POLY1305, empty, empty, empty, empty)
        }
        assertEquals(4, ReallyMeKemAlgorithm.entries.size)
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
            setOf(
                ReallyMeMacAlgorithm.HMAC_SHA256,
                ReallyMeMacAlgorithm.HMAC_SHA384,
                ReallyMeMacAlgorithm.HMAC_SHA512,
            ),
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
            ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA256,
            ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA512,
        )
        val deriveHkdfSupported = setOf(
            ReallyMeKdfAlgorithm.HKDF_SHA256,
            ReallyMeKdfAlgorithm.HKDF_SHA384,
        )
        val deriveJwaConcatKdfSupported = setOf(ReallyMeKdfAlgorithm.JWA_CONCAT_KDF_SHA256)

        ReallyMeKdfAlgorithm.entries
            .filter { algorithm -> !deriveKeySupported.contains(algorithm) }
            .forEach { algorithm ->
                assertFailsWith<ReallyMeCryptoException.UnsupportedAlgorithm>(message = algorithm.algorithmName) {
                    ReallyMeCrypto.deriveKey(algorithm, empty, empty, 1u, 1)
                }
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
    fun nistEcdsaRejectsNonIntegerDerComponentsAsTypedInvalidInput() {
        val malformedSignature = malformedDerEcdsaSignature()

        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeP256Ecdsa.verify(malformedSignature, p256EcdsaMessage, p256EcdsaPublicKey)
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeP384Ecdsa.verify(
                malformedSignature,
                vectorField("p384.json", "message"),
                vectorField("p384.json", "public_key_compressed"),
            )
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeP521Ecdsa.verify(
                malformedSignature,
                vectorField("p521.json", "message"),
                vectorField("p521.json", "public_key_compressed"),
            )
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

}
