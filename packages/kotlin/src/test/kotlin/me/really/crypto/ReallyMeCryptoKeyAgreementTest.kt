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

class ReallyMeCryptoKeyAgreementTest : ReallyMeCryptoTestSupport() {
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

        // Cross-lane KAT: the same bytes @noble/curves 2.4.0 (TS lane oracle)
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

}
