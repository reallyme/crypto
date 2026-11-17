// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto

import java.math.BigInteger
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import me.really.crypto.proto.ReallyMeCryptoProtoAdapters
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.BERSequence
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.sec.SECNamedCurves

class PcurveBoundaryTest : ReallyMeCryptoTestSupport() {
    @BeforeTest
    fun loadProvider() = loadCryptoProviderForTest()

    // Cases contain public metadata and function references, never key owners.
    private class CurveCase(
        val file: String,
        val name: String,
        val signatureAlgorithm: ReallyMeSignatureAlgorithm,
        val agreementAlgorithm: ReallyMeKeyAgreementAlgorithm,
        val verify: (ByteArray, ByteArray, ByteArray) -> Unit,
        val maximumDerLength: Int,
    )

    private fun cases(): List<CurveCase> = listOf(
        CurveCase("p256.json", "secp256r1", ReallyMeSignatureAlgorithm.ECDSA_P256_SHA256, ReallyMeKeyAgreementAlgorithm.P256_ECDH, ReallyMeP256Ecdsa::verify, 72),
        CurveCase("p384.json", "secp384r1", ReallyMeSignatureAlgorithm.ECDSA_P384_SHA384, ReallyMeKeyAgreementAlgorithm.P384_ECDH, ReallyMeP384Ecdsa::verify, 104),
        CurveCase("p521.json", "secp521r1", ReallyMeSignatureAlgorithm.ECDSA_P521_SHA512, ReallyMeKeyAgreementAlgorithm.P521_ECDH, ReallyMeP521Ecdsa::verify, 144),
    )

    @Test
    fun canonicalDerVectorsVerifyWithCompressedAndUncompressedKeys() {
        for (case in cases()) {
            val signature = vectorField(case.file, if (case.file == "p256.json") "ecdsa_signature_der" else "signature_der")
            val message = vectorField(case.file, if (case.file == "p256.json") "ecdsa_message" else "message")
            for (field in listOf("public_key_compressed", "public_key_uncompressed")) {
                val publicKey = vectorField(case.file, field)
                case.verify(signature, message, publicKey)
                ReallyMeCrypto.verify(case.signatureAlgorithm, signature, message, publicKey)
                assertFailsWith<ReallyMeCryptoException.InvalidSignature> {
                    case.verify(signature, message + byteArrayOf(1), publicKey)
                }
            }
        }
    }

    @Test
    fun sharedEncodingVectorsRejectBerSignaturesAndHybridKeys() {
        for (case in cases()) {
            val signature = vectorField(case.file, if (case.file == "p256.json") "ecdsa_signature_der" else "signature_der")
            val message = vectorField(case.file, if (case.file == "p256.json") "ecdsa_message" else "message")
            val publicKey = vectorField(case.file, "public_key_compressed")
            case.verify(signature, message, publicKey)
            for (field in listOf(
                "signature_der_nonminimal_sequence_length",
                "signature_der_indefinite_sequence_length",
                "signature_der_nonminimal_integer_length",
            )) {
                val malformed = vectorField(case.file, field)
                assertFailsWith<ReallyMeCryptoException.InvalidInput>(message = "${case.file}: $field") {
                    case.verify(malformed, message, publicKey)
                }
                assertFailsWith<ReallyMeCryptoException.InvalidInput> {
                    ReallyMeCrypto.verify(case.signatureAlgorithm, malformed, message, publicKey)
                }
            }
            for (field in listOf("public_key_hybrid_even", "public_key_hybrid_odd")) {
                val malformed = vectorField(case.file, field)
                assertFailsWith<ReallyMeCryptoException.InvalidInput>(message = "${case.file}: $field") {
                    case.verify(signature, message, malformed)
                }
                assertFailsWith<ReallyMeCryptoException.InvalidInput> {
                    ReallyMeCrypto.verify(case.signatureAlgorithm, signature, message, malformed)
                }
            }
        }
    }

    @Test
    fun verificationRejectsBerAndNoncanonicalDerAsTypedInputErrors() {
        for (case in cases()) {
            val signature = vectorField(case.file, if (case.file == "p256.json") "ecdsa_signature_der" else "signature_der")
            val message = vectorField(case.file, if (case.file == "p256.json") "ecdsa_message" else "message")
            val publicKey = vectorField(case.file, "public_key_compressed")
            val parsed = ASN1Sequence.getInstance(signature)
            val r = ASN1Integer.getInstance(parsed.getObjectAt(0)).value
            val s = ASN1Integer.getInstance(parsed.getObjectAt(1)).value
            val order = SECNamedCurves.getByName(case.name).n
            val components = arrayOf(ASN1Integer(r), ASN1Integer(s))
            val bodyOffset = if ((signature[1].toInt() and 0xff) < 128) 2 else 3
            val body = signature.copyOfRange(bodyOffset, signature.size)
            assertTrue(body.size < 256)
            val nonminimalLength = byteArrayOf(0x30, 0x82.toByte(), 0, body.size.toByte()) + body
            val rBytes = byteArrayOf(0) + r.toByteArray()
            val paddedR = byteArrayOf(0x02, rBytes.size.toByte()) + rBytes
            val paddedBody = paddedR + ASN1Integer(s).encoded
            val paddedHeader = if (paddedBody.size < 128) {
                byteArrayOf(0x30, paddedBody.size.toByte())
            } else {
                byteArrayOf(0x30, 0x81.toByte(), paddedBody.size.toByte())
            }
            val invalid = listOf(
                ByteArray(0),
                ByteArray(Math.addExact(case.maximumDerLength, 1)),
                BERSequence(components).encoded,
                nonminimalLength,
                paddedHeader + paddedBody,
                signature + byteArrayOf(0),
                DERSequence(arrayOf(ASN1Integer(r.negate()), ASN1Integer(s))).encoded,
                DERSequence(arrayOf(ASN1Integer(BigInteger.ZERO), ASN1Integer(s))).encoded,
                DERSequence(arrayOf(ASN1Integer(order), ASN1Integer(s))).encoded,
                DERSequence(arrayOf(ASN1Integer(r))).encoded,
                DERSequence(arrayOf(ASN1Integer(r), ASN1Integer(s), ASN1Integer(BigInteger.ONE))).encoded,
            )
            for (malformed in invalid) {
                assertFailsWith<ReallyMeCryptoException.InvalidInput> { case.verify(malformed, message, publicKey) }
                assertFailsWith<ReallyMeCryptoException.InvalidInput> {
                    ReallyMeCrypto.verify(case.signatureAlgorithm, malformed, message, publicKey)
                }
            }
        }
    }

    @Test
    fun verificationRejectsHybridAndCompactPublicKeyAliases() {
        for (case in cases()) {
            val signature = vectorField(case.file, if (case.file == "p256.json") "ecdsa_signature_der" else "signature_der")
            val message = vectorField(case.file, if (case.file == "p256.json") "ecdsa_message" else "message")
            for ((field, prefixes) in listOf(
                "public_key_compressed" to listOf(0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0xff),
                "public_key_uncompressed" to listOf(0x00, 0x02, 0x03, 0x05, 0x06, 0x07, 0xff),
            )) {
                for (prefix in prefixes) {
                    val alias = vectorField(case.file, field).also { it[0] = prefix.toByte() }
                    assertFailsWith<ReallyMeCryptoException.InvalidInput> { case.verify(signature, message, alias) }
                }
            }
        }
    }

    @Test
    fun rustAgreementMatchesSharedVectorsAndPreservesCallerInputs() {
        for (case in cases()) {
            val secret = vectorField(case.file, "secret_key")
            val original = secret.copyOf()
            val peer = vectorField(case.file, "peer_public_key_compressed")
            val expected = vectorField(case.file, "shared_secret")
            try {
                val publicKey = ReallyMeRustKeyAgreement.derivePublicKey(case.agreementAlgorithm, secret)
                assertContentEquals(vectorField(case.file, "public_key_compressed"), publicKey)
                val shared = ReallyMeRustKeyAgreement.deriveSharedSecret(case.agreementAlgorithm, peer, secret)
                try {
                    assertContentEquals(expected, shared)
                    assertContentEquals(original, secret)
                } finally {
                    shared.fill(0)
                }
                for (prefix in listOf(0x00, 0x04, 0x05, 0x06, 0x07, 0xff)) {
                    val alias = peer.copyOf().also { it[0] = prefix.toByte() }
                    assertFailsWith<ReallyMeCryptoException.InvalidInput> {
                        ReallyMeRustKeyAgreement.deriveSharedSecret(case.agreementAlgorithm, alias, secret)
                    }
                }
                assertFailsWith<ReallyMeCryptoException.InvalidInput> {
                    ReallyMeRustKeyAgreement.derivePublicKey(case.agreementAlgorithm, ByteArray(secret.size))
                }
            } finally {
                secret.fill(0)
                original.fill(0)
                expected.fill(0)
            }
        }
    }

    @Test
    fun nativeAgreementBoundaryRejectsNullOversizedAndUnknownInputs() {
        val derive = ReallyMeRustKeyAgreement::class.java.getDeclaredMethod(
            "derivePublicKeyNative", Int::class.javaPrimitiveType, ByteArray::class.java,
        ).also { it.isAccessible = true }
        for (selector in listOf(0, -1, Int.MAX_VALUE)) {
            val encoded = derive.invoke(null, selector, ByteArray(0)) as? ByteArray
            assertEquals(ReallyMeNativeStatus.UNSUPPORTED_ALGORITHM, decodeRustNativeResult(encoded).status)
        }
        val selector = ReallyMeCryptoProtoAdapters.toProto(ReallyMeKeyAgreementAlgorithm.P256_ECDH).number
        for (input in listOf(null, ByteArray(Math.addExact(MAX_PROTOBUF_REQUEST_BYTES, 1)))) {
            val encoded = derive.invoke(null, selector, input) as? ByteArray
            assertEquals(ReallyMeNativeStatus.INVALID_INPUT, decodeRustNativeResult(encoded).status)
        }
    }
}
