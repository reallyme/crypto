// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import me.really.codec.ReallyMeCodecRustNativeProvider
import me.really.crypto.proto.ReallyMeCryptoProtoStatus
import me.really.crypto.proto.ReallyMeCryptoProtoAdapters
import me.really.crypto.proto.ReallyMeCryptoWireError
import me.really.crypto.proto.ReallyMeCryptoWireErrorBranch
import me.really.crypto.proto.ReallyMeCryptoWireErrorValidationResult
import me.really.crypto.proto.ReallyMeProviderCapabilityProtoValue
import me.really.crypto.v1.CryptoAlgorithmFamily
import me.really.crypto.v1.CryptoAlgorithmIdentifier
import me.really.crypto.v1.CryptoError
import me.really.crypto.v1.CryptoErrorReason
import me.really.crypto.v1.CryptoPrimitiveError
import me.really.crypto.v1.CryptoProviderError
import me.really.crypto.v1.CryptoProviderSupportStatus
import me.really.crypto.v1.CryptoSignatureDeriveKeyPairRequest
import me.really.crypto.v1.CryptoVerificationStatus
import me.really.crypto.v1.HashAlgorithm
import me.really.crypto.v1.MulticodecKeyAlgorithm
import me.really.crypto.v1.SignatureAlgorithm
import org.junit.jupiter.api.Assumptions.assumeTrue
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.test.fail

class ProtoAdapterTest {
    @Test
    fun supportedProtoAlgorithmsRoundTripToFacadeEnums() {
        assertEquals(
            ReallyMeSignatureAlgorithm.ED25519,
            ReallyMeCryptoProtoAdapters.fromProto(
                SignatureAlgorithm.SIGNATURE_ALGORITHM_ED25519,
            ),
        )
        assertEquals(
            SignatureAlgorithm.SIGNATURE_ALGORITHM_BIP340_SCHNORR_SECP256K1_SHA256,
            ReallyMeCryptoProtoAdapters.toProto(
                ReallyMeSignatureAlgorithm.BIP340_SCHNORR_SECP256K1_SHA256,
            ),
        )
        assertEquals(
            ReallyMeHashAlgorithm.SHA2_256,
            ReallyMeCryptoProtoAdapters.fromProto(HashAlgorithm.HASH_ALGORITHM_SHA2_256),
        )
        assertEquals(
            HashAlgorithm.HASH_ALGORITHM_SHA3_512,
            ReallyMeCryptoProtoAdapters.toProto(ReallyMeHashAlgorithm.SHA3_512),
        )
        assertEquals(
            ReallyMeMulticodecKeyAlgorithm.ML_KEM_768_PUBLIC_KEY,
            ReallyMeCryptoProtoAdapters.fromProto(
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ML_KEM_768_PUB,
            ),
        )
    }

    @Test
    fun adaptersRejectUnspecifiedAndPrivateCodecs() {
        assertFailsWith<ReallyMeCryptoException.UnsupportedAlgorithm> {
            ReallyMeCryptoProtoAdapters.fromProto(HashAlgorithm.HASH_ALGORITHM_UNSPECIFIED)
        }
        assertFailsWith<ReallyMeCryptoException.UnsupportedAlgorithm> {
            ReallyMeCryptoProtoAdapters.fromProto(
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ED25519_PRIV,
            )
        }
        assertFailsWith<ReallyMeCryptoException.UnsupportedAlgorithm> {
            ReallyMeCryptoProtoAdapters.fromProto(SignatureAlgorithm.UNRECOGNIZED)
        }
    }

    @Test
    fun protoErrorBytesRoundTripTypedCryptoErrors() {
        val decoded = ReallyMeCryptoProtoAdapters.fromProtoErrorBytes(
            ReallyMeCryptoProtoAdapters.toProtoBytes(
                ReallyMeCryptoException.InvalidSignature(),
            ),
        )
        val authenticationFailure = ReallyMeCryptoProtoAdapters.fromProtoErrorBytes(
            ReallyMeCryptoProtoAdapters.toProtoBytes(
                ReallyMeCryptoException.AuthenticationFailed(),
            ),
        )

        assertTrue(decoded is ReallyMeCryptoException.InvalidSignature)
        assertTrue(authenticationFailure is ReallyMeCryptoException.AuthenticationFailed)
        assertTrue(
            ReallyMeCryptoProtoAdapters.fromProtoErrorBytes(
                byteArrayOf(0xff.toByte()),
            ) is ReallyMeCryptoException.ProviderFailure,
        )
    }

    @Test
    fun protoWireErrorsPreserveBranchAndReason() {
        val wireError = ReallyMeCryptoWireError.tryNew(
            ReallyMeCryptoWireErrorBranch.PRIMITIVE,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PRIVATE_KEY,
        ).let(::validatedWireError)
        val encoded = ReallyMeCryptoProtoAdapters.wireErrorToProtoBytes(wireError)
        val decoded = ReallyMeCryptoProtoAdapters.wireErrorFromProtoBytes(encoded)
        val errorResult = ReallyMeCryptoProtoAdapters.protoErrorResult(wireError)
        val successResult = ReallyMeCryptoProtoAdapters.protoResult(byteArrayOf(1, 2, 3))

        assertEquals(wireError, decoded)
        assertEquals(ReallyMeCryptoProtoStatus.CRYPTO_ERROR, errorResult.status)
        assertTrue(errorResult.isCryptoError)
        assertEquals(
            wireError,
            ReallyMeCryptoProtoAdapters.wireErrorFromProtoBytes(errorResult.bytes),
        )
        assertEquals(ReallyMeCryptoProtoStatus.RESULT, successResult.status)
        assertTrue(!successResult.isCryptoError)
        assertContentEquals(byteArrayOf(1, 2, 3), successResult.bytes)
    }

    @Test
    fun protoWireErrorsPreserveFutureBranchReasonCodes() {
        val encoded = CryptoError.newBuilder()
            .setPrimitive(CryptoPrimitiveError.newBuilder().setReasonValue(199))
            .build()
            .toByteArray()
        val wire = ReallyMeCryptoProtoAdapters.wireErrorFromProtoBytes(encoded)

        assertEquals(ReallyMeCryptoWireErrorBranch.PRIMITIVE, wire.branch)
        assertEquals(199, wire.reasonCode)
        assertEquals(null, wire.knownReason)
        assertEquals(
            wire,
            ReallyMeCryptoProtoAdapters.wireErrorFromProtoBytes(
                ReallyMeCryptoProtoAdapters.wireErrorToProtoBytes(wire),
            ),
        )
    }

    @Test
    fun protoResultAndGeneratedMessagesRedactAndClearBytes() {
        val callerBytes = byteArrayOf(1, 2, 3)
        val result = ReallyMeCryptoProtoAdapters.protoResult(callerBytes)
        callerBytes.fill(0)
        assertContentEquals(byteArrayOf(1, 2, 3), result.bytes)
        assertTrue(result.toString().contains("<redacted>"))
        result.bestEffortClear()
        assertContentEquals(byteArrayOf(0, 0, 0), result.bytes)

        val first = CryptoSignatureDeriveKeyPairRequest.newBuilder()
            .setSecretKey(com.google.protobuf.ByteString.copyFrom(byteArrayOf(1, 2, 3)))
            .build()
        val second = CryptoSignatureDeriveKeyPairRequest.newBuilder()
            .setSecretKey(com.google.protobuf.ByteString.copyFrom(byteArrayOf(4, 5, 6)))
            .build()
        assertTrue(first.toString().contains("<redacted>"))
        assertEquals(first.hashCode(), second.hashCode())
    }

    @Test
    fun protoWireErrorConstructorRejectsInvalidPairs() {
        assertTrue(
            ReallyMeCryptoWireError.tryNew(
                ReallyMeCryptoWireErrorBranch.PRIMITIVE,
                CryptoErrorReason.CRYPTO_ERROR_REASON_UNSPECIFIED,
            ) is ReallyMeCryptoWireErrorValidationResult.Failure,
        )
        assertTrue(
            ReallyMeCryptoWireError.tryNew(
                ReallyMeCryptoWireErrorBranch.PROVIDER,
                CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
            ) is ReallyMeCryptoWireErrorValidationResult.Failure,
        )
    }

    @Test
    fun malformedCryptoErrorEnvelopesBecomeBackendFailures() {
        val malformedBytes = byteArrayOf(0xff.toByte())
        val missingBranch = CryptoError.newBuilder().build().toByteArray()
        val unspecifiedReason = CryptoError.newBuilder()
            .setPrimitive(
                CryptoPrimitiveError.newBuilder()
                    .setReason(CryptoErrorReason.CRYPTO_ERROR_REASON_UNSPECIFIED),
            )
            .build()
            .toByteArray()
        val mismatchedBranch = CryptoError.newBuilder()
            .setProvider(
                CryptoProviderError.newBuilder()
                    .setReason(CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY),
            )
            .build()
            .toByteArray()

        for (bytes in listOf(malformedBytes, missingBranch, unspecifiedReason, mismatchedBranch)) {
            val wire = ReallyMeCryptoProtoAdapters.wireErrorFromProtoBytes(bytes)
            assertEquals(ReallyMeCryptoWireErrorBranch.BACKEND, wire.branch)
            assertEquals(CryptoErrorReason.CRYPTO_ERROR_REASON_BACKEND_MALFORMED_PROTOBUF, wire.reason)
            assertTrue(
                ReallyMeCryptoProtoAdapters.fromProtoErrorBytes(bytes) is
                    ReallyMeCryptoException.ProviderFailure,
            )
        }
    }

    @Test
    fun protoFacadeProjectionDoesNotCollapseInvalidInputToAuthentication() {
        val invalidReasons = listOf(
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PUBLIC_KEY,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PRIVATE_KEY,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_NONCE,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SALT,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PASSWORD,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_ENCODING,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SHARED_SECRET,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_CIPHERTEXT,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_TAG,
        )

        for (reason in invalidReasons) {
            assertTrue(
                ReallyMeCryptoProtoAdapters.facadeErrorFromWireError(
                    ReallyMeCryptoWireError.tryNew(
                        ReallyMeCryptoWireErrorBranch.PRIMITIVE,
                        reason,
                    ).let(::validatedWireError),
                ) is ReallyMeCryptoException.InvalidInput,
            )
        }
        assertTrue(
            ReallyMeCryptoProtoAdapters.facadeErrorFromWireError(
                ReallyMeCryptoWireError.tryNew(
                    ReallyMeCryptoWireErrorBranch.PRIMITIVE,
                    CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED,
                ).let(::validatedWireError),
            ) is ReallyMeCryptoException.AuthenticationFailed,
        )
    }

    private fun validatedWireError(
        result: ReallyMeCryptoWireErrorValidationResult,
    ): ReallyMeCryptoWireError =
        when (result) {
            is ReallyMeCryptoWireErrorValidationResult.Success -> result.value
            is ReallyMeCryptoWireErrorValidationResult.Failure -> {
                fail("expected a valid wire error")
            }
        }

    @Test
    fun protoJsonWebKeyBytesRoundTripThroughCodecPackage() {
        loadCodecProviderForTest()
        val publicKey = ByteArray(32) { index -> index.toByte() }
        val jwk = ReallyMeJwk.toJwk(ReallyMeJwkAlgorithm.ED25519, publicKey)
        val key = ReallyMeJwkKey(ReallyMeJwkAlgorithm.ED25519, publicKey, jwk)

        val decoded = ReallyMeCryptoProtoAdapters.fromProtoJsonWebKeyBytes(
            ReallyMeCryptoProtoAdapters.toProtoBytes(key),
        )
        assertEquals(key.algorithm, decoded.algorithm)
        assertContentEquals(key.publicKey, decoded.publicKey)
        assertEquals(ReallyMeJwk.toJcs(key.jwk), ReallyMeJwk.toJcs(decoded.jwk))

        val decodedSet = ReallyMeCryptoProtoAdapters.fromProtoJsonWebKeySetBytes(
            ReallyMeCryptoProtoAdapters.toProtoJsonWebKeySetBytes(listOf(key)),
        )
        assertEquals(1, decodedSet.size)
        assertContentEquals(key.publicKey, decodedSet[0].publicKey)
    }

    @Test
    fun multiFieldCryptoEnvelopeBytesRoundTrip() {
        val publicKey = byteArrayOf(1, 2, 3, 4)
        val secretKey = byteArrayOf(5, 6, 7, 8)

        val signature = ReallyMeCryptoProtoAdapters.signatureKeyPairFromProtoBytes(
            ReallyMeCryptoProtoAdapters.signatureKeyPairToProtoBytes(
                ReallyMeSignatureAlgorithm.ED25519,
                ReallyMeSignatureKeyPair(publicKey, secretKey),
            ),
        )
        assertEquals(ReallyMeSignatureAlgorithm.ED25519, signature.algorithm)
        assertContentEquals(publicKey, signature.keyPair.publicKey)
        assertContentEquals(secretKey, signature.keyPair.secretKey)

        val keyAgreement = ReallyMeCryptoProtoAdapters.keyAgreementKeyPairFromProtoBytes(
            ReallyMeCryptoProtoAdapters.keyAgreementKeyPairToProtoBytes(
                ReallyMeKeyAgreementAlgorithm.X25519,
                ReallyMeKeyAgreementKeyPair(publicKey, secretKey),
            ),
        )
        assertEquals(ReallyMeKeyAgreementAlgorithm.X25519, keyAgreement.algorithm)
        assertContentEquals(publicKey, keyAgreement.keyPair.publicKey)
        assertContentEquals(secretKey, keyAgreement.keyPair.secretKey)

        val kem = ReallyMeCryptoProtoAdapters.kemKeyPairFromProtoBytes(
            ReallyMeCryptoProtoAdapters.kemKeyPairToProtoBytes(
                ReallyMeKemAlgorithm.ML_KEM_768,
                ReallyMeKemKeyPair(publicKey, secretKey),
            ),
        )
        assertEquals(ReallyMeKemAlgorithm.ML_KEM_768, kem.algorithm)
        assertContentEquals(publicKey, kem.keyPair.publicKey)
        assertContentEquals(secretKey, kem.keyPair.secretKey)

        val encapsulation = ReallyMeCryptoProtoAdapters.kemEncapsulationFromProtoBytes(
            ReallyMeCryptoProtoAdapters.kemEncapsulationToProtoBytes(
                ReallyMeKemAlgorithm.ML_KEM_768,
                ReallyMeKemEncapsulation(
                    sharedSecret = byteArrayOf(9, 10),
                    ciphertext = byteArrayOf(11, 12),
                ),
            ),
        )
        assertEquals(ReallyMeKemAlgorithm.ML_KEM_768, encapsulation.algorithm)
        assertContentEquals(byteArrayOf(9, 10), encapsulation.encapsulation.sharedSecret)
        assertContentEquals(byteArrayOf(11, 12), encapsulation.encapsulation.ciphertext)

        val sealedMessage = ReallyMeCryptoProtoAdapters.hpkeSealedMessageFromProtoBytes(
            ReallyMeCryptoProtoAdapters.hpkeSealedMessageToProtoBytes(
                ReallyMeHpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305,
                ReallyMeHpkeSealedMessage(
                    encapsulatedKey = byteArrayOf(13, 14),
                    ciphertext = byteArrayOf(15, 16),
                ),
            ),
        )
        assertEquals(
            ReallyMeHpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305,
            sealedMessage.suite,
        )
        assertContentEquals(byteArrayOf(13, 14), sealedMessage.sealedMessage.encapsulatedKey)
        assertContentEquals(byteArrayOf(15, 16), sealedMessage.sealedMessage.ciphertext)
    }

    @Test
    fun verificationAndProviderCapabilityEnvelopeBytesRoundTrip() {
        val algorithm = CryptoAlgorithmIdentifier.newBuilder()
            .setSignature(SignatureAlgorithm.SIGNATURE_ALGORITHM_ED25519)
            .build()

        val verification = ReallyMeCryptoProtoAdapters.verificationResultFromProtoBytes(
            ReallyMeCryptoProtoAdapters.verificationResultToProtoBytes(
                ReallyMeCryptoProtoAdapters.verificationResultToProto(algorithm, true),
            ),
        )
        assertEquals(
            CryptoVerificationStatus.CRYPTO_VERIFICATION_STATUS_VALID,
            verification.status,
        )

        val verificationError = ReallyMeCryptoProtoAdapters.verificationResultFromProtoBytes(
            ReallyMeCryptoProtoAdapters.verificationResultToProtoBytes(
                ReallyMeCryptoProtoAdapters.verificationErrorToProto(
                    algorithm,
                    ReallyMeCryptoException.InvalidSignature(),
                ),
            ),
        )
        assertEquals(
            CryptoVerificationStatus.CRYPTO_VERIFICATION_STATUS_ERROR,
            verificationError.status,
        )

        val decodedCapabilities = ReallyMeCryptoProtoAdapters.providerCapabilitySetFromProtoBytes(
            ReallyMeCryptoProtoAdapters.providerCapabilitySetToProtoBytes(
                listOf(
                    ReallyMeProviderCapabilityProtoValue(
                        algorithm = algorithm,
                        family = CryptoAlgorithmFamily.CRYPTO_ALGORITHM_FAMILY_SIGNATURE,
                        providerNames = listOf("rust"),
                        status = CryptoProviderSupportStatus.CRYPTO_PROVIDER_SUPPORT_STATUS_SUPPORTED,
                        usesRust = true,
                    ),
                ),
            ),
        )
        assertEquals(1, decodedCapabilities.size)
        assertEquals(
            CryptoAlgorithmFamily.CRYPTO_ALGORITHM_FAMILY_SIGNATURE,
            decodedCapabilities[0].family,
        )
        assertEquals(listOf("rust"), decodedCapabilities[0].providerNames)
        assertEquals(
            CryptoProviderSupportStatus.CRYPTO_PROVIDER_SUPPORT_STATUS_SUPPORTED,
            decodedCapabilities[0].status,
        )
        assertTrue(decodedCapabilities[0].usesRust)
    }

    private fun loadCodecProviderForTest() {
        val libraryPath = System.getProperty("reallyme.codec.ffiLibraryPath").orEmpty()
        assumeTrue(libraryPath.isNotEmpty(), "set REALLYME_CODEC_FFI_LIBRARY_PATH to a built codec-ffi library")
        ReallyMeCodecRustNativeProvider.loadLibrary(libraryPath)
    }
}
