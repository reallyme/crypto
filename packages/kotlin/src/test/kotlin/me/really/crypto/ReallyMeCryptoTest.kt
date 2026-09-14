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

class ReallyMeCryptoTest : ReallyMeCryptoTestSupport() {
    @Test
    fun nullNativeOperationResponseMapsToTypedProviderFailure() {
        assertFailsWith<ReallyMeCryptoException.ProviderFailure> {
            requireNativeOperationResponse(null)
        }
        assertContentEquals(
            byteArrayOf(1, 2, 3),
            requireNativeOperationResponse(byteArrayOf(1, 2, 3)),
        )
    }

    @Test
    fun genericProtoAndProtoJsonLanesMatchGeneratedVector() {
        ReallyMeRustNativeProvider.loadBundledLibrary()
        assertContentEquals(
            vectorField("operation_response.json", "operation_response"),
            ReallyMeCrypto.processOperationResponse(
                vectorField("operation_response.json", "request_protobuf"),
            ),
        )
        assertContentEquals(
            vectorField("operation_response.json", "operation_response"),
            ReallyMeCrypto.processOperationResponseJson(
                vectorField("operation_response.json", "request_json"),
            ),
        )
        assertContentEquals(
            vectorField("operation_response.json", "malformed_protobuf_response"),
            ReallyMeCrypto.processOperationResponse(
                vectorField("operation_response.json", "malformed_protobuf"),
            ),
        )
        assertContentEquals(
            vectorField("operation_response.json", "malformed_json_response"),
            ReallyMeCrypto.processOperationResponseJson(
                vectorField("operation_response.json", "malformed_json"),
            ),
        )

        for (oversizedResponseBytes in listOf(
            ReallyMeCrypto.processOperationResponse(ByteArray(MAX_PROTOBUF_REQUEST_BYTES + 1)),
            ReallyMeCrypto.processOperationResponseJson(ByteArray(MAX_PROTO_JSON_REQUEST_BYTES + 1)),
        )) {
            val response = CryptoOperationResponse.parseFrom(oversizedResponseBytes)
            assertEquals(
                CryptoOperationResponse.OutcomeCase.ERROR,
                response.outcomeCase,
            )
            assertEquals(
                CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED,
                response.error.primitive.reason,
            )
        }
    }

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
    fun jceProviderIdentityIsInspectableForProviderBackedPrimitives() {
        val gcmCipher = ReallyMeJceProviders.bouncyCastleCipher("AES/GCM/NoPadding")
        val aesKwCipher = ReallyMeJceProviders.bouncyCastleCipher("AESWrap")
        val rsaSignature = ReallyMeJceProviders.bouncyCastleSignature("SHA256withRSA")
        val rsaKeyFactory = ReallyMeJceProviders.bouncyCastleKeyFactory("RSA")

        assertTrue(ReallyMeJceProviders.isBundledBouncyCastleProvider(gcmCipher.provider))
        assertTrue(ReallyMeJceProviders.isBundledBouncyCastleProvider(aesKwCipher.provider))
        assertTrue(ReallyMeJceProviders.isBundledBouncyCastleProvider(rsaSignature.provider))
        assertTrue(ReallyMeJceProviders.isBundledBouncyCastleProvider(rsaKeyFactory.provider))
    }

    @Test
    fun bestEffortMemoryCleanupOverwritesCallerOwnedKotlinBytes() {
        val secret = byteArrayOf(1, 2, 3, 4, 5, 6)
        ReallyMeCryptoMemory.bestEffortClear(secret)
        assertContentEquals(ByteArray(6), secret)
    }

    @Test
    fun randomSecretSamplingClearsItsInternalCandidateOnSuccessAndFailure() {
        val sampledBytes = ByteArray(32) { index -> (index + 1).toByte() }
        var successfulCandidate: ByteArray? = null
        val successfulRandom = object : SecureRandom() {
            override fun nextBytes(bytes: ByteArray) {
                sampledBytes.copyInto(bytes)
                successfulCandidate = bytes
            }
        }

        val retainedSecret = withRandomSecretCandidate(
            length = sampledBytes.size,
            random = successfulRandom,
            isValid = { true },
            buildResult = { candidate -> candidate.copyOf() },
        )

        assertContentEquals(sampledBytes, retainedSecret)
        assertTrue(successfulCandidate?.all { byte -> byte == 0.toByte() } == true)

        var rejectedCandidate: ByteArray? = null
        val rejectingRandom = object : SecureRandom() {
            override fun nextBytes(bytes: ByteArray) {
                sampledBytes.copyInto(bytes)
                rejectedCandidate = bytes
            }
        }
        assertFailsWith<ReallyMeCryptoException.ProviderFailure> {
            withRandomSecretCandidate(
                length = sampledBytes.size,
                random = rejectingRandom,
                isValid = { false },
                buildResult = { candidate -> candidate.copyOf() },
            )
        }
        assertTrue(rejectedCandidate?.all { byte -> byte == 0.toByte() } == true)
    }

    @Test
    fun secretBearingContainersDoNotStringifyOrHashSecretBytes() {
        val publicKey = byteArrayOf(1, 2, 3)
        val firstSecret = byteArrayOf(91, 92, 93)
        val secondSecret = byteArrayOf(94, 95, 96)
        val first = ReallyMeSignatureKeyPair(publicKey, firstSecret)
        val second = ReallyMeSignatureKeyPair(publicKey.copyOf(), secondSecret)
        val description = first.toString()

        assertTrue(description.contains("<redacted>"))
        assertFalse(description.contains("91"))
        assertEquals(first.hashCode(), second.hashCode())

        val encapsulation = ReallyMeKemEncapsulation(
            sharedSecret = byteArrayOf(81, 82, 83),
            ciphertext = byteArrayOf(1, 2, 3),
        )
        val encapsulationDescription = encapsulation.toString()
        assertTrue(encapsulationDescription.contains("<redacted>"))
        assertFalse(encapsulationDescription.contains("81"))
    }

    @Test
    fun secretBearingContainersCompareSecretHalvesWithoutChangingValueSemantics() {
        val publicKey = byteArrayOf(1, 2, 3)
        val secret = byteArrayOf(4, 5, 6)
        assertEquals(
            ReallyMeSignatureKeyPair(publicKey, secret),
            ReallyMeSignatureKeyPair(publicKey.copyOf(), secret.copyOf()),
        )
        assertEquals(
            ReallyMeKemKeyPair(publicKey, secret),
            ReallyMeKemKeyPair(publicKey.copyOf(), secret.copyOf()),
        )
        assertEquals(
            ReallyMeKeyAgreementKeyPair(publicKey, secret),
            ReallyMeKeyAgreementKeyPair(publicKey.copyOf(), secret.copyOf()),
        )
        assertEquals(
            ReallyMeKemEncapsulation(secret, publicKey),
            ReallyMeKemEncapsulation(secret.copyOf(), publicKey.copyOf()),
        )

        val differentSecret = byteArrayOf(4, 5, 7)
        assertFalse(
            ReallyMeSignatureKeyPair(publicKey, secret) ==
                ReallyMeSignatureKeyPair(publicKey, differentSecret),
        )
        assertFalse(
            ReallyMeKemKeyPair(publicKey, secret) ==
                ReallyMeKemKeyPair(publicKey, differentSecret),
        )
        assertFalse(
            ReallyMeKeyAgreementKeyPair(publicKey, secret) ==
                ReallyMeKeyAgreementKeyPair(publicKey, differentSecret),
        )
        assertFalse(
            ReallyMeKemEncapsulation(secret, publicKey) ==
                ReallyMeKemEncapsulation(differentSecret, publicKey),
        )
    }

    @Test
    fun rustNativeResultDecoderPreservesTypedStatus() {
        val payload = byteArrayOf(0x01, 0x02, 0x03)
        val encodedOk = nativeEnvelope(ReallyMeNativeStatus.OK, payload)
        val ok = decodeRustNativeResult(encodedOk)
        assertEquals(ReallyMeNativeStatus.OK, ok.status)
        assertContentEquals(payload, ok.bytes)
        assertContentEquals(ByteArray(encodedOk.size), encodedOk)

        assertEquals(
            ReallyMeNativeStatus.BACKEND_INTERNAL,
            decodeRustNativeResult(null).status,
        )
        val shortEnvelope = byteArrayOf(0x00, 0x01)
        assertEquals(
            ReallyMeNativeStatus.BACKEND_INTERNAL,
            decodeRustNativeResult(shortEnvelope).status,
        )
        assertContentEquals(ByteArray(shortEnvelope.size), shortEnvelope)

        val unknownEnvelope = nativeEnvelope(127, byteArrayOf(0x55, 0x66))
        val unknown = decodeRustNativeResult(unknownEnvelope)
        assertEquals(
            ReallyMeNativeStatus.BACKEND_INTERNAL,
            unknown.status,
        )
        assertContentEquals(ByteArray(0), unknown.bytes)
        assertContentEquals(ByteArray(unknownEnvelope.size), unknownEnvelope)
        assertTrue(unknown.toString().contains("<redacted>"))
        assertFalse(unknown.toString().contains("85"))

        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            requireRustNativeBytes(
                nativeEnvelope(ReallyMeNativeStatus.INVALID_INPUT, byteArrayOf(0x55, 0x66)),
            )
        }
        assertFailsWith<ReallyMeCryptoException.AuthenticationFailed> {
            requireRustNativeBytes(nativeEnvelope(ReallyMeNativeStatus.AUTHENTICATION_FAILED))
        }
        assertFailsWith<ReallyMeCryptoException.ProviderFailure> {
            requireRustNativeBytes(null)
        }
    }

    @Test
    fun rustNativeStatusesMapToLosslessWireErrors() {
        val invalidInput = ReallyMeCryptoProtoAdapters.wireErrorFromNativeStatus(
            ReallyMeNativeStatus.INVALID_INPUT,
        )
        assertEquals(ReallyMeCryptoWireErrorBranch.PRIMITIVE, invalidInput.branch)
        assertEquals(
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER,
            invalidInput.reason,
        )

        val authentication = ReallyMeCryptoProtoAdapters.wireErrorFromNativeStatus(
            ReallyMeNativeStatus.AUTHENTICATION_FAILED,
        )
        assertEquals(ReallyMeCryptoWireErrorBranch.PRIMITIVE, authentication.branch)
        assertEquals(
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED,
            authentication.reason,
        )

        val providerUnavailable = ReallyMeCryptoProtoAdapters.wireErrorFromNativeStatus(
            ReallyMeNativeStatus.PROVIDER_UNAVAILABLE,
        )
        assertEquals(ReallyMeCryptoWireErrorBranch.PROVIDER, providerUnavailable.branch)
        assertEquals(
            CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE,
            providerUnavailable.reason,
        )

        val backend = ReallyMeCryptoProtoAdapters.wireErrorFromNativeStatus(
            ReallyMeNativeStatus.BACKEND_INTERNAL,
        )
        assertEquals(ReallyMeCryptoWireErrorBranch.BACKEND, backend.branch)
        assertEquals(CryptoErrorReason.CRYPTO_ERROR_REASON_BACKEND_INTERNAL, backend.reason)
    }

    @Test
    fun rustNativeProviderLoadFailuresAreTyped() {
        assertEquals(ReallyMeNativeStatus.INVALID_INPUT, ReallyMeRustNativeProvider.loadLibraryStatus(""))

        val missingPath = Files.createTempDirectory("reallyme-crypto-native-test")
            .resolve("missing-libcrypto-ffi.so")
            .toAbsolutePath()
            .toString()
        val status = ReallyMeRustNativeProvider.loadLibraryStatus(missingPath)
        assertEquals(ReallyMeNativeStatus.PROVIDER_UNAVAILABLE, status)

        val wire = ReallyMeCryptoProtoAdapters.wireErrorFromNativeStatus(status)
        assertEquals(ReallyMeCryptoWireErrorBranch.PROVIDER, wire.branch)
        assertEquals(CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE, wire.reason)
    }

    @Test
    fun bundledRustNativeProviderVerifiesManifestBeforeLoad() {
        assertEquals(ReallyMeNativeStatus.OK, ReallyMeRustNativeProvider.loadBundledLibraryStatus())
        val unrelatedFile = Files.createTempFile("reallyme-crypto-unrelated", ".bin")
        Files.write(unrelatedFile, byteArrayOf(0x01, 0x02, 0x03))

        assertEquals(
            ReallyMeNativeStatus.PROVIDER_UNAVAILABLE,
            ReallyMeRustNativeProvider.loadLibraryStatus(unrelatedFile.toAbsolutePath().toString()),
        )
    }

    @Test
    fun classpathNativeExtractionUsesPrivateDirectoryAndRehashesOnDiskFile() {
        val resource = ReallyMeRustNativeProvider.platformNativeResource()
        assumeTrue(resource != null)
        if (resource == null) {
            return
        }
        val stream = ReallyMeRustNativeProvider::class.java.getResourceAsStream(resource.path)
        assumeTrue(stream != null)
        if (stream == null) {
            return
        }
        val bytes = stream.use { source -> source.readBytes() }
        val parent = Files.createTempDirectory("reallyme-crypto-native-parent")
        var extractedPath: Path? = null
        try {
            val extracted = assertNotNull(
                ReallyMeRustNativeProvider.extractNativeResourceForLoad(resource, bytes, parent),
            )
            extractedPath = extracted
            val extractionParent = assertNotNull(extracted.parent?.parent)
            assertEquals(parent.toRealPath(), extractionParent.toRealPath())
            assertTrue(ReallyMeRustNativeProvider.verifyNativeResourceOnDisk(resource, extracted))
            assertEquals(
                extracted.toRealPath(),
                ReallyMeRustNativeProvider.validateExtractedLibraryForLoad(resource, extracted),
            )
            val directoryView = Files.getFileAttributeView(
                extracted.parent,
                PosixFileAttributeView::class.java,
            )
            val fileView = Files.getFileAttributeView(extracted, PosixFileAttributeView::class.java)
            if (directoryView != null && fileView != null) {
                assertEquals(
                    setOf(
                        PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE,
                        PosixFilePermission.OWNER_EXECUTE,
                    ),
                    directoryView.readAttributes().permissions(),
                )
                assertEquals(
                    setOf(
                        PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE,
                    ),
                    fileView.readAttributes().permissions(),
                )
            }

            val tampered = bytes.copyOf()
            tampered[0] = (tampered[0].toInt() xor 0x01).toByte()
            Files.write(extracted, tampered)
            assertFalse(ReallyMeRustNativeProvider.verifyNativeResourceOnDisk(resource, extracted))
            assertEquals(
                null,
                ReallyMeRustNativeProvider.validateExtractedLibraryForLoad(resource, extracted),
            )
        } finally {
            if (extractedPath != null) {
                Files.deleteIfExists(extractedPath)
                Files.deleteIfExists(extractedPath.parent)
            }
            Files.deleteIfExists(parent)
        }
    }

    @Test
    fun secretBearingKeyPairResultsDoNotAliasCallerInputs() {
        val xWingSecret = ByteArray(ReallyMeXWing.SECRET_KEY_LENGTH) { index ->
            (index + 1).toByte()
        }
        val originalXWingSecret = xWingSecret.copyOf()
        val xWingKeyPair = ReallyMeCrypto.deriveKemKeyPair(
            ReallyMeKemAlgorithm.X_WING_768,
            xWingSecret,
        )
        xWingSecret.fill(0)
        assertContentEquals(originalXWingSecret, xWingKeyPair.secretKey)

        val mlKemSecret = ByteArray(ReallyMeMlKem.SECRET_KEY_LENGTH) { index ->
            (index + 3).toByte()
        }
        val originalMlKemSecret = mlKemSecret.copyOf()
        val mlKemKeyPair = ReallyMeCrypto.deriveKemKeyPair(
            ReallyMeKemAlgorithm.ML_KEM_768,
            mlKemSecret,
        )
        mlKemSecret.fill(0)
        assertContentEquals(originalMlKemSecret, mlKemKeyPair.secretKey)

        val signingSecret = ByteArray(ReallyMeEd25519.SECRET_KEY_LENGTH) { index ->
            (index + 5).toByte()
        }
        val originalSigningSecret = signingSecret.copyOf()
        val signingKeyPair = ReallyMeCrypto.deriveKeyPair(
            ReallyMeSignatureAlgorithm.ED25519,
            signingSecret,
        )
        signingSecret.fill(0)
        assertContentEquals(originalSigningSecret, signingKeyPair.secretKey)

        val agreementSecret = x25519SecretKey.copyOf()
        val originalAgreementSecret = agreementSecret.copyOf()
        val agreementKeyPair = ReallyMeCrypto.deriveKeyAgreementKeyPair(
            ReallyMeKeyAgreementAlgorithm.X25519,
            agreementSecret,
        )
        agreementSecret.fill(0)
        assertContentEquals(originalAgreementSecret, agreementKeyPair.secretKey)
    }

    @Test
    fun rustNativeJniBoundaryRejectsNullArraysWhenLoaded() {
        loadCryptoProviderForTestOrReturn() ?: return

        val aeadSeal = nativeAeadMethod("aes256GcmSivSealNative")
        val aeadNullKey = aeadSeal.invoke(
            null,
            null,
            ByteArray(ReallyMeRustAead.AES_GCM_SIV_NONCE_LENGTH),
            ByteArray(0),
            ByteArray(0),
        ) as ByteArray?
        assertEquals(ReallyMeNativeStatus.INVALID_INPUT, decodeRustNativeResult(aeadNullKey).status)

        val argon2id = ReallyMeArgon2id::class.java.getDeclaredMethod(
            "deriveKeyNative",
            Int::class.javaPrimitiveType,
            ByteArray::class.java,
            ByteArray::class.java,
        )
        argon2id.isAccessible = true
        val argon2idNullSecret = argon2id.invoke(null, 1, null, "somesaltvalue1234".toByteArray()) as ByteArray?
        assertEquals(
            ReallyMeNativeStatus.INVALID_INPUT,
            decodeRustNativeResult(argon2idNullSecret).status,
        )
    }

    @Test
    fun rustNativeJniBoundaryPreservesInvalidLengthAndAuthenticationWhenLoaded() {
        loadCryptoProviderForTestOrReturn() ?: return

        val key = base64UrlBytes("MDEyMzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk8")
        val nonce = base64UrlBytes("0NHS09TV1tfY2drb")
        val aad = base64UrlBytes("cmVhbGx5bWUtY3J5cHRvLWdjbS1zaXYtdmVjdG9yLWFhZA")
        val plaintext = base64UrlBytes("UmVhbGx5TWUgQUVTLTI1Ni1HQ00tU0lWIGNvbmZvcm1hbmNlIHZlY3Rvcg")
        val ciphertext = base64UrlBytes(
            "830aIA-5lFFihlRNK2QIUHoFRAQXaaBqX2nDndhvyVq-EcnpsGqtqHVZC1bTdM8kugkvV_o3Ve9HQq4",
        )

        val seal = nativeAeadMethod("aes256GcmSivSealNative")
        val invalidKey = seal.invoke(null, ByteArray(31), nonce, aad, plaintext) as ByteArray?
        assertEquals(ReallyMeNativeStatus.INVALID_INPUT, decodeRustNativeResult(invalidKey).status)

        val open = nativeAeadMethod("aes256GcmSivOpenNative")
        val tampered = ciphertext.copyOf()
        tampered[0] = (tampered[0].toInt() xor 0x01).toByte()
        val authentication = open.invoke(null, key, nonce, aad, tampered) as ByteArray?
        assertEquals(
            ReallyMeNativeStatus.AUTHENTICATION_FAILED,
            decodeRustNativeResult(authentication).status,
        )
    }

    @Test
    fun multikeyVectorRoundTrips() {
        val vector = jwkVectors().first { it.alg == "Ed25519" && it.multikeyStatus == "supported" }
        val multikey = requireNotNull(vector.multikey)
        val parsed = ReallyMeMultikey.parse(multikey)

        assertEquals("ed25519-pub", parsed.algorithm.codecName)
        assertEquals(vector.alg, parsed.algorithmName)
        assertEquals(vector.publicKeyLength, parsed.expectedPublicKeyLength)
        assertEquals(vector.publicKeyLength, parsed.publicKey.size)
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
    fun jwkParserRejectsPrivateKeyMembers() {
        val publicX = "A".repeat(43)
        listOf("d", "p", "q", "dp", "dq", "qi", "oth", "k", "priv", "privateKey", "secretKey")
            .forEach { name ->
                val json =
                    """{"alg":"EdDSA","crv":"Ed25519","kty":"OKP","use":"sig","x":"$publicX","$name":"redacted-test-value"}"""
                assertFailsWith<ReallyMeCryptoException.InvalidInput> {
                    ReallyMeJwk.fromJwkJson(json)
                }
            }
    }

    @Test
    fun jwkParserRejectsDuplicateUnknownAndMixedShapeMembers() {
        val publicX = "A".repeat(43)
        val valid = """{"alg":"EdDSA","crv":"Ed25519","kty":"OKP","use":"sig","x":"$publicX"}"""
        listOf(
            """{"alg":"EdDSA","crv":"Ed25519","kty":"OKP","kty":"OKP","use":"sig","x":"$publicX"}""",
            """{"alg":"EdDSA","crv":"Ed25519","kty":"OKP","use":"sig","x":"$publicX","unknown":"value"}""",
            """{"alg":"EdDSA","crv":"Ed25519","kty":"OKP","use":"sig","x":"$publicX","y":"$publicX"}""",
        ).forEach { json ->
            assertFailsWith<ReallyMeCryptoException.InvalidInput> {
                ReallyMeJwk.fromJwkJson(json)
            }
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeJwk.fromJwksJson("""{"keys":[$valid],"unknown":"value"}""")
        }
    }

    @Test
    fun jwkParserRejectsMismatchedEcCoordinates() {
        listOf("P-256", "secp256k1").forEach { algorithm ->
            val vector = jwkVectors().first { it.alg == algorithm }
            listOf(YMutation.SAME_PARITY, YMutation.OPPOSITE_PARITY).forEach { mutation ->
                assertFailsWith<ReallyMeCryptoException.InvalidInput>(message = algorithm) {
                    ReallyMeJwk.fromJwkJson(mutatedEcJwkJson(vector.jwkJcs, mutation))
                }
            }
        }
    }

    @Test
    fun okpMetadataIsOptionalButConflictsAreRejected() {
        val publicX = "A".repeat(43)
        val omitted = """{"crv":"Ed25519","kty":"OKP","x":"$publicX"}"""
        assertEquals(ReallyMeJwkAlgorithm.ED25519, ReallyMeJwk.fromJwkJson(omitted).algorithm)

        listOf(""""alg":"ECDH-ES",""", """"use":"enc",""").forEach { metadata ->
            val conflicting = """{$metadata"crv":"Ed25519","kty":"OKP","x":"$publicX"}"""
            assertFailsWith<ReallyMeCryptoException.InvalidInput> {
                ReallyMeJwk.fromJwkJson(conflicting)
            }
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

}
