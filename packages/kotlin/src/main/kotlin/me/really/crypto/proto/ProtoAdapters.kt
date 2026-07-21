// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto.proto

import com.google.protobuf.ByteString
import com.google.protobuf.InvalidProtocolBufferException
import me.really.crypto.ReallyMeAeadAlgorithm
import me.really.crypto.ReallyMeCryptoException
import me.really.crypto.ReallyMeHashAlgorithm
import me.really.crypto.ReallyMeHpkeSuite
import me.really.crypto.ReallyMeHpkeSealedMessage
import me.really.crypto.ReallyMeJwk
import me.really.crypto.ReallyMeJwkAlgorithm
import me.really.crypto.ReallyMeJwkKey
import me.really.crypto.ReallyMeKdfAlgorithm
import me.really.crypto.ReallyMeKemAlgorithm
import me.really.crypto.ReallyMeKemEncapsulation
import me.really.crypto.ReallyMeKemKeyPair
import me.really.crypto.ReallyMeKeyAgreementKeyPair
import me.really.crypto.ReallyMeKeyAgreementAlgorithm
import me.really.crypto.ReallyMeKeyWrapAlgorithm
import me.really.crypto.ReallyMeMacAlgorithm
import me.really.crypto.ReallyMeNativeStatus
import me.really.crypto.ReallyMeMulticodecKeyAlgorithm
import me.really.crypto.ReallyMeSignatureKeyPair
import me.really.crypto.ReallyMeSignatureAlgorithm
import me.really.crypto.v1.AeadAlgorithm
import me.really.crypto.v1.CryptoAlgorithmFamily
import me.really.crypto.v1.CryptoAlgorithmIdentifier
import me.really.crypto.v1.CryptoBackendError
import me.really.crypto.v1.CryptoError
import me.really.crypto.v1.CryptoErrorReason
import me.really.crypto.v1.CryptoHpkeSealedMessage
import me.really.crypto.v1.CryptoKemEncapsulation
import me.really.crypto.v1.CryptoKeyPair
import me.really.crypto.v1.CryptoProviderCapability
import me.really.crypto.v1.CryptoProviderCapabilitySet
import me.really.crypto.v1.CryptoPrimitiveError
import me.really.crypto.v1.CryptoProviderError
import me.really.crypto.v1.CryptoProviderSupportStatus
import me.really.crypto.v1.CryptoVerificationResult
import me.really.crypto.v1.CryptoVerificationStatus
import me.really.crypto.v1.HashAlgorithm
import me.really.crypto.v1.HpkeAeadId
import me.really.crypto.v1.HpkeKdfId
import me.really.crypto.v1.HpkeKemId
import me.really.crypto.v1.HpkeSuiteIdentifier
import me.really.crypto.v1.JsonWebKey
import me.really.crypto.v1.JsonWebKeySet
import me.really.crypto.v1.KdfAlgorithm
import me.really.crypto.v1.KemAlgorithm
import me.really.crypto.v1.KeyAgreementAlgorithm
import me.really.crypto.v1.KeyWrapAlgorithm
import me.really.crypto.v1.MacAlgorithm
import me.really.crypto.v1.MulticodecKeyAlgorithm
import me.really.crypto.v1.SignatureAlgorithm

public data class ReallyMeSignatureKeyPairProtoValue(
    public val algorithm: ReallyMeSignatureAlgorithm,
    public val keyPair: ReallyMeSignatureKeyPair,
)

public data class ReallyMeKeyAgreementKeyPairProtoValue(
    public val algorithm: ReallyMeKeyAgreementAlgorithm,
    public val keyPair: ReallyMeKeyAgreementKeyPair,
)

public data class ReallyMeKemKeyPairProtoValue(
    public val algorithm: ReallyMeKemAlgorithm,
    public val keyPair: ReallyMeKemKeyPair,
)

public data class ReallyMeKemEncapsulationProtoValue(
    public val algorithm: ReallyMeKemAlgorithm,
    public val encapsulation: ReallyMeKemEncapsulation,
)

public data class ReallyMeHpkeSealedMessageProtoValue(
    public val sealedMessage: ReallyMeHpkeSealedMessage,
    public val suite: ReallyMeHpkeSuite,
)

public data class ReallyMeProviderCapabilityProtoValue(
    public val algorithm: CryptoAlgorithmIdentifier,
    public val family: CryptoAlgorithmFamily,
    public val providerNames: List<String>,
    public val status: CryptoProviderSupportStatus,
    public val usesRust: Boolean,
)

public enum class ReallyMeCryptoWireErrorBranch {
    PRIMITIVE,
    PROVIDER,
    BACKEND,
}

public enum class ReallyMeCryptoWireErrorValidationError {
    UNSPECIFIED_REASON,
    BRANCH_REASON_MISMATCH,
    REASON_CODE_OUT_OF_RANGE,
}

public class ReallyMeCryptoWireError private constructor(
    public val branch: ReallyMeCryptoWireErrorBranch,
    public val reasonCode: Int,
) {
    public val knownReason: CryptoErrorReason?
        get() = CryptoErrorReason.forNumber(reasonCode)

    public val reason: CryptoErrorReason
        get() = knownReason ?: CryptoErrorReason.CRYPTO_ERROR_REASON_UNSPECIFIED

    public companion object {
        public fun tryNew(
            branch: ReallyMeCryptoWireErrorBranch,
            reason: CryptoErrorReason,
        ): ReallyMeCryptoWireErrorValidationResult {
            if (reason == CryptoErrorReason.UNRECOGNIZED) {
                return ReallyMeCryptoWireErrorValidationResult.Failure(
                    ReallyMeCryptoWireErrorValidationError.REASON_CODE_OUT_OF_RANGE,
                )
            }
            if (reason == CryptoErrorReason.CRYPTO_ERROR_REASON_UNSPECIFIED) {
                return ReallyMeCryptoWireErrorValidationResult.Failure(
                    ReallyMeCryptoWireErrorValidationError.UNSPECIFIED_REASON,
                )
            }
            if (!ReallyMeCryptoProtoAdapters.reasonMatchesBranch(branch, reason)) {
                return ReallyMeCryptoWireErrorValidationResult.Failure(
                    ReallyMeCryptoWireErrorValidationError.BRANCH_REASON_MISMATCH,
                )
            }
            return ReallyMeCryptoWireErrorValidationResult.Success(
                ReallyMeCryptoWireError(branch, reason.number),
            )
        }

        public fun tryFromReasonCode(
            branch: ReallyMeCryptoWireErrorBranch,
            reasonCode: Int,
        ): ReallyMeCryptoWireErrorValidationResult {
            if (reasonCode == CryptoErrorReason.CRYPTO_ERROR_REASON_UNSPECIFIED.number) {
                return ReallyMeCryptoWireErrorValidationResult.Failure(
                    ReallyMeCryptoWireErrorValidationError.UNSPECIFIED_REASON,
                )
            }
            if (!ReallyMeCryptoProtoAdapters.reasonCodeMatchesBranch(branch, reasonCode)) {
                return ReallyMeCryptoWireErrorValidationResult.Failure(
                    ReallyMeCryptoWireErrorValidationError.REASON_CODE_OUT_OF_RANGE,
                )
            }
            val known = CryptoErrorReason.forNumber(reasonCode)
            if (known != null && !ReallyMeCryptoProtoAdapters.reasonMatchesBranch(branch, known)) {
                return ReallyMeCryptoWireErrorValidationResult.Failure(
                    ReallyMeCryptoWireErrorValidationError.BRANCH_REASON_MISMATCH,
                )
            }
            return ReallyMeCryptoWireErrorValidationResult.Success(
                ReallyMeCryptoWireError(branch, reasonCode),
            )
        }

        internal fun unchecked(
            branch: ReallyMeCryptoWireErrorBranch,
            reason: CryptoErrorReason,
        ): ReallyMeCryptoWireError = ReallyMeCryptoWireError(branch, reason.number)

        internal fun uncheckedReasonCode(
            branch: ReallyMeCryptoWireErrorBranch,
            reasonCode: Int,
        ): ReallyMeCryptoWireError = ReallyMeCryptoWireError(branch, reasonCode)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ReallyMeCryptoWireError) return false
        return branch == other.branch && reasonCode == other.reasonCode
    }

    override fun hashCode(): Int {
        var result = branch.hashCode()
        result = 31 * result + reasonCode
        return result
    }

    override fun toString(): String =
        "ReallyMeCryptoWireError(branch=$branch, reasonCode=$reasonCode)"
}

public sealed interface ReallyMeCryptoWireErrorValidationResult {
    public data class Success(public val value: ReallyMeCryptoWireError) :
        ReallyMeCryptoWireErrorValidationResult

    public data class Failure(public val error: ReallyMeCryptoWireErrorValidationError) :
        ReallyMeCryptoWireErrorValidationResult
}

public object ReallyMeCryptoProtoAdapters {
    public fun wireErrorFromProto(value: CryptoError): ReallyMeCryptoWireError =
        when (value.errorCase) {
            CryptoError.ErrorCase.PRIMITIVE ->
                strictWireError(ReallyMeCryptoWireErrorBranch.PRIMITIVE, value.primitive.reasonValue)
            CryptoError.ErrorCase.PROVIDER ->
                strictWireError(ReallyMeCryptoWireErrorBranch.PROVIDER, value.provider.reasonValue)
            CryptoError.ErrorCase.BACKEND ->
                strictWireError(ReallyMeCryptoWireErrorBranch.BACKEND, value.backend.reasonValue)
            CryptoError.ErrorCase.ERROR_NOT_SET -> malformedCryptoErrorEnvelope()
        }

    public fun wireErrorFromProtoBytes(bytes: ByteArray): ReallyMeCryptoWireError =
        try {
            wireErrorFromProto(CryptoError.parseFrom(bytes))
        } catch (_: InvalidProtocolBufferException) {
            malformedCryptoErrorEnvelope()
        }

    public fun wireErrorToProto(value: ReallyMeCryptoWireError): CryptoError =
        when (value.branch) {
            ReallyMeCryptoWireErrorBranch.PRIMITIVE -> CryptoError.newBuilder()
                .setPrimitive(CryptoPrimitiveError.newBuilder().setReasonValue(value.reasonCode))
                .build()
            ReallyMeCryptoWireErrorBranch.PROVIDER -> CryptoError.newBuilder()
                .setProvider(CryptoProviderError.newBuilder().setReasonValue(value.reasonCode))
                .build()
            ReallyMeCryptoWireErrorBranch.BACKEND -> CryptoError.newBuilder()
                .setBackend(CryptoBackendError.newBuilder().setReasonValue(value.reasonCode))
                .build()
        }

    public fun wireErrorToProtoBytes(value: ReallyMeCryptoWireError): ByteArray =
        wireErrorToProto(value).toByteArray()

    public fun facadeErrorFromWireError(value: ReallyMeCryptoWireError): ReallyMeCryptoException =
        value.knownReason?.let(::fromProto) ?: ReallyMeCryptoException.ProviderFailure()

    public fun wireErrorFromNativeStatus(value: ReallyMeNativeStatus): ReallyMeCryptoWireError =
        when (value) {
            ReallyMeNativeStatus.OK -> ReallyMeCryptoWireError.unchecked(
                ReallyMeCryptoWireErrorBranch.BACKEND,
                CryptoErrorReason.CRYPTO_ERROR_REASON_BACKEND_INVALID_STATE,
            )
            ReallyMeNativeStatus.INVALID_INPUT -> ReallyMeCryptoWireError.unchecked(
                ReallyMeCryptoWireErrorBranch.PRIMITIVE,
                CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER,
            )
            ReallyMeNativeStatus.AUTHENTICATION_FAILED -> ReallyMeCryptoWireError.unchecked(
                ReallyMeCryptoWireErrorBranch.PRIMITIVE,
                CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED,
            )
            ReallyMeNativeStatus.UNSUPPORTED_ALGORITHM -> ReallyMeCryptoWireError.unchecked(
                ReallyMeCryptoWireErrorBranch.PROVIDER,
                CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM,
            )
            ReallyMeNativeStatus.PROVIDER_UNAVAILABLE -> ReallyMeCryptoWireError.unchecked(
                ReallyMeCryptoWireErrorBranch.PROVIDER,
                CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE,
            )
            ReallyMeNativeStatus.BACKEND_INTERNAL -> ReallyMeCryptoWireError.unchecked(
                ReallyMeCryptoWireErrorBranch.BACKEND,
                CryptoErrorReason.CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
            )
            ReallyMeNativeStatus.INVALID_SIGNATURE -> ReallyMeCryptoWireError.unchecked(
                ReallyMeCryptoWireErrorBranch.PRIMITIVE,
                CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SIGNATURE,
            )
        }

    public fun fromProto(value: CryptoError): ReallyMeCryptoException =
        facadeErrorFromWireError(wireErrorFromProto(value))

    public fun fromProtoErrorBytes(bytes: ByteArray): ReallyMeCryptoException =
        facadeErrorFromWireError(wireErrorFromProtoBytes(bytes))

    public fun toProto(value: ReallyMeCryptoException): CryptoError =
        when (value) {
            is ReallyMeCryptoException.InvalidInput -> CryptoError.newBuilder()
                .setPrimitive(
                    CryptoPrimitiveError.newBuilder()
                        .setReason(
                            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER,
                        ),
                )
                .build()
            is ReallyMeCryptoException.InvalidSignature -> CryptoError.newBuilder()
                .setPrimitive(
                    CryptoPrimitiveError.newBuilder()
                        .setReason(
                            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SIGNATURE,
                        ),
                )
                .build()
            is ReallyMeCryptoException.AuthenticationFailed -> CryptoError.newBuilder()
                .setPrimitive(
                    CryptoPrimitiveError.newBuilder()
                        .setReason(
                            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED,
                        ),
                )
                .build()
            is ReallyMeCryptoException.UnsupportedAlgorithm -> CryptoError.newBuilder()
                .setProvider(
                    CryptoProviderError.newBuilder()
                        .setReason(
                            CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM,
                        ),
                )
                .build()
            is ReallyMeCryptoException.UnsupportedPlatform -> CryptoError.newBuilder()
                .setProvider(
                    CryptoProviderError.newBuilder()
                        .setReason(
                            CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_BACKEND,
                        ),
                )
                .build()
            is ReallyMeCryptoException.PlatformKeyAlreadyExists -> CryptoError.newBuilder()
                .setProvider(
                    CryptoProviderError.newBuilder()
                        .setReason(CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_KEY_EXISTS),
                )
                .build()
            is ReallyMeCryptoException.PlatformKeyNotFound -> CryptoError.newBuilder()
                .setProvider(
                    CryptoProviderError.newBuilder()
                        .setReason(CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_KEY_NOT_FOUND),
                )
                .build()
            is ReallyMeCryptoException.PlatformAuthenticationRequired -> CryptoError.newBuilder()
                .setProvider(
                    CryptoProviderError.newBuilder()
                        .setReason(
                            CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_USER_AUTHENTICATION_REQUIRED,
                        ),
                )
                .build()
            is ReallyMeCryptoException.HardwareUnavailable -> CryptoError.newBuilder()
                .setProvider(
                    CryptoProviderError.newBuilder()
                        .setReason(
                            CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_UNAVAILABLE,
                        ),
                )
                .build()
            is ReallyMeCryptoException.HardwareRejectedKey -> CryptoError.newBuilder()
                .setProvider(
                    CryptoProviderError.newBuilder()
                        .setReason(
                            CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_REJECTED_KEY,
                        ),
                )
                .build()
            is ReallyMeCryptoException.ProviderFailure -> CryptoError.newBuilder()
                .setBackend(
                    CryptoBackendError.newBuilder()
                        .setReason(CryptoErrorReason.CRYPTO_ERROR_REASON_BACKEND_INTERNAL),
                )
                .build()
        }

    public fun toProtoBytes(value: ReallyMeCryptoException): ByteArray =
        toProto(value).toByteArray()

    private fun fromProto(value: CryptoErrorReason): ReallyMeCryptoException =
        when (value) {
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SIGNATURE,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_VERIFICATION_FAILED,
            -> ReallyMeCryptoException.InvalidSignature()
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED,
            -> ReallyMeCryptoException.AuthenticationFailed()
            CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM,
            -> ReallyMeCryptoException.UnsupportedAlgorithm()
            CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_BACKEND,
            -> ReallyMeCryptoException.UnsupportedPlatform()
            CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_KEY_EXISTS,
            -> ReallyMeCryptoException.PlatformKeyAlreadyExists()
            CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_KEY_NOT_FOUND,
            -> ReallyMeCryptoException.PlatformKeyNotFound()
            CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_USER_AUTHENTICATION_REQUIRED,
            -> ReallyMeCryptoException.PlatformAuthenticationRequired()
            CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_UNAVAILABLE,
            -> ReallyMeCryptoException.HardwareUnavailable()
            CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_REJECTED_KEY,
            -> ReallyMeCryptoException.HardwareRejectedKey()
            CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_ACCESS_DENIED,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_USER_CANCELED,
            CryptoErrorReason.CRYPTO_ERROR_REASON_BACKEND_INVALID_STATE,
            CryptoErrorReason.CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
            -> ReallyMeCryptoException.ProviderFailure()
            CryptoErrorReason.CRYPTO_ERROR_REASON_UNSPECIFIED,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PUBLIC_KEY,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PRIVATE_KEY,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_NONCE,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SALT,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PASSWORD,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_ENCODING,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_CIPHERTEXT,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_TAG,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SHARED_SECRET,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_JSON,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_MISSING_OPERATION,
            CryptoErrorReason.UNRECOGNIZED,
            -> ReallyMeCryptoException.InvalidInput()
        }

    private fun strictWireError(
        branch: ReallyMeCryptoWireErrorBranch,
        reasonCode: Int,
    ): ReallyMeCryptoWireError {
        return when (val result = ReallyMeCryptoWireError.tryFromReasonCode(branch, reasonCode)) {
            is ReallyMeCryptoWireErrorValidationResult.Success -> result.value
            is ReallyMeCryptoWireErrorValidationResult.Failure -> malformedCryptoErrorEnvelope()
        }
    }

    private fun malformedCryptoErrorEnvelope(): ReallyMeCryptoWireError =
        ReallyMeCryptoWireError.unchecked(
            ReallyMeCryptoWireErrorBranch.PRIMITIVE,
            CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF,
        )

    internal fun reasonMatchesBranch(
        branch: ReallyMeCryptoWireErrorBranch,
        reason: CryptoErrorReason,
    ): Boolean =
        when (branch) {
            ReallyMeCryptoWireErrorBranch.PRIMITIVE -> reason in primitiveCryptoErrorReasons
            ReallyMeCryptoWireErrorBranch.PROVIDER -> reason in providerCryptoErrorReasons
            ReallyMeCryptoWireErrorBranch.BACKEND -> reason in backendCryptoErrorReasons
        }

    internal fun reasonCodeMatchesBranch(
        branch: ReallyMeCryptoWireErrorBranch,
        reasonCode: Int,
    ): Boolean =
        when (branch) {
            ReallyMeCryptoWireErrorBranch.PRIMITIVE -> reasonCode in 100..199
            ReallyMeCryptoWireErrorBranch.PROVIDER -> reasonCode in 200..299
            ReallyMeCryptoWireErrorBranch.BACKEND -> reasonCode in 300..399
        }

    private val primitiveCryptoErrorReasons: Set<CryptoErrorReason> = setOf(
        CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER,
        CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH,
        CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
        CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PUBLIC_KEY,
        CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PRIVATE_KEY,
        CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_NONCE,
        CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SALT,
        CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PASSWORD,
        CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_ENCODING,
        CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SIGNATURE,
        CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_VERIFICATION_FAILED,
        CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED,
        CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_CIPHERTEXT,
        CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_TAG,
        CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SHARED_SECRET,
        CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF,
        CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_JSON,
        CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED,
        CryptoErrorReason.CRYPTO_ERROR_REASON_PRIMITIVE_MISSING_OPERATION,
    )

    private val providerCryptoErrorReasons: Set<CryptoErrorReason> = setOf(
        CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM,
        CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_BACKEND,
        CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE,
        CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE,
        CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_KEY_EXISTS,
        CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_KEY_NOT_FOUND,
        CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_ACCESS_DENIED,
        CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_USER_AUTHENTICATION_REQUIRED,
        CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_USER_CANCELED,
        CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_UNAVAILABLE,
        CryptoErrorReason.CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_REJECTED_KEY,
    )

    private val backendCryptoErrorReasons: Set<CryptoErrorReason> = setOf(
        CryptoErrorReason.CRYPTO_ERROR_REASON_BACKEND_INVALID_STATE,
        CryptoErrorReason.CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
    )

    public fun fromProto(value: JsonWebKey): ReallyMeJwkKey {
        if (!value.hasAlgorithm()) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        val algorithm = jwkAlgorithmFromProto(value.algorithm)
        val publicKey = value.publicKey.toByteArray()
        val jwk = ReallyMeJwk.toJwk(algorithm, publicKey)
        if (!value.canonicalJcs.isEmpty) {
            val canonicalJcs = value.canonicalJcs.toStringUtf8()
            if (canonicalJcs != ReallyMeJwk.toJcs(jwk)) {
                throw ReallyMeCryptoException.InvalidInput()
            }
        }
        return ReallyMeJwkKey(algorithm, publicKey, jwk)
    }

    public fun fromProtoJsonWebKeyBytes(bytes: ByteArray): ReallyMeJwkKey =
        try {
            fromProto(JsonWebKey.parseFrom(bytes))
        } catch (error: ReallyMeCryptoException) {
            throw error
        } catch (_: InvalidProtocolBufferException) {
            throw ReallyMeCryptoException.InvalidInput()
        }

    public fun toProto(value: ReallyMeJwkKey): JsonWebKey =
        JsonWebKey.newBuilder()
            .setAlgorithm(jwkAlgorithmToProto(value.algorithm))
            .setPublicKey(ByteString.copyFrom(value.publicKey))
            .setCanonicalJcs(ByteString.copyFromUtf8(ReallyMeJwk.toJcs(value.jwk)))
            .build()

    public fun toProtoBytes(value: ReallyMeJwkKey): ByteArray =
        toProto(value).toByteArray()

    public fun fromProto(value: JsonWebKeySet): List<ReallyMeJwkKey> =
        value.keysList.map { fromProto(it) }

    public fun fromProtoJsonWebKeySetBytes(bytes: ByteArray): List<ReallyMeJwkKey> =
        try {
            fromProto(JsonWebKeySet.parseFrom(bytes))
        } catch (error: ReallyMeCryptoException) {
            throw error
        } catch (_: InvalidProtocolBufferException) {
            throw ReallyMeCryptoException.InvalidInput()
        }

    public fun toProtoJsonWebKeySet(values: List<ReallyMeJwkKey>): JsonWebKeySet =
        JsonWebKeySet.newBuilder()
            .addAllKeys(values.map { toProto(it) })
            .build()

    public fun toProtoJsonWebKeySetBytes(values: List<ReallyMeJwkKey>): ByteArray =
        toProtoJsonWebKeySet(values).toByteArray()

    @JvmStatic
    public fun signatureKeyPairToProto(
        algorithm: ReallyMeSignatureAlgorithm,
        keyPair: ReallyMeSignatureKeyPair,
    ): CryptoKeyPair = keyPairToProto(signatureAlgorithmIdentifierToProto(algorithm), keyPair.publicKey, keyPair.secretKey)

    @JvmStatic
    public fun signatureKeyPairToProtoBytes(
        algorithm: ReallyMeSignatureAlgorithm,
        keyPair: ReallyMeSignatureKeyPair,
    ): ByteArray = signatureKeyPairToProto(algorithm, keyPair).toByteArray()

    @JvmStatic
    public fun signatureKeyPairFromProto(value: CryptoKeyPair): ReallyMeSignatureKeyPairProtoValue =
        ReallyMeSignatureKeyPairProtoValue(
            signatureAlgorithmFromIdentifier(value.algorithm, value.hasAlgorithm()),
            ReallyMeSignatureKeyPair(value.publicKey.toByteArray(), value.secretKey.toByteArray()),
        )

    @JvmStatic
    public fun signatureKeyPairFromProtoBytes(bytes: ByteArray): ReallyMeSignatureKeyPairProtoValue =
        try {
            signatureKeyPairFromProto(CryptoKeyPair.parseFrom(bytes))
        } catch (error: ReallyMeCryptoException) {
            throw error
        } catch (_: InvalidProtocolBufferException) {
            throw ReallyMeCryptoException.InvalidInput()
        }

    @JvmStatic
    public fun keyAgreementKeyPairToProto(
        algorithm: ReallyMeKeyAgreementAlgorithm,
        keyPair: ReallyMeKeyAgreementKeyPair,
    ): CryptoKeyPair = keyPairToProto(keyAgreementAlgorithmIdentifierToProto(algorithm), keyPair.publicKey, keyPair.secretKey)

    @JvmStatic
    public fun keyAgreementKeyPairToProtoBytes(
        algorithm: ReallyMeKeyAgreementAlgorithm,
        keyPair: ReallyMeKeyAgreementKeyPair,
    ): ByteArray = keyAgreementKeyPairToProto(algorithm, keyPair).toByteArray()

    @JvmStatic
    public fun keyAgreementKeyPairFromProto(value: CryptoKeyPair): ReallyMeKeyAgreementKeyPairProtoValue =
        ReallyMeKeyAgreementKeyPairProtoValue(
            keyAgreementAlgorithmFromIdentifier(value.algorithm, value.hasAlgorithm()),
            ReallyMeKeyAgreementKeyPair(value.publicKey.toByteArray(), value.secretKey.toByteArray()),
        )

    @JvmStatic
    public fun keyAgreementKeyPairFromProtoBytes(bytes: ByteArray): ReallyMeKeyAgreementKeyPairProtoValue =
        try {
            keyAgreementKeyPairFromProto(CryptoKeyPair.parseFrom(bytes))
        } catch (error: ReallyMeCryptoException) {
            throw error
        } catch (_: InvalidProtocolBufferException) {
            throw ReallyMeCryptoException.InvalidInput()
        }

    @JvmStatic
    public fun kemKeyPairToProto(
        algorithm: ReallyMeKemAlgorithm,
        keyPair: ReallyMeKemKeyPair,
    ): CryptoKeyPair = keyPairToProto(kemAlgorithmIdentifierToProto(algorithm), keyPair.publicKey, keyPair.secretKey)

    @JvmStatic
    public fun kemKeyPairToProtoBytes(
        algorithm: ReallyMeKemAlgorithm,
        keyPair: ReallyMeKemKeyPair,
    ): ByteArray = kemKeyPairToProto(algorithm, keyPair).toByteArray()

    @JvmStatic
    public fun kemKeyPairFromProto(value: CryptoKeyPair): ReallyMeKemKeyPairProtoValue =
        ReallyMeKemKeyPairProtoValue(
            kemAlgorithmFromIdentifier(value.algorithm, value.hasAlgorithm()),
            ReallyMeKemKeyPair(value.publicKey.toByteArray(), value.secretKey.toByteArray()),
        )

    @JvmStatic
    public fun kemKeyPairFromProtoBytes(bytes: ByteArray): ReallyMeKemKeyPairProtoValue =
        try {
            kemKeyPairFromProto(CryptoKeyPair.parseFrom(bytes))
        } catch (error: ReallyMeCryptoException) {
            throw error
        } catch (_: InvalidProtocolBufferException) {
            throw ReallyMeCryptoException.InvalidInput()
        }

    @JvmStatic
    public fun kemEncapsulationToProto(
        algorithm: ReallyMeKemAlgorithm,
        encapsulation: ReallyMeKemEncapsulation,
    ): CryptoKemEncapsulation =
        CryptoKemEncapsulation.newBuilder()
            .setAlgorithm(kemAlgorithmIdentifierToProto(algorithm))
            .setCiphertext(ByteString.copyFrom(encapsulation.ciphertext))
            .setSharedSecret(ByteString.copyFrom(encapsulation.sharedSecret))
            .build()

    @JvmStatic
    public fun kemEncapsulationToProtoBytes(
        algorithm: ReallyMeKemAlgorithm,
        encapsulation: ReallyMeKemEncapsulation,
    ): ByteArray = kemEncapsulationToProto(algorithm, encapsulation).toByteArray()

    @JvmStatic
    public fun kemEncapsulationFromProto(value: CryptoKemEncapsulation): ReallyMeKemEncapsulationProtoValue =
        ReallyMeKemEncapsulationProtoValue(
            kemAlgorithmFromIdentifier(value.algorithm, value.hasAlgorithm()),
            ReallyMeKemEncapsulation(value.sharedSecret.toByteArray(), value.ciphertext.toByteArray()),
        )

    @JvmStatic
    public fun kemEncapsulationFromProtoBytes(bytes: ByteArray): ReallyMeKemEncapsulationProtoValue =
        try {
            kemEncapsulationFromProto(CryptoKemEncapsulation.parseFrom(bytes))
        } catch (error: ReallyMeCryptoException) {
            throw error
        } catch (_: InvalidProtocolBufferException) {
            throw ReallyMeCryptoException.InvalidInput()
        }

    @JvmStatic
    public fun hpkeSealedMessageToProto(
        suite: ReallyMeHpkeSuite,
        sealedMessage: ReallyMeHpkeSealedMessage,
    ): CryptoHpkeSealedMessage =
        CryptoHpkeSealedMessage.newBuilder()
            .setAlgorithm(hpkeSuiteIdentifierToProto(suite))
            .setEncapsulatedKey(ByteString.copyFrom(sealedMessage.encapsulatedKey))
            .setCiphertext(ByteString.copyFrom(sealedMessage.ciphertext))
            .build()

    @JvmStatic
    public fun hpkeSealedMessageToProtoBytes(
        suite: ReallyMeHpkeSuite,
        sealedMessage: ReallyMeHpkeSealedMessage,
    ): ByteArray = hpkeSealedMessageToProto(suite, sealedMessage).toByteArray()

    @JvmStatic
    public fun hpkeSealedMessageFromProto(value: CryptoHpkeSealedMessage): ReallyMeHpkeSealedMessageProtoValue =
        ReallyMeHpkeSealedMessageProtoValue(
            ReallyMeHpkeSealedMessage(value.encapsulatedKey.toByteArray(), value.ciphertext.toByteArray()),
            hpkeSuiteFromIdentifier(value.algorithm, value.hasAlgorithm()),
        )

    @JvmStatic
    public fun hpkeSealedMessageFromProtoBytes(bytes: ByteArray): ReallyMeHpkeSealedMessageProtoValue =
        try {
            hpkeSealedMessageFromProto(CryptoHpkeSealedMessage.parseFrom(bytes))
        } catch (error: ReallyMeCryptoException) {
            throw error
        } catch (_: InvalidProtocolBufferException) {
            throw ReallyMeCryptoException.InvalidInput()
        }

    @JvmStatic
    public fun verificationResultToProto(
        algorithm: CryptoAlgorithmIdentifier,
        valid: Boolean,
    ): CryptoVerificationResult =
        CryptoVerificationResult.newBuilder()
            .setAlgorithm(algorithm)
            .setStatus(
                if (valid) {
                    CryptoVerificationStatus.CRYPTO_VERIFICATION_STATUS_VALID
                } else {
                    CryptoVerificationStatus.CRYPTO_VERIFICATION_STATUS_INVALID
                },
            )
            .build()

    @JvmStatic
    public fun verificationErrorToProto(
        algorithm: CryptoAlgorithmIdentifier,
        error: ReallyMeCryptoException,
    ): CryptoVerificationResult =
        CryptoVerificationResult.newBuilder()
            .setAlgorithm(algorithm)
            .setStatus(CryptoVerificationStatus.CRYPTO_VERIFICATION_STATUS_ERROR)
            .setError(toProto(error))
            .build()

    @JvmStatic
    public fun verificationResultToProtoBytes(value: CryptoVerificationResult): ByteArray =
        value.toByteArray()

    @JvmStatic
    public fun verificationResultFromProtoBytes(bytes: ByteArray): CryptoVerificationResult =
        try {
            CryptoVerificationResult.parseFrom(bytes)
        } catch (_: InvalidProtocolBufferException) {
            throw ReallyMeCryptoException.InvalidInput()
        }

    @JvmStatic
    public fun providerCapabilityToProto(
        value: ReallyMeProviderCapabilityProtoValue,
    ): CryptoProviderCapability {
        if (
            value.algorithm.algorithmCase == CryptoAlgorithmIdentifier.AlgorithmCase.ALGORITHM_NOT_SET ||
            value.family == CryptoAlgorithmFamily.CRYPTO_ALGORITHM_FAMILY_UNSPECIFIED ||
            value.status == CryptoProviderSupportStatus.CRYPTO_PROVIDER_SUPPORT_STATUS_UNSPECIFIED ||
            value.status == CryptoProviderSupportStatus.UNRECOGNIZED
        ) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        return CryptoProviderCapability.newBuilder()
            .setAlgorithm(value.algorithm)
            .setFamily(value.family)
            .addAllProviderNames(value.providerNames)
            .setStatus(value.status)
            .setUsesRust(value.usesRust)
            .build()
    }

    @JvmStatic
    public fun providerCapabilityFromProto(value: CryptoProviderCapability): ReallyMeProviderCapabilityProtoValue {
        if (
            !value.hasAlgorithm() ||
            value.family == CryptoAlgorithmFamily.CRYPTO_ALGORITHM_FAMILY_UNSPECIFIED ||
            value.family == CryptoAlgorithmFamily.UNRECOGNIZED ||
            value.status == CryptoProviderSupportStatus.CRYPTO_PROVIDER_SUPPORT_STATUS_UNSPECIFIED ||
            value.status == CryptoProviderSupportStatus.UNRECOGNIZED
        ) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        return ReallyMeProviderCapabilityProtoValue(
            value.algorithm,
            value.family,
            value.providerNamesList,
            value.status,
            value.usesRust,
        )
    }

    @JvmStatic
    public fun providerCapabilitySetToProto(
        values: List<ReallyMeProviderCapabilityProtoValue>,
    ): CryptoProviderCapabilitySet =
        CryptoProviderCapabilitySet.newBuilder()
            .addAllCapabilities(values.map { providerCapabilityToProto(it) })
            .build()

    @JvmStatic
    public fun providerCapabilitySetToProtoBytes(
        values: List<ReallyMeProviderCapabilityProtoValue>,
    ): ByteArray = providerCapabilitySetToProto(values).toByteArray()

    @JvmStatic
    public fun providerCapabilitySetFromProto(
        value: CryptoProviderCapabilitySet,
    ): List<ReallyMeProviderCapabilityProtoValue> =
        value.capabilitiesList.map { providerCapabilityFromProto(it) }

    @JvmStatic
    public fun providerCapabilitySetFromProtoBytes(bytes: ByteArray): List<ReallyMeProviderCapabilityProtoValue> =
        try {
            providerCapabilitySetFromProto(CryptoProviderCapabilitySet.parseFrom(bytes))
        } catch (error: ReallyMeCryptoException) {
            throw error
        } catch (_: InvalidProtocolBufferException) {
            throw ReallyMeCryptoException.InvalidInput()
        }

    public fun fromProto(value: SignatureAlgorithm): ReallyMeSignatureAlgorithm =
        when (value) {
            SignatureAlgorithm.SIGNATURE_ALGORITHM_ED25519 -> ReallyMeSignatureAlgorithm.ED25519
            SignatureAlgorithm.SIGNATURE_ALGORITHM_ECDSA_P256_SHA256 ->
                ReallyMeSignatureAlgorithm.ECDSA_P256_SHA256
            SignatureAlgorithm.SIGNATURE_ALGORITHM_ECDSA_P384_SHA384 ->
                ReallyMeSignatureAlgorithm.ECDSA_P384_SHA384
            SignatureAlgorithm.SIGNATURE_ALGORITHM_ECDSA_P521_SHA512 ->
                ReallyMeSignatureAlgorithm.ECDSA_P521_SHA512
            SignatureAlgorithm.SIGNATURE_ALGORITHM_ECDSA_SECP256K1_SHA256 ->
                ReallyMeSignatureAlgorithm.ECDSA_SECP256K1_SHA256
            SignatureAlgorithm.SIGNATURE_ALGORITHM_BIP340_SCHNORR_SECP256K1_SHA256 ->
                ReallyMeSignatureAlgorithm.BIP340_SCHNORR_SECP256K1_SHA256
            SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA1 ->
                ReallyMeSignatureAlgorithm.RSA_PKCS1V15_SHA1
            SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA256 ->
                ReallyMeSignatureAlgorithm.RSA_PKCS1V15_SHA256
            SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA384 ->
                ReallyMeSignatureAlgorithm.RSA_PKCS1V15_SHA384
            SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA512 ->
                ReallyMeSignatureAlgorithm.RSA_PKCS1V15_SHA512
            SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PSS_SHA1_MGF1_SHA1 ->
                ReallyMeSignatureAlgorithm.RSA_PSS_SHA1_MGF1_SHA1
            SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PSS_SHA256_MGF1_SHA256 ->
                ReallyMeSignatureAlgorithm.RSA_PSS_SHA256_MGF1_SHA256
            SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PSS_SHA384_MGF1_SHA384 ->
                ReallyMeSignatureAlgorithm.RSA_PSS_SHA384_MGF1_SHA384
            SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PSS_SHA512_MGF1_SHA512 ->
                ReallyMeSignatureAlgorithm.RSA_PSS_SHA512_MGF1_SHA512
            SignatureAlgorithm.SIGNATURE_ALGORITHM_ML_DSA_44 -> ReallyMeSignatureAlgorithm.ML_DSA_44
            SignatureAlgorithm.SIGNATURE_ALGORITHM_ML_DSA_65 -> ReallyMeSignatureAlgorithm.ML_DSA_65
            SignatureAlgorithm.SIGNATURE_ALGORITHM_ML_DSA_87 -> ReallyMeSignatureAlgorithm.ML_DSA_87
            SignatureAlgorithm.SIGNATURE_ALGORITHM_SLH_DSA_SHA2_128S ->
                ReallyMeSignatureAlgorithm.SLH_DSA_SHA2_128S
            else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    public fun toProto(value: ReallyMeSignatureAlgorithm): SignatureAlgorithm =
        when (value) {
            ReallyMeSignatureAlgorithm.ED25519 -> SignatureAlgorithm.SIGNATURE_ALGORITHM_ED25519
            ReallyMeSignatureAlgorithm.ECDSA_P256_SHA256 ->
                SignatureAlgorithm.SIGNATURE_ALGORITHM_ECDSA_P256_SHA256
            ReallyMeSignatureAlgorithm.ECDSA_P384_SHA384 ->
                SignatureAlgorithm.SIGNATURE_ALGORITHM_ECDSA_P384_SHA384
            ReallyMeSignatureAlgorithm.ECDSA_P521_SHA512 ->
                SignatureAlgorithm.SIGNATURE_ALGORITHM_ECDSA_P521_SHA512
            ReallyMeSignatureAlgorithm.ECDSA_SECP256K1_SHA256 ->
                SignatureAlgorithm.SIGNATURE_ALGORITHM_ECDSA_SECP256K1_SHA256
            ReallyMeSignatureAlgorithm.BIP340_SCHNORR_SECP256K1_SHA256 ->
                SignatureAlgorithm.SIGNATURE_ALGORITHM_BIP340_SCHNORR_SECP256K1_SHA256
            ReallyMeSignatureAlgorithm.RSA_PKCS1V15_SHA1 ->
                SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA1
            ReallyMeSignatureAlgorithm.RSA_PKCS1V15_SHA256 ->
                SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA256
            ReallyMeSignatureAlgorithm.RSA_PKCS1V15_SHA384 ->
                SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA384
            ReallyMeSignatureAlgorithm.RSA_PKCS1V15_SHA512 ->
                SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA512
            ReallyMeSignatureAlgorithm.RSA_PSS_SHA1_MGF1_SHA1 ->
                SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PSS_SHA1_MGF1_SHA1
            ReallyMeSignatureAlgorithm.RSA_PSS_SHA256_MGF1_SHA256 ->
                SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PSS_SHA256_MGF1_SHA256
            ReallyMeSignatureAlgorithm.RSA_PSS_SHA384_MGF1_SHA384 ->
                SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PSS_SHA384_MGF1_SHA384
            ReallyMeSignatureAlgorithm.RSA_PSS_SHA512_MGF1_SHA512 ->
                SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PSS_SHA512_MGF1_SHA512
            ReallyMeSignatureAlgorithm.ML_DSA_44 -> SignatureAlgorithm.SIGNATURE_ALGORITHM_ML_DSA_44
            ReallyMeSignatureAlgorithm.ML_DSA_65 -> SignatureAlgorithm.SIGNATURE_ALGORITHM_ML_DSA_65
            ReallyMeSignatureAlgorithm.ML_DSA_87 -> SignatureAlgorithm.SIGNATURE_ALGORITHM_ML_DSA_87
            ReallyMeSignatureAlgorithm.SLH_DSA_SHA2_128S ->
                SignatureAlgorithm.SIGNATURE_ALGORITHM_SLH_DSA_SHA2_128S
        }

    public fun fromProto(value: HashAlgorithm): ReallyMeHashAlgorithm =
        when (value) {
            HashAlgorithm.HASH_ALGORITHM_SHA2_256 -> ReallyMeHashAlgorithm.SHA2_256
            HashAlgorithm.HASH_ALGORITHM_SHA2_384 -> ReallyMeHashAlgorithm.SHA2_384
            HashAlgorithm.HASH_ALGORITHM_SHA2_512 -> ReallyMeHashAlgorithm.SHA2_512
            HashAlgorithm.HASH_ALGORITHM_SHA3_224 -> ReallyMeHashAlgorithm.SHA3_224
            HashAlgorithm.HASH_ALGORITHM_SHA3_256 -> ReallyMeHashAlgorithm.SHA3_256
            HashAlgorithm.HASH_ALGORITHM_SHA3_384 -> ReallyMeHashAlgorithm.SHA3_384
            HashAlgorithm.HASH_ALGORITHM_SHA3_512 -> ReallyMeHashAlgorithm.SHA3_512
            else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    public fun toProto(value: ReallyMeHashAlgorithm): HashAlgorithm =
        when (value) {
            ReallyMeHashAlgorithm.SHA2_256 -> HashAlgorithm.HASH_ALGORITHM_SHA2_256
            ReallyMeHashAlgorithm.SHA2_384 -> HashAlgorithm.HASH_ALGORITHM_SHA2_384
            ReallyMeHashAlgorithm.SHA2_512 -> HashAlgorithm.HASH_ALGORITHM_SHA2_512
            ReallyMeHashAlgorithm.SHA3_224 -> HashAlgorithm.HASH_ALGORITHM_SHA3_224
            ReallyMeHashAlgorithm.SHA3_256 -> HashAlgorithm.HASH_ALGORITHM_SHA3_256
            ReallyMeHashAlgorithm.SHA3_384 -> HashAlgorithm.HASH_ALGORITHM_SHA3_384
            ReallyMeHashAlgorithm.SHA3_512 -> HashAlgorithm.HASH_ALGORITHM_SHA3_512
        }

    public fun fromProto(value: AeadAlgorithm): ReallyMeAeadAlgorithm =
        when (value) {
            AeadAlgorithm.AEAD_ALGORITHM_AES_128_GCM -> ReallyMeAeadAlgorithm.AES_128_GCM
            AeadAlgorithm.AEAD_ALGORITHM_AES_192_GCM -> ReallyMeAeadAlgorithm.AES_192_GCM
            AeadAlgorithm.AEAD_ALGORITHM_AES_256_GCM -> ReallyMeAeadAlgorithm.AES_256_GCM
            AeadAlgorithm.AEAD_ALGORITHM_AES_256_GCM_SIV -> ReallyMeAeadAlgorithm.AES_256_GCM_SIV
            AeadAlgorithm.AEAD_ALGORITHM_CHACHA20_POLY1305 ->
                ReallyMeAeadAlgorithm.CHACHA20_POLY1305
            AeadAlgorithm.AEAD_ALGORITHM_XCHACHA20_POLY1305 ->
                ReallyMeAeadAlgorithm.XCHACHA20_POLY1305
            else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    public fun toProto(value: ReallyMeAeadAlgorithm): AeadAlgorithm =
        when (value) {
            ReallyMeAeadAlgorithm.AES_128_GCM -> AeadAlgorithm.AEAD_ALGORITHM_AES_128_GCM
            ReallyMeAeadAlgorithm.AES_192_GCM -> AeadAlgorithm.AEAD_ALGORITHM_AES_192_GCM
            ReallyMeAeadAlgorithm.AES_256_GCM -> AeadAlgorithm.AEAD_ALGORITHM_AES_256_GCM
            ReallyMeAeadAlgorithm.AES_256_GCM_SIV -> AeadAlgorithm.AEAD_ALGORITHM_AES_256_GCM_SIV
            ReallyMeAeadAlgorithm.CHACHA20_POLY1305 -> AeadAlgorithm.AEAD_ALGORITHM_CHACHA20_POLY1305
            ReallyMeAeadAlgorithm.XCHACHA20_POLY1305 ->
                AeadAlgorithm.AEAD_ALGORITHM_XCHACHA20_POLY1305
        }

    public fun fromProto(value: KemAlgorithm): ReallyMeKemAlgorithm =
        when (value) {
            KemAlgorithm.KEM_ALGORITHM_ML_KEM_512 -> ReallyMeKemAlgorithm.ML_KEM_512
            KemAlgorithm.KEM_ALGORITHM_ML_KEM_768 -> ReallyMeKemAlgorithm.ML_KEM_768
            KemAlgorithm.KEM_ALGORITHM_ML_KEM_1024 -> ReallyMeKemAlgorithm.ML_KEM_1024
            KemAlgorithm.KEM_ALGORITHM_X_WING_768 -> ReallyMeKemAlgorithm.X_WING_768
            else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    public fun toProto(value: ReallyMeKemAlgorithm): KemAlgorithm =
        when (value) {
            ReallyMeKemAlgorithm.ML_KEM_512 -> KemAlgorithm.KEM_ALGORITHM_ML_KEM_512
            ReallyMeKemAlgorithm.ML_KEM_768 -> KemAlgorithm.KEM_ALGORITHM_ML_KEM_768
            ReallyMeKemAlgorithm.ML_KEM_1024 -> KemAlgorithm.KEM_ALGORITHM_ML_KEM_1024
            ReallyMeKemAlgorithm.X_WING_768 -> KemAlgorithm.KEM_ALGORITHM_X_WING_768
        }

    public fun fromProto(value: KeyAgreementAlgorithm): ReallyMeKeyAgreementAlgorithm =
        when (value) {
            KeyAgreementAlgorithm.KEY_AGREEMENT_ALGORITHM_X25519 -> ReallyMeKeyAgreementAlgorithm.X25519
            KeyAgreementAlgorithm.KEY_AGREEMENT_ALGORITHM_P256_ECDH ->
                ReallyMeKeyAgreementAlgorithm.P256_ECDH
            KeyAgreementAlgorithm.KEY_AGREEMENT_ALGORITHM_P384_ECDH ->
                ReallyMeKeyAgreementAlgorithm.P384_ECDH
            KeyAgreementAlgorithm.KEY_AGREEMENT_ALGORITHM_P521_ECDH ->
                ReallyMeKeyAgreementAlgorithm.P521_ECDH
            else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    public fun toProto(value: ReallyMeKeyAgreementAlgorithm): KeyAgreementAlgorithm =
        when (value) {
            ReallyMeKeyAgreementAlgorithm.X25519 -> KeyAgreementAlgorithm.KEY_AGREEMENT_ALGORITHM_X25519
            ReallyMeKeyAgreementAlgorithm.P256_ECDH ->
                KeyAgreementAlgorithm.KEY_AGREEMENT_ALGORITHM_P256_ECDH
            ReallyMeKeyAgreementAlgorithm.P384_ECDH ->
                KeyAgreementAlgorithm.KEY_AGREEMENT_ALGORITHM_P384_ECDH
            ReallyMeKeyAgreementAlgorithm.P521_ECDH ->
                KeyAgreementAlgorithm.KEY_AGREEMENT_ALGORITHM_P521_ECDH
        }

    public fun fromProto(value: MacAlgorithm): ReallyMeMacAlgorithm =
        when (value) {
            MacAlgorithm.MAC_ALGORITHM_HMAC_SHA256 -> ReallyMeMacAlgorithm.HMAC_SHA256
            MacAlgorithm.MAC_ALGORITHM_HMAC_SHA384 -> ReallyMeMacAlgorithm.HMAC_SHA384
            MacAlgorithm.MAC_ALGORITHM_HMAC_SHA512 -> ReallyMeMacAlgorithm.HMAC_SHA512
            else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    public fun toProto(value: ReallyMeMacAlgorithm): MacAlgorithm =
        when (value) {
            ReallyMeMacAlgorithm.HMAC_SHA256 -> MacAlgorithm.MAC_ALGORITHM_HMAC_SHA256
            ReallyMeMacAlgorithm.HMAC_SHA384 -> MacAlgorithm.MAC_ALGORITHM_HMAC_SHA384
            ReallyMeMacAlgorithm.HMAC_SHA512 -> MacAlgorithm.MAC_ALGORITHM_HMAC_SHA512
        }

    public fun fromProto(value: KdfAlgorithm): ReallyMeKdfAlgorithm =
        when (value) {
            KdfAlgorithm.KDF_ALGORITHM_HKDF_SHA256 -> ReallyMeKdfAlgorithm.HKDF_SHA256
            KdfAlgorithm.KDF_ALGORITHM_HKDF_SHA384 -> ReallyMeKdfAlgorithm.HKDF_SHA384
            KdfAlgorithm.KDF_ALGORITHM_ARGON2ID -> ReallyMeKdfAlgorithm.ARGON2ID
            KdfAlgorithm.KDF_ALGORITHM_KMAC_256 -> ReallyMeKdfAlgorithm.KMAC256
            KdfAlgorithm.KDF_ALGORITHM_PBKDF2_HMAC_SHA256 -> ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA256
            KdfAlgorithm.KDF_ALGORITHM_PBKDF2_HMAC_SHA512 -> ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA512
            KdfAlgorithm.KDF_ALGORITHM_JWA_CONCAT_KDF_SHA256 ->
                ReallyMeKdfAlgorithm.JWA_CONCAT_KDF_SHA256
            else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    public fun toProto(value: ReallyMeKdfAlgorithm): KdfAlgorithm =
        when (value) {
            ReallyMeKdfAlgorithm.HKDF_SHA256 -> KdfAlgorithm.KDF_ALGORITHM_HKDF_SHA256
            ReallyMeKdfAlgorithm.HKDF_SHA384 -> KdfAlgorithm.KDF_ALGORITHM_HKDF_SHA384
            ReallyMeKdfAlgorithm.ARGON2ID -> KdfAlgorithm.KDF_ALGORITHM_ARGON2ID
            ReallyMeKdfAlgorithm.KMAC256 -> KdfAlgorithm.KDF_ALGORITHM_KMAC_256
            ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA256 -> KdfAlgorithm.KDF_ALGORITHM_PBKDF2_HMAC_SHA256
            ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA512 -> KdfAlgorithm.KDF_ALGORITHM_PBKDF2_HMAC_SHA512
            ReallyMeKdfAlgorithm.JWA_CONCAT_KDF_SHA256 ->
                KdfAlgorithm.KDF_ALGORITHM_JWA_CONCAT_KDF_SHA256
        }

    public fun fromProto(value: KeyWrapAlgorithm): ReallyMeKeyWrapAlgorithm =
        when (value) {
            KeyWrapAlgorithm.KEY_WRAP_ALGORITHM_AES_128_KW -> ReallyMeKeyWrapAlgorithm.AES_128_KW
            KeyWrapAlgorithm.KEY_WRAP_ALGORITHM_AES_192_KW -> ReallyMeKeyWrapAlgorithm.AES_192_KW
            KeyWrapAlgorithm.KEY_WRAP_ALGORITHM_AES_256_KW -> ReallyMeKeyWrapAlgorithm.AES_256_KW
            else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    public fun toProto(value: ReallyMeKeyWrapAlgorithm): KeyWrapAlgorithm =
        when (value) {
            ReallyMeKeyWrapAlgorithm.AES_128_KW -> KeyWrapAlgorithm.KEY_WRAP_ALGORITHM_AES_128_KW
            ReallyMeKeyWrapAlgorithm.AES_192_KW -> KeyWrapAlgorithm.KEY_WRAP_ALGORITHM_AES_192_KW
            ReallyMeKeyWrapAlgorithm.AES_256_KW -> KeyWrapAlgorithm.KEY_WRAP_ALGORITHM_AES_256_KW
        }

    public fun fromProto(value: HpkeSuiteIdentifier): ReallyMeHpkeSuite =
        when {
            value.kem == HpkeKemId.HPKE_KEM_ID_DHKEM_P256_HKDF_SHA256 &&
                value.kdf == HpkeKdfId.HPKE_KDF_ID_HKDF_SHA256 &&
                value.aead == HpkeAeadId.HPKE_AEAD_ID_AES_256_GCM ->
                ReallyMeHpkeSuite.DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_256_GCM
            value.kem == HpkeKemId.HPKE_KEM_ID_DHKEM_X25519_HKDF_SHA256 &&
                value.kdf == HpkeKdfId.HPKE_KDF_ID_HKDF_SHA256 &&
                value.aead == HpkeAeadId.HPKE_AEAD_ID_CHACHA20_POLY1305 ->
                ReallyMeHpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305
            else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    public fun toProto(value: ReallyMeHpkeSuite): HpkeSuiteIdentifier {
        val builder = HpkeSuiteIdentifier.newBuilder()
            .setKdf(HpkeKdfId.HPKE_KDF_ID_HKDF_SHA256)
        return when (value) {
            ReallyMeHpkeSuite.DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_256_GCM ->
                builder
                    .setKem(HpkeKemId.HPKE_KEM_ID_DHKEM_P256_HKDF_SHA256)
                    .setAead(HpkeAeadId.HPKE_AEAD_ID_AES_256_GCM)
                    .build()
            ReallyMeHpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305 ->
                builder
                    .setKem(HpkeKemId.HPKE_KEM_ID_DHKEM_X25519_HKDF_SHA256)
                    .setAead(HpkeAeadId.HPKE_AEAD_ID_CHACHA20_POLY1305)
                    .build()
        }
    }

    public fun fromProto(value: MulticodecKeyAlgorithm): ReallyMeMulticodecKeyAlgorithm =
        when (value) {
            MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ED25519_PUB ->
                ReallyMeMulticodecKeyAlgorithm.ED25519_PUBLIC_KEY
            MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_X25519_PUB ->
                ReallyMeMulticodecKeyAlgorithm.X25519_PUBLIC_KEY
            MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_SECP256K1_PUB ->
                ReallyMeMulticodecKeyAlgorithm.SECP256K1_PUBLIC_KEY
            MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_P256_PUB ->
                ReallyMeMulticodecKeyAlgorithm.P256_PUBLIC_KEY
            MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_P384_PUB ->
                ReallyMeMulticodecKeyAlgorithm.P384_PUBLIC_KEY
            MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_P521_PUB ->
                ReallyMeMulticodecKeyAlgorithm.P521_PUBLIC_KEY
            MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ED448_PUB ->
                ReallyMeMulticodecKeyAlgorithm.ED448_PUBLIC_KEY
            MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_RSA_PUB ->
                ReallyMeMulticodecKeyAlgorithm.RSA_PUBLIC_KEY
            MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ML_KEM_512_PUB ->
                ReallyMeMulticodecKeyAlgorithm.ML_KEM_512_PUBLIC_KEY
            MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ML_KEM_768_PUB ->
                ReallyMeMulticodecKeyAlgorithm.ML_KEM_768_PUBLIC_KEY
            MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ML_KEM_1024_PUB ->
                ReallyMeMulticodecKeyAlgorithm.ML_KEM_1024_PUBLIC_KEY
            MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ML_DSA_44_PUB ->
                ReallyMeMulticodecKeyAlgorithm.ML_DSA_44_PUBLIC_KEY
            MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ML_DSA_65_PUB ->
                ReallyMeMulticodecKeyAlgorithm.ML_DSA_65_PUBLIC_KEY
            MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ML_DSA_87_PUB ->
                ReallyMeMulticodecKeyAlgorithm.ML_DSA_87_PUBLIC_KEY
            else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    public fun toProto(value: ReallyMeMulticodecKeyAlgorithm): MulticodecKeyAlgorithm =
        when (value) {
            ReallyMeMulticodecKeyAlgorithm.ED25519_PUBLIC_KEY ->
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ED25519_PUB
            ReallyMeMulticodecKeyAlgorithm.X25519_PUBLIC_KEY ->
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_X25519_PUB
            ReallyMeMulticodecKeyAlgorithm.SECP256K1_PUBLIC_KEY ->
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_SECP256K1_PUB
            ReallyMeMulticodecKeyAlgorithm.P256_PUBLIC_KEY ->
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_P256_PUB
            ReallyMeMulticodecKeyAlgorithm.P384_PUBLIC_KEY ->
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_P384_PUB
            ReallyMeMulticodecKeyAlgorithm.P521_PUBLIC_KEY ->
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_P521_PUB
            ReallyMeMulticodecKeyAlgorithm.ED448_PUBLIC_KEY ->
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ED448_PUB
            ReallyMeMulticodecKeyAlgorithm.RSA_PUBLIC_KEY ->
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_RSA_PUB
            ReallyMeMulticodecKeyAlgorithm.ML_KEM_512_PUBLIC_KEY ->
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ML_KEM_512_PUB
            ReallyMeMulticodecKeyAlgorithm.ML_KEM_768_PUBLIC_KEY ->
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ML_KEM_768_PUB
            ReallyMeMulticodecKeyAlgorithm.ML_KEM_1024_PUBLIC_KEY ->
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ML_KEM_1024_PUB
            ReallyMeMulticodecKeyAlgorithm.ML_DSA_44_PUBLIC_KEY ->
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ML_DSA_44_PUB
            ReallyMeMulticodecKeyAlgorithm.ML_DSA_65_PUBLIC_KEY ->
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ML_DSA_65_PUB
            ReallyMeMulticodecKeyAlgorithm.ML_DSA_87_PUBLIC_KEY ->
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ML_DSA_87_PUB
        }

    private fun jwkAlgorithmToProto(
        value: ReallyMeJwkAlgorithm,
    ): CryptoAlgorithmIdentifier =
        when (value) {
            ReallyMeJwkAlgorithm.ED25519 -> CryptoAlgorithmIdentifier.newBuilder()
                .setSignature(SignatureAlgorithm.SIGNATURE_ALGORITHM_ED25519)
                .build()
            ReallyMeJwkAlgorithm.X25519 -> CryptoAlgorithmIdentifier.newBuilder()
                .setKeyAgreement(KeyAgreementAlgorithm.KEY_AGREEMENT_ALGORITHM_X25519)
                .build()
            ReallyMeJwkAlgorithm.P256 -> CryptoAlgorithmIdentifier.newBuilder()
                .setSignature(SignatureAlgorithm.SIGNATURE_ALGORITHM_ECDSA_P256_SHA256)
                .build()
            ReallyMeJwkAlgorithm.SECP256K1 -> CryptoAlgorithmIdentifier.newBuilder()
                .setSignature(SignatureAlgorithm.SIGNATURE_ALGORITHM_ECDSA_SECP256K1_SHA256)
                .build()
            ReallyMeJwkAlgorithm.ML_DSA_44 -> CryptoAlgorithmIdentifier.newBuilder()
                .setSignature(SignatureAlgorithm.SIGNATURE_ALGORITHM_ML_DSA_44)
                .build()
            ReallyMeJwkAlgorithm.ML_DSA_65 -> CryptoAlgorithmIdentifier.newBuilder()
                .setSignature(SignatureAlgorithm.SIGNATURE_ALGORITHM_ML_DSA_65)
                .build()
            ReallyMeJwkAlgorithm.ML_DSA_87 -> CryptoAlgorithmIdentifier.newBuilder()
                .setSignature(SignatureAlgorithm.SIGNATURE_ALGORITHM_ML_DSA_87)
                .build()
            ReallyMeJwkAlgorithm.ML_KEM_512 -> CryptoAlgorithmIdentifier.newBuilder()
                .setKem(KemAlgorithm.KEM_ALGORITHM_ML_KEM_512)
                .build()
            ReallyMeJwkAlgorithm.ML_KEM_768 -> CryptoAlgorithmIdentifier.newBuilder()
                .setKem(KemAlgorithm.KEM_ALGORITHM_ML_KEM_768)
                .build()
            ReallyMeJwkAlgorithm.ML_KEM_1024 -> CryptoAlgorithmIdentifier.newBuilder()
                .setKem(KemAlgorithm.KEM_ALGORITHM_ML_KEM_1024)
                .build()
            ReallyMeJwkAlgorithm.SLH_DSA_SHA2_128S -> CryptoAlgorithmIdentifier.newBuilder()
                .setSignature(SignatureAlgorithm.SIGNATURE_ALGORITHM_SLH_DSA_SHA2_128S)
                .build()
            ReallyMeJwkAlgorithm.X_WING_768 -> CryptoAlgorithmIdentifier.newBuilder()
                .setKem(KemAlgorithm.KEM_ALGORITHM_X_WING_768)
                .build()
        }

    private fun jwkAlgorithmFromProto(
        value: CryptoAlgorithmIdentifier,
    ): ReallyMeJwkAlgorithm =
        when (value.algorithmCase) {
            CryptoAlgorithmIdentifier.AlgorithmCase.SIGNATURE -> when (value.signature) {
                SignatureAlgorithm.SIGNATURE_ALGORITHM_ED25519 ->
                    ReallyMeJwkAlgorithm.ED25519
                SignatureAlgorithm.SIGNATURE_ALGORITHM_ECDSA_P256_SHA256 ->
                    ReallyMeJwkAlgorithm.P256
                SignatureAlgorithm.SIGNATURE_ALGORITHM_ECDSA_SECP256K1_SHA256 ->
                    ReallyMeJwkAlgorithm.SECP256K1
                SignatureAlgorithm.SIGNATURE_ALGORITHM_ML_DSA_44 ->
                    ReallyMeJwkAlgorithm.ML_DSA_44
                SignatureAlgorithm.SIGNATURE_ALGORITHM_ML_DSA_65 ->
                    ReallyMeJwkAlgorithm.ML_DSA_65
                SignatureAlgorithm.SIGNATURE_ALGORITHM_ML_DSA_87 ->
                    ReallyMeJwkAlgorithm.ML_DSA_87
                SignatureAlgorithm.SIGNATURE_ALGORITHM_SLH_DSA_SHA2_128S ->
                    ReallyMeJwkAlgorithm.SLH_DSA_SHA2_128S
                else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
            }
            CryptoAlgorithmIdentifier.AlgorithmCase.KEY_AGREEMENT -> {
                if (value.keyAgreement == KeyAgreementAlgorithm.KEY_AGREEMENT_ALGORITHM_X25519) {
                    ReallyMeJwkAlgorithm.X25519
                } else {
                    throw ReallyMeCryptoException.UnsupportedAlgorithm()
                }
            }
            CryptoAlgorithmIdentifier.AlgorithmCase.KEM -> when (value.kem) {
                KemAlgorithm.KEM_ALGORITHM_ML_KEM_512 -> ReallyMeJwkAlgorithm.ML_KEM_512
                KemAlgorithm.KEM_ALGORITHM_ML_KEM_768 -> ReallyMeJwkAlgorithm.ML_KEM_768
                KemAlgorithm.KEM_ALGORITHM_ML_KEM_1024 -> ReallyMeJwkAlgorithm.ML_KEM_1024
                KemAlgorithm.KEM_ALGORITHM_X_WING_768 -> ReallyMeJwkAlgorithm.X_WING_768
                else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
            }
            CryptoAlgorithmIdentifier.AlgorithmCase.ALGORITHM_NOT_SET ->
                throw ReallyMeCryptoException.InvalidInput()
            else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    private fun keyPairToProto(
        algorithm: CryptoAlgorithmIdentifier,
        publicKey: ByteArray,
        secretKey: ByteArray,
    ): CryptoKeyPair =
        CryptoKeyPair.newBuilder()
            .setAlgorithm(algorithm)
            .setPublicKey(ByteString.copyFrom(publicKey))
            .setSecretKey(ByteString.copyFrom(secretKey))
            .build()

    private fun signatureAlgorithmIdentifierToProto(
        value: ReallyMeSignatureAlgorithm,
    ): CryptoAlgorithmIdentifier =
        CryptoAlgorithmIdentifier.newBuilder()
            .setSignature(toProto(value))
            .build()

    private fun keyAgreementAlgorithmIdentifierToProto(
        value: ReallyMeKeyAgreementAlgorithm,
    ): CryptoAlgorithmIdentifier =
        CryptoAlgorithmIdentifier.newBuilder()
            .setKeyAgreement(toProto(value))
            .build()

    private fun kemAlgorithmIdentifierToProto(
        value: ReallyMeKemAlgorithm,
    ): CryptoAlgorithmIdentifier =
        CryptoAlgorithmIdentifier.newBuilder()
            .setKem(toProto(value))
            .build()

    private fun hpkeSuiteIdentifierToProto(
        value: ReallyMeHpkeSuite,
    ): CryptoAlgorithmIdentifier =
        CryptoAlgorithmIdentifier.newBuilder()
            .setHpkeSuite(toProto(value))
            .build()

    private fun signatureAlgorithmFromIdentifier(
        value: CryptoAlgorithmIdentifier,
        isPresent: Boolean,
    ): ReallyMeSignatureAlgorithm {
        if (!isPresent || value.algorithmCase != CryptoAlgorithmIdentifier.AlgorithmCase.SIGNATURE) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        return fromProto(value.signature)
    }

    private fun keyAgreementAlgorithmFromIdentifier(
        value: CryptoAlgorithmIdentifier,
        isPresent: Boolean,
    ): ReallyMeKeyAgreementAlgorithm {
        if (!isPresent || value.algorithmCase != CryptoAlgorithmIdentifier.AlgorithmCase.KEY_AGREEMENT) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        return fromProto(value.keyAgreement)
    }

    private fun kemAlgorithmFromIdentifier(
        value: CryptoAlgorithmIdentifier,
        isPresent: Boolean,
    ): ReallyMeKemAlgorithm {
        if (!isPresent || value.algorithmCase != CryptoAlgorithmIdentifier.AlgorithmCase.KEM) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        return fromProto(value.kem)
    }

    private fun hpkeSuiteFromIdentifier(
        value: CryptoAlgorithmIdentifier,
        isPresent: Boolean,
    ): ReallyMeHpkeSuite {
        if (!isPresent || value.algorithmCase != CryptoAlgorithmIdentifier.AlgorithmCase.HPKE_SUITE) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        return fromProto(value.hpkeSuite)
    }
}
