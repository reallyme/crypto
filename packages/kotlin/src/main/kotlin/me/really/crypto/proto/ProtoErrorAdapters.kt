// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

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

public interface ReallyMeCryptoProtoErrorAdapters {
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

}
