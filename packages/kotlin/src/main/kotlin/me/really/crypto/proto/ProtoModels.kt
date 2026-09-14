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
            if (!reasonMatchesBranch(branch, reason)) {
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
            if (!reasonCodeMatchesBranch(branch, reasonCode)) {
                return ReallyMeCryptoWireErrorValidationResult.Failure(
                    ReallyMeCryptoWireErrorValidationError.REASON_CODE_OUT_OF_RANGE,
                )
            }
            val known = CryptoErrorReason.forNumber(reasonCode)
            if (known != null && !reasonMatchesBranch(branch, known)) {
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
