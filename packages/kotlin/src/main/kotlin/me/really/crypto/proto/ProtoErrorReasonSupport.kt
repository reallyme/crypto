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

internal val primitiveCryptoErrorReasons: Set<CryptoErrorReason> = setOf(
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

internal val providerCryptoErrorReasons: Set<CryptoErrorReason> = setOf(
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

internal val backendCryptoErrorReasons: Set<CryptoErrorReason> = setOf(
    CryptoErrorReason.CRYPTO_ERROR_REASON_BACKEND_INVALID_STATE,
    CryptoErrorReason.CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
)
