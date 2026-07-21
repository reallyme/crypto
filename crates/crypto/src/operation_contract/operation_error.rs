// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Semantic-operation to generated-wire error mapping.

#[cfg(any(
    feature = "hmac",
    all(
        feature = "dispatch",
        any(
            feature = "rsa",
            feature = "ed25519",
            feature = "p256",
            feature = "p384",
            feature = "p521",
            feature = "secp256k1",
            feature = "ml-dsa-44",
            feature = "ml-dsa-65",
            feature = "ml-dsa-87",
            feature = "slh-dsa"
        )
    )
))]
use buffa::{EnumValue, MessageField};
use crypto_proto::generated::proto::reallyme::crypto::v1::CryptoErrorReason;
#[cfg(any(
    feature = "hmac",
    all(
        feature = "dispatch",
        any(
            feature = "rsa",
            feature = "ed25519",
            feature = "p256",
            feature = "p384",
            feature = "p521",
            feature = "secp256k1",
            feature = "ml-dsa-44",
            feature = "ml-dsa-65",
            feature = "ml-dsa-87",
            feature = "slh-dsa"
        )
    )
))]
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoAlgorithmIdentifier, CryptoVerificationResult, CryptoVerificationStatus,
};
use crypto_proto::wire::{CryptoWireError, CryptoWireErrorBranch};

use crate::operations::{
    BackendErrorReason, OperationError, PrimitiveErrorReason, ProviderErrorReason,
};

use super::wire_error::{invalid_parameter, unsupported_algorithm, wire_error};

#[cfg(any(
    feature = "hmac",
    all(
        feature = "dispatch",
        any(
            feature = "rsa",
            feature = "ed25519",
            feature = "p256",
            feature = "p384",
            feature = "p521",
            feature = "secp256k1",
            feature = "ml-dsa-44",
            feature = "ml-dsa-65",
            feature = "ml-dsa-87",
            feature = "slh-dsa"
        )
    )
))]
pub(super) fn verification_result(
    algorithm: CryptoAlgorithmIdentifier,
    verified: bool,
    error: Option<CryptoWireError>,
) -> CryptoVerificationResult {
    CryptoVerificationResult {
        algorithm: MessageField::some(algorithm),
        status: EnumValue::from(match (verified, error) {
            (true, None) => CryptoVerificationStatus::CRYPTO_VERIFICATION_STATUS_VALID,
            (false, None) => CryptoVerificationStatus::CRYPTO_VERIFICATION_STATUS_INVALID,
            (false, Some(_)) | (true, Some(_)) => {
                CryptoVerificationStatus::CRYPTO_VERIFICATION_STATUS_ERROR
            }
        }),
        error: match error {
            Some(error) => MessageField::some(error.to_proto()),
            None => MessageField::none(),
        },
        __buffa_unknown_fields: Default::default(),
    }
}

pub(super) fn map_operation_error(error: OperationError) -> CryptoWireError {
    match error {
        OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        } => unsupported_algorithm(),
        OperationError::Provider { .. } => wire_error(
            CryptoWireErrorBranch::Provider,
            CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE,
        ),
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey,
        } => wire_error(
            CryptoWireErrorBranch::Primitive,
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
        ),
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidPublicKey,
        } => wire_error(
            CryptoWireErrorBranch::Primitive,
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PUBLIC_KEY,
        ),
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidPrivateKey,
        } => wire_error(
            CryptoWireErrorBranch::Primitive,
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PRIVATE_KEY,
        ),
        OperationError::Primitive {
            reason: PrimitiveErrorReason::MalformedCiphertext,
        } => wire_error(
            CryptoWireErrorBranch::Primitive,
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_CIPHERTEXT,
        ),
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidParameter,
        } => invalid_parameter(),
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidLength,
        }
        | OperationError::Primitive {
            reason: PrimitiveErrorReason::LengthOverflow,
        } => wire_error(
            CryptoWireErrorBranch::Primitive,
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH,
        ),
        OperationError::Primitive {
            reason: PrimitiveErrorReason::VerificationFailed,
        } => wire_error(
            CryptoWireErrorBranch::Primitive,
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED,
        ),
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidSharedSecret,
        } => wire_error(
            CryptoWireErrorBranch::Primitive,
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SHARED_SECRET,
        ),
        OperationError::Primitive { .. } => invalid_parameter(),
        OperationError::Backend {
            reason: BackendErrorReason::InvalidOutput,
        } => wire_error(
            CryptoWireErrorBranch::Backend,
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INVALID_STATE,
        ),
        OperationError::Backend { .. } => wire_error(
            CryptoWireErrorBranch::Backend,
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
    }
}

#[cfg(any(
    feature = "hmac",
    all(
        feature = "dispatch",
        any(
            feature = "rsa",
            feature = "ed25519",
            feature = "p256",
            feature = "p384",
            feature = "p521",
            feature = "secp256k1",
            feature = "ml-dsa-44",
            feature = "ml-dsa-65",
            feature = "ml-dsa-87",
            feature = "slh-dsa"
        )
    )
))]
pub(super) fn is_operation_verification_mismatch(error: &OperationError) -> bool {
    matches!(
        error,
        OperationError::Primitive {
            reason: PrimitiveErrorReason::VerificationFailed,
        }
    )
}
