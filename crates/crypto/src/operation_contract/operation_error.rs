// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

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
use crypto_proto::wire::CryptoWireError;

use crate::operations::OperationError;

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
    error.into()
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
        *error,
        crypto_core::CryptoError::PRIMITIVE_VERIFICATION_FAILED
            | crypto_core::CryptoError::PRIMITIVE_AUTHENTICATION_FAILED
            | crypto_core::CryptoError::PRIMITIVE_INVALID_SIGNATURE
    )
}
