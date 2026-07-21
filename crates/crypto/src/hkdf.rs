// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! HKDF facade routes backed by the semantic KDF operation owner.

use crypto_core::{CryptoError, HkdfFailureKind, HkdfHash};

pub use crypto_hkdf::{
    DeriveRequest, DomainKeyPurpose, DomainTag, HkdfInfo, HkdfInputKeyMaterial, HkdfOutput,
    HkdfSalt, HkdfSha384Prk, HkdfSuite, HKDF_SHA384_MAX_OUTPUT_LENGTH, HKDF_SHA384_PRK_LENGTH,
};

/// Derives fixed-length HKDF output through the operation layer.
pub fn derive<const N: usize>(request: &DeriveRequest<'_>) -> Result<HkdfOutput<N>, CryptoError> {
    crate::operations::kdf::derive_hkdf::<N>(request)
        .map_err(|error| crypto_error_from_operation_error(request.suite.hash(), error))
}

/// Extracts an HKDF-SHA384 pseudorandom key through the operation layer.
pub fn extract_sha384(
    salt: Option<&HkdfSalt>,
    ikm: &HkdfInputKeyMaterial,
) -> Result<HkdfSha384Prk, CryptoError> {
    crate::operations::kdf::extract_hkdf_sha384(salt, ikm)
        .map_err(|error| crypto_error_from_operation_error(HkdfHash::Sha2_384, error))
}

/// Expands an HKDF-SHA384 pseudorandom key through the operation layer.
pub fn expand_sha384<const N: usize>(
    prk: &HkdfSha384Prk,
    info: &HkdfInfo,
) -> Result<HkdfOutput<N>, CryptoError> {
    crate::operations::kdf::expand_hkdf_sha384::<N>(prk, info)
        .map_err(|error| crypto_error_from_operation_error(HkdfHash::Sha2_384, error))
}

/// Derives a 32-byte workspace domain key through the operation layer.
pub fn derive_domain_key_32(
    ikm: &HkdfInputKeyMaterial,
    salt: Option<&HkdfSalt>,
    purpose: DomainKeyPurpose,
    domain_tag: &DomainTag,
) -> Result<HkdfOutput<32>, CryptoError> {
    crate::operations::kdf::derive_domain_hkdf_key_32(ikm, salt, purpose, domain_tag)
        .map_err(|error| crypto_error_from_operation_error(HkdfHash::Sha3_256, error))
}

fn crypto_error_from_operation_error(
    hash: HkdfHash,
    error: crate::operations::OperationError,
) -> CryptoError {
    let kind = match error {
        crate::operations::OperationError::Primitive {
            reason: crate::operations::PrimitiveErrorReason::InvalidKey,
        } => HkdfFailureKind::InvalidIkmLength,
        crate::operations::OperationError::Primitive {
            reason: crate::operations::PrimitiveErrorReason::InvalidLength,
        } => HkdfFailureKind::InvalidOutputLength,
        crate::operations::OperationError::Primitive {
            reason: crate::operations::PrimitiveErrorReason::LengthOverflow,
        } => HkdfFailureKind::LengthOverflow,
        crate::operations::OperationError::Provider {
            reason: crate::operations::ProviderErrorReason::UnsupportedAlgorithm,
        } => return CryptoError::Unsupported,
        _ => HkdfFailureKind::ExpandFailed,
    };

    CryptoError::Hkdf { hash, kind }
}
