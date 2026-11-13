// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! HKDF facade routes backed by the semantic KDF operation owner.

use crypto_core::CryptoError;

pub use crypto_hkdf::{
    DeriveRequest, DomainKeyPurpose, DomainTag, HkdfInfo, HkdfInputKeyMaterial, HkdfOutput,
    HkdfSalt, HkdfSha384Prk, HkdfSuite, HKDF_SHA384_MAX_OUTPUT_LENGTH, HKDF_SHA384_PRK_LENGTH,
};

/// Derives fixed-length HKDF output through the operation layer.
pub fn derive<const N: usize>(request: &DeriveRequest<'_>) -> Result<HkdfOutput<N>, CryptoError> {
    crate::operations::kdf::derive_hkdf::<N>(request)
}

/// Extracts an HKDF-SHA384 pseudorandom key through the operation layer.
pub fn extract_sha384(
    salt: Option<&HkdfSalt>,
    ikm: &HkdfInputKeyMaterial,
) -> Result<HkdfSha384Prk, CryptoError> {
    crate::operations::kdf::extract_hkdf_sha384(salt, ikm)
}

/// Expands an HKDF-SHA384 pseudorandom key through the operation layer.
pub fn expand_sha384<const N: usize>(
    prk: &HkdfSha384Prk,
    info: &HkdfInfo,
) -> Result<HkdfOutput<N>, CryptoError> {
    crate::operations::kdf::expand_hkdf_sha384::<N>(prk, info)
}

/// Derives a 32-byte workspace domain key through the operation layer.
pub fn derive_domain_key_32(
    ikm: &HkdfInputKeyMaterial,
    salt: Option<&HkdfSalt>,
    purpose: DomainKeyPurpose,
    domain_tag: &DomainTag,
) -> Result<HkdfOutput<32>, CryptoError> {
    crate::operations::kdf::derive_domain_hkdf_key_32(ikm, salt, purpose, domain_tag)
}
