// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Semantic owner for key-derivation operations.

use crypto_core::CryptoError;
#[cfg(feature = "hkdf")]
use crypto_core::HkdfFailureKind;
#[cfg(any(
    feature = "argon2id",
    feature = "pbkdf2",
    feature = "kmac",
    feature = "concat-kdf"
))]
use crypto_core::KdfFailureKind;

use super::{BackendErrorReason, OperationError, PrimitiveErrorReason, ProviderErrorReason};
use crate::secret_material::{bind_operation_policy, SecretMaterialOperation};

#[cfg(feature = "argon2id")]
/// Derives a fixed Argon2id key with an explicit reviewed profile.
pub fn derive_argon2id(
    request: &crypto_argon2id::DeriveKeyRequest<'_>,
) -> Result<crypto_argon2id::Argon2idDerivedKey, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::KeyDerivation);
    crypto_argon2id::derive_key(request).map_err(map_kdf_error)
}

#[cfg(feature = "argon2id")]
/// Derives a fixed Argon2id key from the public versioned profile selector.
pub fn derive_argon2id_for_version(
    kdf_version: u32,
    secret: &[u8],
    salt: &[u8],
) -> Result<crypto_argon2id::Argon2idDerivedKey, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::KeyDerivation);
    crypto_argon2id::derive_key_for_version(kdf_version, secret, salt).map_err(map_kdf_error)
}

#[cfg(feature = "hkdf")]
/// Derives fixed-length HKDF output with the selected suite.
pub fn derive_hkdf<const N: usize>(
    request: &crypto_hkdf::DeriveRequest<'_>,
) -> Result<crypto_hkdf::HkdfOutput<N>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::KeyDerivation);
    crypto_hkdf::derive::<N>(request).map_err(map_hkdf_error)
}

#[cfg(feature = "hkdf")]
/// Extracts an HKDF-SHA384 pseudorandom key from input keying material.
pub fn extract_hkdf_sha384(
    salt: Option<&crypto_hkdf::HkdfSalt>,
    ikm: &crypto_hkdf::HkdfInputKeyMaterial,
) -> Result<crypto_hkdf::HkdfSha384Prk, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::KeyDerivation);
    crypto_hkdf::extract_sha384(salt, ikm).map_err(map_hkdf_error)
}

#[cfg(feature = "hkdf")]
/// Expands an HKDF-SHA384 pseudorandom key into fixed-size output material.
pub fn expand_hkdf_sha384<const N: usize>(
    prk: &crypto_hkdf::HkdfSha384Prk,
    info: &crypto_hkdf::HkdfInfo,
) -> Result<crypto_hkdf::HkdfOutput<N>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::KeyDerivation);
    crypto_hkdf::expand_sha384::<N>(prk, info).map_err(map_hkdf_error)
}

#[cfg(feature = "hkdf")]
/// Derives the workspace domain-separated 32-byte HKDF key profile.
pub fn derive_domain_hkdf_key_32(
    ikm: &crypto_hkdf::HkdfInputKeyMaterial,
    salt: Option<&crypto_hkdf::HkdfSalt>,
    purpose: crypto_hkdf::DomainKeyPurpose,
    domain_tag: &crypto_hkdf::DomainTag,
) -> Result<crypto_hkdf::HkdfOutput<32>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::KeyDerivation);
    crypto_hkdf::derive_domain_key_32(ikm, salt, purpose, domain_tag).map_err(map_hkdf_error)
}

#[cfg(feature = "pbkdf2")]
/// Derives PBKDF2 output under the modern public work-factor policy.
pub fn derive_pbkdf2(
    request: &crypto_pbkdf2::Pbkdf2Request<'_>,
) -> Result<crypto_pbkdf2::Pbkdf2Output, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::KeyDerivation);
    if !(crypto_pbkdf2::PBKDF2_MODERN_MIN_ITERATIONS..=crypto_pbkdf2::PBKDF2_MAX_ITERATIONS)
        .contains(&request.iterations.as_u32())
    {
        return Err(primitive(PrimitiveErrorReason::InvalidParameter));
    }
    crypto_pbkdf2::derive_key(request).map_err(map_kdf_error)
}

#[cfg(feature = "pbkdf2")]
/// Builds PBKDF2 owners under the modern policy, then derives key material.
pub fn derive_pbkdf2_from_raw(
    prf: crypto_pbkdf2::Pbkdf2Prf,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    output_len: usize,
) -> Result<crypto_pbkdf2::Pbkdf2Output, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::KeyDerivation);
    let password =
        crypto_pbkdf2::Pbkdf2Password::from_slice(password, prf).map_err(map_kdf_error)?;
    let salt = crypto_pbkdf2::Pbkdf2Salt::from_slice(salt, prf).map_err(map_kdf_error)?;
    let iterations =
        crypto_pbkdf2::Pbkdf2Iterations::from_u32_modern(iterations, prf).map_err(map_kdf_error)?;
    derive_pbkdf2(&crypto_pbkdf2::Pbkdf2Request {
        prf,
        password: &password,
        salt: &salt,
        iterations,
        output_len,
    })
}

#[cfg(feature = "kmac")]
/// Derives KMAC256 output keying material.
pub fn derive_kmac256(
    key: &crypto_kmac::Kmac256Key,
    context: &[u8],
    customization: &[u8],
    output_len: usize,
) -> Result<crypto_kmac::Kmac256Output, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::KeyDerivation);
    crypto_kmac::derive_kmac256(key, context, customization, output_len).map_err(map_kdf_error)
}

#[cfg(feature = "concat-kdf")]
/// Derives fixed-length JWA ECDH-ES Concat KDF output with SHA-256.
pub fn derive_jwa_concat_kdf_sha256<const N: usize>(
    request: &crypto_concat_kdf::JwaConcatKdfRequest<'_>,
) -> Result<crypto_concat_kdf::JwaConcatKdfOutput<N>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::KeyDerivation);
    crypto_concat_kdf::derive_jwa_concat_kdf_sha256::<N>(request).map_err(map_kdf_error)
}

#[cfg(any(
    feature = "argon2id",
    feature = "pbkdf2",
    feature = "kmac",
    feature = "concat-kdf"
))]
fn map_kdf_error(error: CryptoError) -> OperationError {
    match error {
        CryptoError::Kdf {
            kind: KdfFailureKind::InvalidSecretLength,
            ..
        } => primitive(PrimitiveErrorReason::InvalidKey),
        CryptoError::Kdf {
            kind: KdfFailureKind::InvalidSaltLength | KdfFailureKind::InvalidOutputLength,
            ..
        } => primitive(PrimitiveErrorReason::InvalidLength),
        CryptoError::Kdf {
            kind: KdfFailureKind::InvalidIterationCount | KdfFailureKind::InvalidParams,
            ..
        } => primitive(PrimitiveErrorReason::InvalidParameter),
        CryptoError::Kdf {
            kind: KdfFailureKind::DerivationFailed,
            ..
        } => backend(BackendErrorReason::Internal),
        CryptoError::Unsupported => provider(ProviderErrorReason::UnsupportedAlgorithm),
        _ => backend(BackendErrorReason::Internal),
    }
}

#[cfg(feature = "hkdf")]
fn map_hkdf_error(error: CryptoError) -> OperationError {
    match error {
        CryptoError::Hkdf {
            kind: HkdfFailureKind::InvalidIkmLength,
            ..
        } => primitive(PrimitiveErrorReason::InvalidKey),
        CryptoError::Hkdf {
            kind:
                HkdfFailureKind::InvalidDomainTagLength
                | HkdfFailureKind::InvalidDomainTagByte
                | HkdfFailureKind::InvalidOutputLength,
            ..
        } => primitive(PrimitiveErrorReason::InvalidLength),
        CryptoError::Hkdf {
            kind: HkdfFailureKind::LengthOverflow,
            ..
        } => primitive(PrimitiveErrorReason::LengthOverflow),
        CryptoError::Hkdf {
            kind: HkdfFailureKind::ExpandFailed,
            ..
        } => backend(BackendErrorReason::Internal),
        CryptoError::Unsupported => provider(ProviderErrorReason::UnsupportedAlgorithm),
        _ => backend(BackendErrorReason::Internal),
    }
}

fn primitive(reason: PrimitiveErrorReason) -> OperationError {
    OperationError::Primitive { reason }
}

fn provider(reason: ProviderErrorReason) -> OperationError {
    OperationError::Provider { reason }
}

fn backend(reason: BackendErrorReason) -> OperationError {
    OperationError::Backend { reason }
}
