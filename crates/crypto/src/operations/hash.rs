// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Semantic owner for hash operations.

use crypto_core::HashAlgorithm;

use super::OperationError;
use crate::secret_material::{bind_operation_policy, SecretMaterialOperation};

/// Compute a digest for the selected hash algorithm.
///
/// The operation layer owns algorithm selection so protobuf, FFI, WASM, and SDK
/// adapters cannot grow independent hash dispatch semantics.
pub fn digest(algorithm: HashAlgorithm, input: &[u8]) -> Result<Vec<u8>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::Hash);
    match algorithm {
        HashAlgorithm::Sha2_256 => digest_sha2_256_bytes(input, algorithm),
        HashAlgorithm::Sha2_384 => digest_sha2_384_bytes(input, algorithm),
        HashAlgorithm::Sha2_512 => digest_sha2_512_bytes(input, algorithm),
        HashAlgorithm::Sha3_224 => digest_sha3_224_bytes(input, algorithm),
        HashAlgorithm::Sha3_256 => digest_sha3_256_bytes(input, algorithm),
        HashAlgorithm::Sha3_384 => digest_sha3_384_bytes(input, algorithm),
        HashAlgorithm::Sha3_512 => digest_sha3_512_bytes(input, algorithm),
    }
}

#[cfg(feature = "sha2")]
/// Compute SHA-256 and return the fixed-size primitive digest wrapper.
pub fn sha2_256(input: &[u8]) -> crypto_sha2_256::Sha2_256Digest {
    let _policy = bind_operation_policy(SecretMaterialOperation::Hash);
    crypto_sha2_256::digest(input)
}

#[cfg(feature = "sha2")]
fn digest_sha2_256_bytes(
    input: &[u8],
    _algorithm: HashAlgorithm,
) -> Result<Vec<u8>, OperationError> {
    Ok(sha2_256(input).into_bytes().to_vec())
}

#[cfg(not(feature = "sha2"))]
fn digest_sha2_256_bytes(
    _input: &[u8],
    algorithm: HashAlgorithm,
) -> Result<Vec<u8>, OperationError> {
    unsupported_hash(algorithm)
}

#[cfg(feature = "sha2")]
/// Compute SHA-384 and return the fixed-size primitive digest wrapper.
pub fn sha2_384(input: &[u8]) -> crypto_sha2::Sha2_384Digest {
    let _policy = bind_operation_policy(SecretMaterialOperation::Hash);
    crypto_sha2::digest_sha2_384(input)
}

#[cfg(feature = "sha2")]
fn digest_sha2_384_bytes(
    input: &[u8],
    _algorithm: HashAlgorithm,
) -> Result<Vec<u8>, OperationError> {
    Ok(sha2_384(input).into_bytes().to_vec())
}

#[cfg(not(feature = "sha2"))]
fn digest_sha2_384_bytes(
    _input: &[u8],
    algorithm: HashAlgorithm,
) -> Result<Vec<u8>, OperationError> {
    unsupported_hash(algorithm)
}

#[cfg(feature = "sha2")]
/// Compute SHA-512 and return the fixed-size primitive digest wrapper.
pub fn sha2_512(input: &[u8]) -> crypto_sha2::Sha2_512Digest {
    let _policy = bind_operation_policy(SecretMaterialOperation::Hash);
    crypto_sha2::digest_sha2_512(input)
}

#[cfg(feature = "sha2")]
fn digest_sha2_512_bytes(
    input: &[u8],
    _algorithm: HashAlgorithm,
) -> Result<Vec<u8>, OperationError> {
    Ok(sha2_512(input).into_bytes().to_vec())
}

#[cfg(not(feature = "sha2"))]
fn digest_sha2_512_bytes(
    _input: &[u8],
    algorithm: HashAlgorithm,
) -> Result<Vec<u8>, OperationError> {
    unsupported_hash(algorithm)
}

#[cfg(feature = "sha3")]
/// Compute SHA3-224 and return the fixed-size primitive digest wrapper.
pub fn sha3_224(input: &[u8]) -> crypto_sha3::Sha3_224Digest {
    let _policy = bind_operation_policy(SecretMaterialOperation::Hash);
    crypto_sha3::digest_sha3_224(input)
}

#[cfg(feature = "sha3")]
fn digest_sha3_224_bytes(
    input: &[u8],
    _algorithm: HashAlgorithm,
) -> Result<Vec<u8>, OperationError> {
    Ok(sha3_224(input).into_bytes().to_vec())
}

#[cfg(not(feature = "sha3"))]
fn digest_sha3_224_bytes(
    _input: &[u8],
    algorithm: HashAlgorithm,
) -> Result<Vec<u8>, OperationError> {
    unsupported_hash(algorithm)
}

#[cfg(feature = "sha3")]
/// Compute SHA3-256 and return the fixed-size primitive digest wrapper.
pub fn sha3_256(input: &[u8]) -> crypto_sha3_256::Sha3_256Digest {
    let _policy = bind_operation_policy(SecretMaterialOperation::Hash);
    crypto_sha3_256::digest(input)
}

#[cfg(feature = "sha3")]
fn digest_sha3_256_bytes(
    input: &[u8],
    _algorithm: HashAlgorithm,
) -> Result<Vec<u8>, OperationError> {
    Ok(sha3_256(input).into_bytes().to_vec())
}

#[cfg(not(feature = "sha3"))]
fn digest_sha3_256_bytes(
    _input: &[u8],
    algorithm: HashAlgorithm,
) -> Result<Vec<u8>, OperationError> {
    unsupported_hash(algorithm)
}

#[cfg(feature = "sha3")]
/// Compute SHA3-384 and return the fixed-size primitive digest wrapper.
pub fn sha3_384(input: &[u8]) -> crypto_sha3::Sha3_384Digest {
    let _policy = bind_operation_policy(SecretMaterialOperation::Hash);
    crypto_sha3::digest_sha3_384(input)
}

#[cfg(feature = "sha3")]
fn digest_sha3_384_bytes(
    input: &[u8],
    _algorithm: HashAlgorithm,
) -> Result<Vec<u8>, OperationError> {
    Ok(sha3_384(input).into_bytes().to_vec())
}

#[cfg(not(feature = "sha3"))]
fn digest_sha3_384_bytes(
    _input: &[u8],
    algorithm: HashAlgorithm,
) -> Result<Vec<u8>, OperationError> {
    unsupported_hash(algorithm)
}

#[cfg(feature = "sha3")]
/// Compute SHA3-512 and return the fixed-size primitive digest wrapper.
pub fn sha3_512(input: &[u8]) -> crypto_sha3::Sha3_512Digest {
    let _policy = bind_operation_policy(SecretMaterialOperation::Hash);
    crypto_sha3::digest_sha3_512(input)
}

#[cfg(feature = "sha3")]
fn digest_sha3_512_bytes(
    input: &[u8],
    _algorithm: HashAlgorithm,
) -> Result<Vec<u8>, OperationError> {
    Ok(sha3_512(input).into_bytes().to_vec())
}

#[cfg(not(feature = "sha3"))]
fn digest_sha3_512_bytes(
    _input: &[u8],
    algorithm: HashAlgorithm,
) -> Result<Vec<u8>, OperationError> {
    unsupported_hash(algorithm)
}

#[cfg(any(not(feature = "sha2"), not(feature = "sha3")))]
fn unsupported_hash<T>(_algorithm: HashAlgorithm) -> Result<T, OperationError> {
    Err(OperationError::Provider {
        reason: super::ProviderErrorReason::UnsupportedAlgorithm,
    })
}
