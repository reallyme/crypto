// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Semantic owner for public-key byte encoding helpers.

use super::{BackendErrorReason, OperationError, PrimitiveErrorReason};
use crate::secret_material::{bind_operation_policy, SecretMaterialOperation};

/// Validates a fixed-width public key and returns its canonical byte form.
pub fn copy_fixed_public_key(
    public_key: &[u8],
    expected_len: usize,
) -> Result<Vec<u8>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::PublicKeyEncoding);
    if public_key.len() != expected_len {
        return Err(invalid_public_key());
    }
    Ok(public_key.to_vec())
}

#[cfg(feature = "ed25519")]
/// Validates and returns canonical Ed25519 public-key bytes.
pub fn encode_ed25519_public_key(public_key: &[u8]) -> Result<Vec<u8>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::PublicKeyEncoding);
    crypto_ed25519::encode_public_key(public_key).map_err(map_public_key_error)
}

#[cfg(feature = "ed25519")]
/// Decodes Ed25519 public-key bytes into the canonical raw representation.
pub fn decode_ed25519_public_key(public_key: &[u8]) -> Result<Vec<u8>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::PublicKeyEncoding);
    crypto_ed25519::decode_public_key(public_key).map_err(map_public_key_error)
}

#[cfg(feature = "p256")]
/// Compresses an uncompressed P-256 SEC1 public key.
pub fn compress_p256_public_key(public_key: &[u8]) -> Result<Vec<u8>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::PublicKeyEncoding);
    crypto_p256::compress_p256(public_key).map_err(map_public_key_error)
}

#[cfg(feature = "p256")]
/// Decompresses a compressed P-256 SEC1 public key.
pub fn decompress_p256_public_key(public_key: &[u8]) -> Result<Vec<u8>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::PublicKeyEncoding);
    crypto_p256::decompress_p256(public_key).map_err(map_public_key_error)
}

#[cfg(feature = "p384")]
/// Compresses an uncompressed P-384 SEC1 public key.
pub fn compress_p384_public_key(public_key: &[u8]) -> Result<Vec<u8>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::PublicKeyEncoding);
    crypto_p384::compress_p384(public_key).map_err(map_public_key_error)
}

#[cfg(feature = "p384")]
/// Decompresses a compressed P-384 SEC1 public key.
pub fn decompress_p384_public_key(public_key: &[u8]) -> Result<Vec<u8>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::PublicKeyEncoding);
    crypto_p384::decompress_p384(public_key).map_err(map_public_key_error)
}

#[cfg(feature = "p521")]
/// Compresses an uncompressed P-521 SEC1 public key.
pub fn compress_p521_public_key(public_key: &[u8]) -> Result<Vec<u8>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::PublicKeyEncoding);
    crypto_p521::compress_p521(public_key).map_err(map_public_key_error)
}

#[cfg(feature = "p521")]
/// Decompresses a compressed P-521 SEC1 public key.
pub fn decompress_p521_public_key(public_key: &[u8]) -> Result<Vec<u8>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::PublicKeyEncoding);
    crypto_p521::decompress_p521(public_key).map_err(map_public_key_error)
}

#[cfg(feature = "secp256k1")]
/// Validates and returns canonical compressed secp256k1 public-key bytes.
pub fn encode_secp256k1_public_key(public_key: &[u8]) -> Result<Vec<u8>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::PublicKeyEncoding);
    crypto_secp256k1::encode_public_key(public_key).map_err(map_public_key_error)
}

#[cfg(feature = "secp256k1")]
/// Decodes secp256k1 public-key bytes into the canonical compressed representation.
pub fn decode_secp256k1_public_key(public_key: &[u8]) -> Result<Vec<u8>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::PublicKeyEncoding);
    crypto_secp256k1::decode_public_key(public_key).map_err(map_public_key_error)
}

#[cfg(feature = "secp256k1")]
/// Decompresses a secp256k1 public key into affine coordinate bytes.
pub fn decompress_secp256k1_public_key(
    public_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::PublicKeyEncoding);
    crypto_secp256k1::decompress_public_key(public_key).map_err(map_public_key_error)
}

#[cfg(feature = "secp256k1")]
/// Validates and returns canonical BIP-340 x-only public-key bytes.
pub fn encode_bip340_schnorr_public_key(public_key: &[u8]) -> Result<Vec<u8>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::PublicKeyEncoding);
    crypto_secp256k1::encode_bip340_schnorr_public_key(public_key).map_err(map_public_key_error)
}

#[cfg(feature = "secp256k1")]
/// Decodes BIP-340 x-only public-key bytes into the canonical representation.
pub fn decode_bip340_schnorr_public_key(public_key: &[u8]) -> Result<Vec<u8>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::PublicKeyEncoding);
    crypto_secp256k1::decode_bip340_schnorr_public_key(public_key).map_err(map_public_key_error)
}

#[cfg(feature = "x25519")]
/// Validates and returns canonical X25519 public-key bytes.
pub fn encode_x25519_public_key(public_key: &[u8]) -> Result<Vec<u8>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::PublicKeyEncoding);
    crypto_x25519::encode_public_key(public_key).map_err(map_public_key_error)
}

#[cfg(feature = "x25519")]
/// Decodes X25519 public-key bytes into the canonical raw representation.
pub fn decode_x25519_public_key(public_key: &[u8]) -> Result<Vec<u8>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::PublicKeyEncoding);
    crypto_x25519::decode_public_key(public_key).map_err(map_public_key_error)
}

fn map_public_key_error(error: crypto_core::CryptoError) -> OperationError {
    match error {
        crypto_core::CryptoError::InvalidKey => invalid_public_key(),
        crypto_core::CryptoError::Signature {
            kind: crypto_core::SignatureFailureKind::InvalidPublicKey,
            ..
        } => invalid_public_key(),
        crypto_core::CryptoError::Unsupported => OperationError::Provider {
            reason: super::ProviderErrorReason::UnsupportedAlgorithm,
        },
        _ => OperationError::Backend {
            reason: BackendErrorReason::Internal,
        },
    }
}

fn invalid_public_key() -> OperationError {
    OperationError::Primitive {
        reason: PrimitiveErrorReason::InvalidPublicKey,
    }
}
