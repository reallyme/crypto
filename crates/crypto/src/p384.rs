// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! P-384 root facade with signature and key agreement routed through operations.

use crypto_core::{Algorithm, CryptoError, SignatureOperation};
use zeroize::Zeroizing;

use crate::key_agreement_error::crypto_error_from_derive_shared_secret_operation_error;
use crate::signature_error::crypto_error_from_operation_error;

pub use crypto_p384::{
    compress_p384, compress_public_key, decompress_p384, decompress_public_key,
    P384_PUBLIC_KEY_COMPRESSED_LEN, P384_PUBLIC_KEY_RAW_LEN, P384_PUBLIC_KEY_UNCOMPRESSED_LEN,
    P384_SECRET_KEY_LEN, P384_SHARED_SECRET_LEN, P384_SIGNATURE_DER_MAX_LEN,
};

/// Generate a P-384 ECDSA keypair through the signature operation owner.
pub fn generate_p384_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    crate::operations::signature::generate_key_pair(Algorithm::P384)
        .map(|key_pair| (key_pair.public_key, key_pair.secret_key))
        .map_err(|error| {
            crypto_error_from_operation_error(SignatureOperation::KeyManagement, error)
        })
}

/// Reconstruct a P-384 ECDSA keypair from a validated 48-byte scalar.
pub fn generate_p384_keypair_from_secret_key(
    secret_key: &[u8; 48],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    crate::operations::signature::derive_key_pair(Algorithm::P384, secret_key)
        .map(|key_pair| (key_pair.public_key, key_pair.secret_key))
        .map_err(|error| {
            crypto_error_from_operation_error(SignatureOperation::KeyManagement, error)
        })
}

/// Signs `message` with ECDSA P-384 and SHA-384, returning DER encoding.
pub fn sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    crate::operations::signature::sign(Algorithm::P384, secret_key, message)
        .map_err(|error| crypto_error_from_operation_error(SignatureOperation::Sign, error))
}

/// Verifies a DER-encoded ECDSA P-384/SHA-384 signature over `message`.
pub fn verify(
    public_key_sec1: &[u8],
    message: &[u8],
    signature_der: &[u8],
) -> Result<(), CryptoError> {
    crate::operations::signature::verify(Algorithm::P384, public_key_sec1, message, signature_der)
        .map_err(|error| crypto_error_from_operation_error(SignatureOperation::Verify, error))
}

/// Derive the raw P-384 ECDH shared secret through the key-agreement owner.
pub fn derive_p384_shared_secret(
    secret_key: &[u8],
    public_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    crate::operations::key_agreement::derive_shared_secret(Algorithm::P384, secret_key, public_key)
        .map_err(crypto_error_from_derive_shared_secret_operation_error)
}
