// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! P-521 root facade with signature and key agreement routed through operations.

use crypto_core::{Algorithm, CryptoError, SignatureOperation};
use zeroize::Zeroizing;

use crate::key_agreement_error::crypto_error_from_derive_shared_secret_operation_error;
use crate::signature_error::crypto_error_from_operation_error;

pub use crypto_p521::{
    compress_p521, compress_public_key, decompress_p521, decompress_public_key,
    P521_PUBLIC_KEY_COMPRESSED_LEN, P521_PUBLIC_KEY_RAW_LEN, P521_PUBLIC_KEY_UNCOMPRESSED_LEN,
    P521_SECRET_KEY_LEN, P521_SHARED_SECRET_LEN, P521_SIGNATURE_DER_MAX_LEN,
};

/// Generate a P-521 ECDSA keypair through the signature operation owner.
pub fn generate_p521_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    crate::operations::signature::generate_key_pair(Algorithm::P521)
        .map(|key_pair| (key_pair.public_key, key_pair.secret_key))
        .map_err(|error| {
            crypto_error_from_operation_error(SignatureOperation::KeyManagement, error)
        })
}

/// Reconstruct a P-521 ECDSA keypair from a validated 66-byte scalar.
pub fn generate_p521_keypair_from_secret_key(
    secret_key: &[u8; 66],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    crate::operations::signature::derive_key_pair(Algorithm::P521, secret_key)
        .map(|key_pair| (key_pair.public_key, key_pair.secret_key))
        .map_err(|error| {
            crypto_error_from_operation_error(SignatureOperation::KeyManagement, error)
        })
}

/// Hash `message` with SHA-512, sign it with P-521 ECDSA, and return DER.
///
/// Despite the retained low-level function name, callers pass the original
/// message. The primitive performs exactly one SHA-512 hash internally.
pub fn sign_p521_der_prehash(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    crate::operations::signature::sign(Algorithm::P521, secret_key, message)
        .map_err(|error| crypto_error_from_operation_error(SignatureOperation::Sign, error))
}

/// Verify a DER-encoded P-521 ECDSA/SHA-512 signature over `message`.
pub fn verify_p521_der_prehash(
    signature_der: &[u8],
    message: &[u8],
    public_key_sec1: &[u8],
) -> Result<(), CryptoError> {
    crate::operations::signature::verify(Algorithm::P521, public_key_sec1, message, signature_der)
        .map_err(|error| crypto_error_from_operation_error(SignatureOperation::Verify, error))
}

/// Derive the raw P-521 ECDH shared secret through the key-agreement owner.
pub fn derive_p521_shared_secret(
    secret_key: &[u8],
    public_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    crate::operations::key_agreement::derive_shared_secret(Algorithm::P521, secret_key, public_key)
        .map_err(crypto_error_from_derive_shared_secret_operation_error)
}
