// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! P-256 root facade with signature and key agreement routed through operations.

use crypto_core::{Algorithm, CryptoError, SignatureOperation};
use zeroize::Zeroizing;

use crate::key_agreement_error::crypto_error_from_derive_shared_secret_operation_error;
use crate::signature_error::crypto_error_from_operation_error;

pub use crypto_p256::{
    compress_public_key, decode_se_handle, decompress_public_key, encode_se_handle,
    p256_ecdsa_der_to_jose_signature, p256_ecdsa_jose_signature_to_der,
    P256_ECDSA_JOSE_SIGNATURE_LEN, P256_SIGNATURE_DER_MAX_LEN, SE_HANDLE_PREFIX,
};

#[cfg(feature = "native")]
pub use crypto_p256::{
    compressed_public_key_from_private_key, private_key_from_pem, private_key_from_pkcs8_der,
    private_key_from_pkcs8_pem, private_key_from_sec1_der, private_key_from_sec1_pem,
    public_key_from_spki_der, public_key_from_spki_pem,
};

/// Generate a P-256 ECDSA keypair through the signature operation owner.
pub fn generate_p256_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    crate::operations::signature::generate_key_pair(Algorithm::P256)
        .map(|key_pair| (key_pair.public_key, key_pair.secret_key))
        .map_err(|error| {
            crypto_error_from_operation_error(SignatureOperation::KeyManagement, error)
        })
}

/// Reconstruct a P-256 ECDSA keypair from a validated 32-byte scalar.
pub fn generate_p256_keypair_from_secret_key(
    secret_key: &[u8; 32],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    crate::operations::signature::derive_key_pair(Algorithm::P256, secret_key)
        .map(|key_pair| (key_pair.public_key, key_pair.secret_key))
        .map_err(|error| {
            crypto_error_from_operation_error(SignatureOperation::KeyManagement, error)
        })
}

/// Hash `message` with SHA-256, sign it with P-256 ECDSA, and return DER.
///
/// Despite the retained low-level function name, callers pass the original
/// message. The primitive performs exactly one SHA-256 hash internally.
pub fn sign_p256_der_prehash(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    crate::operations::signature::sign(Algorithm::P256, secret_key, message)
        .map_err(|error| crypto_error_from_operation_error(SignatureOperation::Sign, error))
}

/// Verify a DER-encoded P-256 ECDSA/SHA-256 signature over `message`.
pub fn verify_p256_der_prehash(
    signature_der: &[u8],
    message: &[u8],
    public_key_sec1: &[u8],
) -> Result<(), CryptoError> {
    crate::operations::signature::verify(Algorithm::P256, public_key_sec1, message, signature_der)
        .map_err(|error| crypto_error_from_operation_error(SignatureOperation::Verify, error))
}

/// Derive the raw P-256 ECDH shared secret through the key-agreement owner.
pub fn derive_p256_shared_secret(
    secret_key: &[u8],
    public_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    crate::operations::key_agreement::derive_shared_secret(Algorithm::P256, secret_key, public_key)
        .map_err(crypto_error_from_derive_shared_secret_operation_error)
}
