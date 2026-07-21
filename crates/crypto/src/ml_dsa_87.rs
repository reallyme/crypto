// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! ML-DSA-87 root facade routed through the signature operation layer.

use crypto_core::{Algorithm, CryptoError, SignatureOperation};
use zeroize::Zeroizing;

use crate::signature_error::crypto_error_from_operation_error;

pub use crypto_ml_dsa_87::{
    decode_public_key, encode_public_key, ML_DSA_87_PUBLIC_KEY_LEN, ML_DSA_87_SECRET_SEED_LEN,
    ML_DSA_87_SIGNATURE_LEN,
};

/// Generate an ML-DSA-87 keypair through the signature operation owner.
pub fn generate_ml_dsa_87_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    crate::operations::signature::generate_key_pair(Algorithm::MlDsa87)
        .map(|key_pair| (key_pair.public_key, key_pair.secret_key))
        .map_err(|error| {
            crypto_error_from_operation_error(SignatureOperation::KeyManagement, error)
        })
}

/// Reconstruct an ML-DSA-87 keypair from a 32-byte FIPS 204 seed.
pub fn generate_ml_dsa_87_keypair_from_seed(
    seed: &[u8; ML_DSA_87_SECRET_SEED_LEN],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    crate::operations::signature::derive_key_pair(Algorithm::MlDsa87, seed)
        .map(|key_pair| (key_pair.public_key, key_pair.secret_key))
        .map_err(|error| {
            crypto_error_from_operation_error(SignatureOperation::KeyManagement, error)
        })
}

/// Sign `message` with an ML-DSA-87 seed.
pub fn sign_ml_dsa_87(secret_seed: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    crate::operations::signature::sign(Algorithm::MlDsa87, secret_seed, message)
        .map_err(|error| crypto_error_from_operation_error(SignatureOperation::Sign, error))
}

/// Verify an ML-DSA-87 detached signature.
pub fn verify_ml_dsa_87(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    crate::operations::signature::verify(Algorithm::MlDsa87, public_key, message, signature)
        .map_err(|error| crypto_error_from_operation_error(SignatureOperation::Verify, error))
}
