// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! ML-KEM-1024 root facade routed through the KEM operation layer.

use crypto_core::{Algorithm, CryptoError};
use zeroize::Zeroizing;

use crate::kem_error::{
    crypto_error_from_kem_decapsulation_operation_error,
    crypto_error_from_kem_encapsulation_operation_error,
    crypto_error_from_kem_key_generation_operation_error,
};

pub use crypto_ml_kem_1024::{ML_KEM_1024_PUBLIC_KEY_LEN, ML_KEM_1024_SECRET_KEY_LEN};

/// Generate an ML-KEM-1024 keypair through the KEM operation owner.
pub fn generate_ml_kem_1024_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    crate::operations::kem::generate_key_pair(Algorithm::MlKem1024)
        .map(|key_pair| (key_pair.public_key, key_pair.secret_key))
        .map_err(crypto_error_from_kem_key_generation_operation_error)
}

/// Reconstruct an ML-KEM-1024 keypair from a 64-byte FIPS 203 seed.
pub fn generate_ml_kem_1024_keypair_from_seed(
    seed: &[u8; ML_KEM_1024_SECRET_KEY_LEN],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    crate::operations::kem::derive_key_pair(Algorithm::MlKem1024, seed)
        .map(|key_pair| (key_pair.public_key, key_pair.secret_key))
        .map_err(crypto_error_from_kem_key_generation_operation_error)
}

/// Encapsulate to an ML-KEM-1024 public key.
pub fn ml_kem_1024_encapsulate(
    public_key: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    crate::operations::kem::encapsulate(Algorithm::MlKem1024, public_key)
        .map(|encapsulation| (encapsulation.ciphertext, encapsulation.shared_secret))
        .map_err(crypto_error_from_kem_encapsulation_operation_error)
}

/// Deterministically encapsulate to an ML-KEM-1024 public key for conformance.
#[cfg(feature = "test-vectors")]
pub fn ml_kem_1024_encapsulate_derand(
    public_key: &[u8],
    randomness: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    crate::operations::kem::encapsulate_derand(Algorithm::MlKem1024, public_key, randomness)
        .map(|encapsulation| (encapsulation.ciphertext, encapsulation.shared_secret))
        .map_err(crypto_error_from_kem_encapsulation_operation_error)
}

/// Decapsulate an ML-KEM-1024 ciphertext.
pub fn ml_kem_1024_decapsulate(
    ciphertext: &[u8],
    secret_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    crate::operations::kem::decapsulate(Algorithm::MlKem1024, ciphertext, secret_key)
        .map_err(crypto_error_from_kem_decapsulation_operation_error)
}
