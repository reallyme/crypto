// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! ML-KEM-512 root facade routed through the KEM operation layer.

use crypto_core::{Algorithm, CryptoError};
use zeroize::Zeroizing;

use crate::kem_error::{
    crypto_error_from_kem_decapsulation_operation_error,
    crypto_error_from_kem_encapsulation_operation_error,
    crypto_error_from_kem_key_generation_operation_error,
};

pub use crypto_ml_kem_512::{ML_KEM_512_PUBLIC_KEY_LEN, ML_KEM_512_SECRET_KEY_LEN};

/// Generate an ML-KEM-512 keypair through the KEM operation owner.
pub fn generate_ml_kem_512_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    crate::operations::kem::generate_key_pair(Algorithm::MlKem512)
        .map(|key_pair| (key_pair.public_key, key_pair.secret_key))
        .map_err(crypto_error_from_kem_key_generation_operation_error)
}

/// Reconstruct an ML-KEM-512 keypair from a 64-byte FIPS 203 seed.
pub fn generate_ml_kem_512_keypair_from_seed(
    seed: &[u8; ML_KEM_512_SECRET_KEY_LEN],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    crate::operations::kem::derive_key_pair(Algorithm::MlKem512, seed)
        .map(|key_pair| (key_pair.public_key, key_pair.secret_key))
        .map_err(crypto_error_from_kem_key_generation_operation_error)
}

/// Encapsulate to an ML-KEM-512 public key.
pub fn ml_kem_512_encapsulate(
    public_key: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    crate::operations::kem::encapsulate(Algorithm::MlKem512, public_key)
        .map(|encapsulation| (encapsulation.ciphertext, encapsulation.shared_secret))
        .map_err(crypto_error_from_kem_encapsulation_operation_error)
}

/// Deterministically encapsulate to an ML-KEM-512 public key for conformance.
#[cfg(feature = "test-vectors")]
pub fn ml_kem_512_encapsulate_derand(
    public_key: &[u8],
    randomness: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    crate::operations::kem::encapsulate_derand(Algorithm::MlKem512, public_key, randomness)
        .map(|encapsulation| (encapsulation.ciphertext, encapsulation.shared_secret))
        .map_err(crypto_error_from_kem_encapsulation_operation_error)
}

/// Decapsulate an ML-KEM-512 ciphertext.
pub fn ml_kem_512_decapsulate(
    ciphertext: &[u8],
    secret_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    crate::operations::kem::decapsulate(Algorithm::MlKem512, ciphertext, secret_key)
        .map_err(crypto_error_from_kem_decapsulation_operation_error)
}
