// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! X-Wing root facade routed through the KEM operation layer.

use crypto_core::{Algorithm, CryptoError};
use zeroize::Zeroizing;

use crate::kem_error::{
    crypto_error_from_kem_decapsulation_operation_error,
    crypto_error_from_kem_encapsulation_operation_error,
    crypto_error_from_kem_key_generation_operation_error,
};

pub use crypto_x_wing::{
    X_WING_768_CIPHERTEXT_LEN, X_WING_768_PUBLIC_KEY_LEN, X_WING_ENCAPS_SEED_LEN,
    X_WING_SECRET_KEY_LEN, X_WING_SHARED_SECRET_LEN,
};

/// Generate an X-Wing-768 keypair through the KEM operation owner.
pub fn generate_x_wing_768_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    crate::operations::kem::generate_key_pair(Algorithm::XWing768)
        .map(|key_pair| (key_pair.public_key, key_pair.secret_key))
        .map_err(crypto_error_from_kem_key_generation_operation_error)
}

/// Reconstruct an X-Wing-768 keypair from a caller-supplied 32-byte seed.
pub fn generate_x_wing_768_keypair_derand(
    secret_key: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    crate::operations::kem::derive_key_pair(Algorithm::XWing768, secret_key)
        .map(|key_pair| (key_pair.public_key, key_pair.secret_key))
        .map_err(crypto_error_from_kem_key_generation_operation_error)
}

/// Encapsulate to an X-Wing-768 public key through the KEM operation owner.
pub fn x_wing_768_encapsulate(
    public_key: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    crate::operations::kem::encapsulate(Algorithm::XWing768, public_key)
        .map(|encapsulation| (encapsulation.ciphertext, encapsulation.shared_secret))
        .map_err(crypto_error_from_kem_encapsulation_operation_error)
}

/// Deterministically encapsulate to an X-Wing-768 public key for conformance.
#[cfg(feature = "test-vectors")]
pub fn x_wing_768_encapsulate_derand(
    public_key: &[u8],
    seed: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    crate::operations::kem::encapsulate_derand(Algorithm::XWing768, public_key, seed)
        .map(|encapsulation| (encapsulation.ciphertext, encapsulation.shared_secret))
        .map_err(crypto_error_from_kem_encapsulation_operation_error)
}

/// Decapsulate an X-Wing-768 ciphertext through the KEM operation owner.
pub fn x_wing_768_decapsulate(
    ciphertext: &[u8],
    secret_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    crate::operations::kem::decapsulate(Algorithm::XWing768, ciphertext, secret_key)
        .map_err(crypto_error_from_kem_decapsulation_operation_error)
}
