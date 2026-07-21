// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! X25519 root facade with key agreement routed through the operation layer.

use crypto_core::{Algorithm, CryptoError};
use zeroize::Zeroizing;

use crate::key_agreement_error::{
    crypto_error_from_derive_shared_secret_operation_error,
    crypto_error_from_key_generation_operation_error,
};

pub use crypto_x25519::{decode_public_key, encode_public_key};

/// Generate an X25519 keypair through the key-agreement operation owner.
pub fn generate_x25519_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    crate::operations::key_agreement::generate_key_pair(Algorithm::X25519)
        .map(|key_pair| (key_pair.public_key, key_pair.secret_key))
        .map_err(crypto_error_from_key_generation_operation_error)
}

/// Reconstruct an X25519 keypair from an existing 32-byte secret seed.
pub fn generate_x25519_keypair_from_seed(
    seed: &[u8; 32],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    crate::operations::key_agreement::derive_key_pair(Algorithm::X25519, seed)
        .map(|key_pair| (key_pair.public_key, key_pair.secret_key))
        .map_err(crypto_error_from_key_generation_operation_error)
}

/// Derive the raw X25519 shared secret through the key-agreement operation owner.
pub fn derive_x25519_shared_secret(
    secret_key: &[u8],
    public_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    crate::operations::key_agreement::derive_shared_secret(
        Algorithm::X25519,
        secret_key,
        public_key,
    )
    .map_err(crypto_error_from_derive_shared_secret_operation_error)
}
