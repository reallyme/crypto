// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, KemFailureKind};
use zeroize::{Zeroize, Zeroizing};

use crate::expand::{expand_decapsulation_key, ml_kem_1024_public_key, ml_kem_768_public_key};
use crate::random::fill_random;
use crate::suite::{X25519_KEY_LEN, X_WING_SECRET_KEY_LEN};

fn compose_public_key(
    ml_kem_public_key: &[u8],
    x25519_public_key: &[u8; X25519_KEY_LEN],
) -> Result<Vec<u8>, CryptoError> {
    let capacity = ml_kem_public_key
        .len()
        .checked_add(x25519_public_key.len())
        .ok_or(CryptoError::KemFailure {
            kind: KemFailureKind::KeyGenerationFailed,
        })?;
    let mut public_key = Vec::with_capacity(capacity);
    public_key.extend_from_slice(ml_kem_public_key);
    public_key.extend_from_slice(x25519_public_key);
    Ok(public_key)
}

fn generate_keypair_derand(
    secret_key: &[u8],
    ml_kem_public_key_fn: fn(&[u8; 64]) -> Result<Vec<u8>, CryptoError>,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    if secret_key.len() != X_WING_SECRET_KEY_LEN {
        return Err(CryptoError::InvalidKey);
    }

    let expanded = expand_decapsulation_key(secret_key)?;
    let ml_kem_public_key = ml_kem_public_key_fn(&expanded.ml_kem_seed)?;
    let public_key = compose_public_key(&ml_kem_public_key, &expanded.x25519_public_key)?;
    Ok((public_key, Zeroizing::new(secret_key.to_vec())))
}

fn generate_keypair(
    ml_kem_public_key_fn: fn(&[u8; 64]) -> Result<Vec<u8>, CryptoError>,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    let mut secret_key = Zeroizing::new([0u8; X_WING_SECRET_KEY_LEN]);
    fill_random(&mut *secret_key)?;
    let result = generate_keypair_derand(&*secret_key, ml_kem_public_key_fn);
    secret_key.zeroize();
    result
}

/// Generate an X-Wing keypair using the standard ML-KEM-768 suite.
pub fn generate_x_wing_768_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    generate_keypair(ml_kem_768_public_key)
}

/// Generate an X-Wing keypair from a caller-supplied 32-byte seed.
pub fn generate_x_wing_768_keypair_derand(
    secret_key: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    generate_keypair_derand(secret_key, ml_kem_768_public_key)
}

/// Generate an X-Wing-1024 keypair using the ReallyMe ML-KEM-1024 suite.
pub fn generate_x_wing_1024_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    generate_keypair(ml_kem_1024_public_key)
}

/// Generate an X-Wing-1024 keypair from a caller-supplied 32-byte seed.
pub fn generate_x_wing_1024_keypair_derand(
    secret_key: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    generate_keypair_derand(secret_key, ml_kem_1024_public_key)
}
