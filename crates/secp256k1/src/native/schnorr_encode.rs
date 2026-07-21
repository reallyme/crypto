// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::{BIP340_SCHNORR_PUBLIC_KEY_LEN, SECP256K1_SECRET_KEY_LEN};
use crypto_core::CryptoError;
use k256::schnorr::{SigningKey, VerifyingKey};

/// Derive the BIP-340 x-only public key for a secp256k1 secret scalar.
pub fn derive_bip340_schnorr_public_key(secret_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if secret_key.len() != SECP256K1_SECRET_KEY_LEN {
        return Err(CryptoError::InvalidKey);
    }
    let signing_key = SigningKey::from_slice(secret_key).map_err(|_| CryptoError::InvalidKey)?;
    Ok(signing_key.verifying_key().to_bytes().to_vec())
}

fn validate_bip340_public_key(public_key: &[u8]) -> Result<(), CryptoError> {
    if public_key.len() != BIP340_SCHNORR_PUBLIC_KEY_LEN {
        return Err(CryptoError::InvalidKey);
    }
    VerifyingKey::from_slice(public_key).map_err(|_| CryptoError::InvalidKey)?;
    Ok(())
}

/// Encode a BIP-340 x-only public key after validating its canonical shape.
pub fn encode_bip340_schnorr_public_key(public_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    validate_bip340_public_key(public_key)?;
    Ok(public_key.to_vec())
}

/// Decode a BIP-340 x-only public key after validating its canonical shape.
pub fn decode_bip340_schnorr_public_key(public_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    validate_bip340_public_key(public_key)?;
    Ok(public_key.to_vec())
}
