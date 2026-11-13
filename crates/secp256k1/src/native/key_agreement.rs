// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::CryptoError;
use k256::ecdh::diffie_hellman;
use k256::{PublicKey, SecretKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

const SECP256K1_UNCOMPRESSED_PUBLIC_KEY_LEN: usize =
    crypto_core::contract_constants::secp256k1::SECP256K1_UNCOMPRESSED_PUBLIC_KEY_LEN;
const SECP256K1_SHARED_SECRET_LEN: usize =
    crypto_core::contract_constants::secp256k1::SECP256K1_SHARED_SECRET_LEN;
const SEC1_UNCOMPRESSED_POINT_TAG: u8 = 0x04;

/// A raw secp256k1 ECDH x-coordinate with zeroize-on-drop ownership.
pub struct Secp256k1SharedSecret([u8; SECP256K1_SHARED_SECRET_LEN]);

impl Secp256k1SharedSecret {
    /// Borrows the raw secret without copying it.
    pub const fn as_bytes(&self) -> &[u8; SECP256K1_SHARED_SECRET_LEN] {
        &self.0
    }
}

impl Zeroize for Secp256k1SharedSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// This owner contains a plain array, so a marker alone does not clear it.
// Keep actual destruction adjacent to the explicit clearing implementation.
impl Drop for Secp256k1SharedSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Secp256k1SharedSecret {}

/// Derives a raw secp256k1 ECDH shared secret for HPKE-style protocols.
///
/// Public keys must use the 65-byte uncompressed SEC1 representation required
/// by the registered DHKEM. Parsing validates curve membership and rejects the
/// point at infinity before scalar multiplication.
pub fn derive_secp256k1_shared_secret(
    private_key: &[u8],
    public_key: &[u8],
) -> Result<Secp256k1SharedSecret, CryptoError> {
    if private_key.len() != SECP256K1_SHARED_SECRET_LEN {
        return Err(CryptoError::PRIMITIVE_INVALID_KEY);
    }
    if public_key.len() != SECP256K1_UNCOMPRESSED_PUBLIC_KEY_LEN
        || public_key.first().copied() != Some(SEC1_UNCOMPRESSED_POINT_TAG)
    {
        return Err(CryptoError::PRIMITIVE_INVALID_KEY);
    }

    let secret_key =
        SecretKey::from_slice(private_key).map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;
    let public_key =
        PublicKey::from_sec1_bytes(public_key).map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;
    let shared_secret = diffie_hellman(secret_key.to_nonzero_scalar(), public_key.as_affine());
    // Initialize the final clearing owner before copying the raw x-coordinate.
    // The backend owner and returned owner then each clear their own storage.
    let mut output = Secp256k1SharedSecret([0_u8; SECP256K1_SHARED_SECRET_LEN]);
    output.0.copy_from_slice(shared_secret.raw_secret_bytes());
    Ok(output)
}

#[cfg(test)]
#[path = "key_agreement_ownership_tests.rs"]
mod ownership_tests;
