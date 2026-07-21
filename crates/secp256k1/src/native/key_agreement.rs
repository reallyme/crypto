// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use k256::ecdh::diffie_hellman;
use k256::{PublicKey, SecretKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

const SECP256K1_UNCOMPRESSED_PUBLIC_KEY_LEN: usize = 65;
const SECP256K1_SHARED_SECRET_LEN: usize = 32;
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
    if public_key.len() != SECP256K1_UNCOMPRESSED_PUBLIC_KEY_LEN
        || public_key.first().copied() != Some(SEC1_UNCOMPRESSED_POINT_TAG)
    {
        return Err(CryptoError::InvalidKey);
    }

    let secret_key = SecretKey::from_slice(private_key).map_err(|_| CryptoError::InvalidKey)?;
    let public_key = PublicKey::from_sec1_bytes(public_key).map_err(|_| CryptoError::InvalidKey)?;
    let shared_secret = diffie_hellman(secret_key.to_nonzero_scalar(), public_key.as_affine());
    let mut bytes = [0_u8; SECP256K1_SHARED_SECRET_LEN];
    bytes.copy_from_slice(shared_secret.raw_secret_bytes());
    Ok(Secp256k1SharedSecret(bytes))
}
