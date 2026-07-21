// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use x448::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{X448_PRIVATE_KEY_LEN, X448_PUBLIC_KEY_LEN, X448_SHARED_SECRET_LEN};

/// An X448 private scalar with zeroize-on-drop ownership.
pub struct X448PrivateKey(StaticSecret);

impl X448PrivateKey {
    /// Imports a fixed-size scalar. X448 clamping is applied by the backend.
    pub fn from_array(bytes: [u8; X448_PRIVATE_KEY_LEN]) -> Self {
        Self(StaticSecret::from(bytes))
    }

    /// Imports a 56-byte scalar. X448 clamping is applied by the backend.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let scalar =
            <[u8; X448_PRIVATE_KEY_LEN]>::try_from(bytes).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self::from_array(scalar))
    }

    /// Exposes the scalar to protocol adapters that must serialize HPKE keys.
    pub fn as_bytes(&self) -> &[u8; X448_PRIVATE_KEY_LEN] {
        self.0.as_bytes()
    }

    pub(crate) fn backend(&self) -> &StaticSecret {
        &self.0
    }
}

impl Zeroize for X448PrivateKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for X448PrivateKey {}

/// A validated X448 public u-coordinate.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct X448PublicKey([u8; X448_PUBLIC_KEY_LEN]);

impl X448PublicKey {
    /// Imports a public key and rejects low-order points.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let encoded =
            <[u8; X448_PUBLIC_KEY_LEN]>::try_from(bytes).map_err(|_| CryptoError::InvalidKey)?;
        PublicKey::from_bytes(&encoded).ok_or(CryptoError::InvalidKey)?;
        Ok(Self(encoded))
    }

    /// Returns the RFC 7748 wire representation.
    pub const fn as_bytes(&self) -> &[u8; X448_PUBLIC_KEY_LEN] {
        &self.0
    }

    pub(crate) fn backend(&self) -> Result<PublicKey, CryptoError> {
        PublicKey::from_bytes(&self.0).ok_or(CryptoError::InvalidKey)
    }
}

impl core::fmt::Debug for X448PublicKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("X448PublicKey(<redacted>)")
    }
}

impl From<&X448PrivateKey> for X448PublicKey {
    fn from(private_key: &X448PrivateKey) -> Self {
        let public_key = PublicKey::from(private_key.backend());
        Self(*public_key.as_bytes())
    }
}

/// A raw X448 shared secret with zeroize-on-drop ownership.
pub struct X448SharedSecret([u8; X448_SHARED_SECRET_LEN]);

impl X448SharedSecret {
    pub(crate) const fn from_array(bytes: [u8; X448_SHARED_SECRET_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrows the raw secret without copying it.
    pub const fn as_bytes(&self) -> &[u8; X448_SHARED_SECRET_LEN] {
        &self.0
    }
}

impl Zeroize for X448SharedSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for X448SharedSecret {}
