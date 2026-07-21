// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::constants::{
    AEAD_NONCE_12_LENGTH, AES_256_GCM_KEY_LENGTH, ARGON2_SALT_16_LENGTH, ARGON2_SALT_32_LENGTH,
    ML_DSA_87_SEED_LENGTH, ML_KEM_1024_SEED_LENGTH,
};

/// A randomly generated 12-byte AEAD nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AeadNonce12([u8; AEAD_NONCE_12_LENGTH]);

impl AeadNonce12 {
    /// Returns a reference to the raw nonce bytes.
    pub const fn as_bytes(&self) -> &[u8; AEAD_NONCE_12_LENGTH] {
        &self.0
    }

    pub(crate) fn from_array(bytes: [u8; AEAD_NONCE_12_LENGTH]) -> Self {
        Self(bytes)
    }
}

/// A randomly generated 16-byte Argon2 salt.
///
/// Argon2 salts can become stable account-correlating identifiers. This owner
/// therefore clears its bytes on drop and never exposes them through `Debug`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Argon2Salt16([u8; ARGON2_SALT_16_LENGTH]);

impl PartialEq for Argon2Salt16 {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl Eq for Argon2Salt16 {}

impl core::hash::Hash for Argon2Salt16 {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        core::hash::Hash::hash(&self.0, state);
    }
}

impl Argon2Salt16 {
    /// Returns a reference to the raw salt bytes.
    pub const fn as_bytes(&self) -> &[u8; ARGON2_SALT_16_LENGTH] {
        &self.0
    }

    pub(crate) fn from_array(bytes: [u8; ARGON2_SALT_16_LENGTH]) -> Self {
        Self(bytes)
    }
}

impl core::fmt::Debug for Argon2Salt16 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Argon2Salt16(<redacted>)")
    }
}

/// A randomly generated 32-byte Argon2 salt.
///
/// Argon2 salts can become stable account-correlating identifiers. This owner
/// therefore clears its bytes on drop and never exposes them through `Debug`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Argon2Salt32([u8; ARGON2_SALT_32_LENGTH]);

impl PartialEq for Argon2Salt32 {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl Eq for Argon2Salt32 {}

impl core::hash::Hash for Argon2Salt32 {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        core::hash::Hash::hash(&self.0, state);
    }
}

impl Argon2Salt32 {
    /// Returns a reference to the raw salt bytes.
    pub const fn as_bytes(&self) -> &[u8; ARGON2_SALT_32_LENGTH] {
        &self.0
    }

    pub(crate) fn from_array(bytes: [u8; ARGON2_SALT_32_LENGTH]) -> Self {
        Self(bytes)
    }
}

impl core::fmt::Debug for Argon2Salt32 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Argon2Salt32(<redacted>)")
    }
}

/// Randomly generated AES-256-GCM key material.
///
/// This is a sensitive-security-parameter owner and zeroizes on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Aes256GcmKeyMaterial {
    bytes: SecretBox<[u8; AES_256_GCM_KEY_LENGTH]>,
}

impl Aes256GcmKeyMaterial {
    /// Returns a reference to the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; AES_256_GCM_KEY_LENGTH] {
        self.bytes.expose_secret()
    }

    /// Consumes the owner and returns the raw key bytes.
    ///
    /// The returned array is now the caller's SSP owner and must be cleared by
    /// that caller when no longer needed.
    pub fn into_bytes(mut self) -> [u8; AES_256_GCM_KEY_LENGTH] {
        let output = *self.bytes.expose_secret();
        self.bytes.zeroize();
        output
    }

    pub(crate) fn from_array(mut bytes: [u8; AES_256_GCM_KEY_LENGTH]) -> Self {
        let mut secret = SecretBox::new(Box::new([0u8; AES_256_GCM_KEY_LENGTH]));
        *secret.expose_secret_mut() = bytes;
        bytes.zeroize();
        Self { bytes: secret }
    }
}

/// Randomly generated ML-KEM-1024 FIPS 203 seed material.
///
/// This is a sensitive-security-parameter owner and zeroizes on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MlKem1024Seed {
    bytes: SecretBox<[u8; ML_KEM_1024_SEED_LENGTH]>,
}

impl MlKem1024Seed {
    /// Returns a reference to the raw seed bytes.
    pub fn as_bytes(&self) -> &[u8; ML_KEM_1024_SEED_LENGTH] {
        self.bytes.expose_secret()
    }

    /// Consumes the owner and returns the raw seed bytes.
    ///
    /// The returned array is now the caller's SSP owner and must be cleared by
    /// that caller when no longer needed.
    pub fn into_bytes(mut self) -> [u8; ML_KEM_1024_SEED_LENGTH] {
        let output = *self.bytes.expose_secret();
        self.bytes.zeroize();
        output
    }

    pub(crate) fn from_array(mut bytes: [u8; ML_KEM_1024_SEED_LENGTH]) -> Self {
        let mut secret = SecretBox::new(Box::new([0u8; ML_KEM_1024_SEED_LENGTH]));
        *secret.expose_secret_mut() = bytes;
        bytes.zeroize();
        Self { bytes: secret }
    }
}

/// Randomly generated ML-DSA-87 FIPS 204 seed material.
///
/// This is a sensitive-security-parameter owner and zeroizes on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MlDsa87Seed {
    bytes: SecretBox<[u8; ML_DSA_87_SEED_LENGTH]>,
}

impl MlDsa87Seed {
    /// Returns a reference to the raw seed bytes.
    pub fn as_bytes(&self) -> &[u8; ML_DSA_87_SEED_LENGTH] {
        self.bytes.expose_secret()
    }

    /// Consumes the owner and returns the raw seed bytes.
    ///
    /// The returned array is now the caller's SSP owner and must be cleared by
    /// that caller when no longer needed.
    pub fn into_bytes(mut self) -> [u8; ML_DSA_87_SEED_LENGTH] {
        let output = *self.bytes.expose_secret();
        self.bytes.zeroize();
        output
    }

    pub(crate) fn from_array(mut bytes: [u8; ML_DSA_87_SEED_LENGTH]) -> Self {
        let mut secret = SecretBox::new(Box::new([0u8; ML_DSA_87_SEED_LENGTH]));
        *secret.expose_secret_mut() = bytes;
        bytes.zeroize();
        Self { bytes: secret }
    }
}

/// A buffer of `N` randomly generated bytes.
///
/// Zeroizes its bytes on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RandomBytes<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> RandomBytes<N> {
    /// Returns a reference to the raw random bytes.
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Consumes the buffer, returning the owned random bytes.
    ///
    /// The returned array is no longer zeroized on drop by this type.
    pub fn into_bytes(self) -> [u8; N] {
        self.bytes
    }

    pub(crate) fn from_array(bytes: [u8; N]) -> Self {
        Self { bytes }
    }
}
