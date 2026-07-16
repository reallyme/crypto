// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::constants::{
    AES_256_GCM_SIV_KEY_LENGTH, AES_256_GCM_SIV_NONCE_LENGTH, AES_256_GCM_SIV_TAG_LENGTH,
};

/// AES-256-GCM-SIV key material.
///
/// Enforces key length at construction and zeroizes its bytes on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Aes256GcmSivKey {
    bytes: [u8; AES_256_GCM_SIV_KEY_LENGTH],
}

impl Aes256GcmSivKey {
    /// Constructs a key from raw bytes, returning an error unless the input is
    /// exactly [`AES_256_GCM_SIV_KEY_LENGTH`] bytes.
    pub fn from_slice(input: &[u8]) -> Result<Self, CryptoError> {
        if input.len() != AES_256_GCM_SIV_KEY_LENGTH {
            return Err(CryptoError::InvalidAeadKeyLength {
                expected: AES_256_GCM_SIV_KEY_LENGTH,
                actual: input.len(),
            });
        }

        let mut bytes = [0u8; AES_256_GCM_SIV_KEY_LENGTH];
        bytes.copy_from_slice(input);
        Ok(Self { bytes })
    }

    /// Returns a reference to the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; AES_256_GCM_SIV_KEY_LENGTH] {
        &self.bytes
    }
}

/// AES-256-GCM-SIV nonce material.
///
/// GCM-SIV is nonce-misuse resistant: reusing a `(key, nonce)` pair does not
/// catastrophically break confidentiality, though distinct nonces are still
/// recommended. This type validates only the [`AES_256_GCM_SIV_NONCE_LENGTH`]
/// byte length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aes256GcmSivNonce {
    bytes: [u8; AES_256_GCM_SIV_NONCE_LENGTH],
}

impl Aes256GcmSivNonce {
    /// Constructs a nonce from raw bytes, returning an error unless the input
    /// is exactly [`AES_256_GCM_SIV_NONCE_LENGTH`] bytes.
    pub fn from_slice(input: &[u8]) -> Result<Self, CryptoError> {
        if input.len() != AES_256_GCM_SIV_NONCE_LENGTH {
            return Err(CryptoError::InvalidAeadNonceLength {
                expected: AES_256_GCM_SIV_NONCE_LENGTH,
                actual: input.len(),
            });
        }

        let mut bytes = [0u8; AES_256_GCM_SIV_NONCE_LENGTH];
        bytes.copy_from_slice(input);
        Ok(Self { bytes })
    }

    /// Returns a reference to the raw nonce bytes.
    pub fn as_bytes(&self) -> &[u8; AES_256_GCM_SIV_NONCE_LENGTH] {
        &self.bytes
    }
}

/// Authenticated ciphertext container storing `ciphertext || tag`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiphertextWithTag {
    bytes: Vec<u8>,
}

impl CiphertextWithTag {
    /// Wraps a `ciphertext || tag` byte vector, returning an error unless it is
    /// at least [`AES_256_GCM_SIV_TAG_LENGTH`] bytes (enough to hold the tag).
    pub fn from_vec(input: Vec<u8>) -> Result<Self, CryptoError> {
        if input.len() < AES_256_GCM_SIV_TAG_LENGTH {
            return Err(CryptoError::InvalidCiphertextLength {
                minimum: AES_256_GCM_SIV_TAG_LENGTH,
                actual: input.len(),
            });
        }

        Ok(Self { bytes: input })
    }

    /// Returns a reference to the raw `ciphertext || tag` bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the container, returning the owned `ciphertext || tag` bytes.
    pub fn into_vec(self) -> Vec<u8> {
        self.bytes
    }
}

/// Inputs for a single AES-256-GCM-SIV encryption operation.
pub struct EncryptRequest<'a> {
    /// Encryption key.
    pub key: &'a Aes256GcmSivKey,
    /// Nonce for this operation.
    pub nonce: Aes256GcmSivNonce,
    /// Additional authenticated data, authenticated but not encrypted.
    pub aad: &'a [u8],
    /// Plaintext to encrypt.
    pub plaintext: &'a [u8],
}

/// Inputs for a single AES-256-GCM-SIV decryption operation.
pub struct DecryptRequest<'a> {
    /// Decryption key.
    pub key: &'a Aes256GcmSivKey,
    /// Nonce that was used to produce the ciphertext.
    pub nonce: Aes256GcmSivNonce,
    /// Additional authenticated data that must match what was authenticated.
    pub aad: &'a [u8],
    /// Authenticated `ciphertext || tag` to decrypt and verify.
    pub ciphertext: &'a CiphertextWithTag,
}
