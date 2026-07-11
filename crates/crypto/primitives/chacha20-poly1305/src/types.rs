// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length in bytes of a ChaCha20-Poly1305 key (32 bytes / 256 bits).
pub const CHACHA20_POLY1305_KEY_LENGTH: usize = 32;
/// Length in bytes of an RFC 8439 ChaCha20-Poly1305 nonce (96 bits).
pub const CHACHA20_POLY1305_NONCE_LENGTH: usize = 12;
/// Length in bytes of an XChaCha20-Poly1305 nonce (192 bits).
pub const XCHACHA20_POLY1305_NONCE_LENGTH: usize = 24;
/// Length in bytes of a Poly1305 authentication tag (128 bits).
pub const CHACHA20_POLY1305_TAG_LENGTH: usize = 16;

/// ChaCha20-Poly1305 key material.
///
/// This type owns the secret key bytes so they are zeroized at drop and so
/// callers cannot accidentally pass an unchecked arbitrary-length buffer.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ChaCha20Poly1305Key {
    bytes: [u8; CHACHA20_POLY1305_KEY_LENGTH],
}

impl ChaCha20Poly1305Key {
    /// Constructs a key from raw bytes, returning an error unless the input is
    /// exactly [`CHACHA20_POLY1305_KEY_LENGTH`] bytes.
    pub fn from_slice(input: &[u8]) -> Result<Self, CryptoError> {
        if input.len() != CHACHA20_POLY1305_KEY_LENGTH {
            return Err(CryptoError::InvalidAeadKeyLength {
                expected: CHACHA20_POLY1305_KEY_LENGTH,
                actual: input.len(),
            });
        }

        let mut bytes = [0u8; CHACHA20_POLY1305_KEY_LENGTH];
        bytes.copy_from_slice(input);
        Ok(Self { bytes })
    }

    /// Returns a reference to the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; CHACHA20_POLY1305_KEY_LENGTH] {
        &self.bytes
    }
}

/// RFC 8439 ChaCha20-Poly1305 nonce material.
///
/// # Caller contract: nonce uniqueness
///
/// Reusing a `(key, nonce)` pair breaks confidentiality and authenticity for
/// ChaCha20-Poly1305. This wrapper validates the 96-bit nonce shape only; the
/// caller must ensure every encryption under a key uses a distinct nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChaCha20Poly1305Nonce {
    bytes: [u8; CHACHA20_POLY1305_NONCE_LENGTH],
}

impl ChaCha20Poly1305Nonce {
    /// Constructs a nonce from raw bytes, returning an error unless the input
    /// is exactly [`CHACHA20_POLY1305_NONCE_LENGTH`] bytes.
    pub fn from_slice(input: &[u8]) -> Result<Self, CryptoError> {
        if input.len() != CHACHA20_POLY1305_NONCE_LENGTH {
            return Err(CryptoError::InvalidAeadNonceLength {
                expected: CHACHA20_POLY1305_NONCE_LENGTH,
                actual: input.len(),
            });
        }

        let mut bytes = [0u8; CHACHA20_POLY1305_NONCE_LENGTH];
        bytes.copy_from_slice(input);
        Ok(Self { bytes })
    }

    /// Returns a reference to the raw nonce bytes.
    pub fn as_bytes(&self) -> &[u8; CHACHA20_POLY1305_NONCE_LENGTH] {
        &self.bytes
    }
}

/// XChaCha20-Poly1305 nonce material.
///
/// XChaCha's 192-bit nonce is suitable for random nonce generation at high
/// volume, but reuse under the same key is still forbidden.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XChaCha20Poly1305Nonce {
    bytes: [u8; XCHACHA20_POLY1305_NONCE_LENGTH],
}

impl XChaCha20Poly1305Nonce {
    /// Constructs an XChaCha nonce from raw bytes, returning an error unless
    /// the input is exactly [`XCHACHA20_POLY1305_NONCE_LENGTH`] bytes.
    pub fn from_slice(input: &[u8]) -> Result<Self, CryptoError> {
        if input.len() != XCHACHA20_POLY1305_NONCE_LENGTH {
            return Err(CryptoError::InvalidAeadNonceLength {
                expected: XCHACHA20_POLY1305_NONCE_LENGTH,
                actual: input.len(),
            });
        }

        let mut bytes = [0u8; XCHACHA20_POLY1305_NONCE_LENGTH];
        bytes.copy_from_slice(input);
        Ok(Self { bytes })
    }

    /// Returns a reference to the raw nonce bytes.
    pub fn as_bytes(&self) -> &[u8; XCHACHA20_POLY1305_NONCE_LENGTH] {
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
    /// at least [`CHACHA20_POLY1305_TAG_LENGTH`] bytes.
    pub fn from_vec(input: Vec<u8>) -> Result<Self, CryptoError> {
        if input.len() < CHACHA20_POLY1305_TAG_LENGTH {
            return Err(CryptoError::InvalidCiphertextLength {
                minimum: CHACHA20_POLY1305_TAG_LENGTH,
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

/// Inputs for a single ChaCha20-Poly1305 encryption operation.
pub struct EncryptRequest<'a> {
    /// Encryption key.
    pub key: &'a ChaCha20Poly1305Key,
    /// RFC 8439 nonce; must be unique per key.
    pub nonce: ChaCha20Poly1305Nonce,
    /// Additional authenticated data, authenticated but not encrypted.
    pub aad: &'a [u8],
    /// Plaintext to encrypt.
    pub plaintext: &'a [u8],
}

/// Inputs for a single ChaCha20-Poly1305 decryption operation.
pub struct DecryptRequest<'a> {
    /// Decryption key.
    pub key: &'a ChaCha20Poly1305Key,
    /// Nonce that was used to produce the ciphertext.
    pub nonce: ChaCha20Poly1305Nonce,
    /// Additional authenticated data that must match what was authenticated.
    pub aad: &'a [u8],
    /// Authenticated `ciphertext || tag` to decrypt and verify.
    pub ciphertext: &'a CiphertextWithTag,
}

/// Inputs for a single XChaCha20-Poly1305 encryption operation.
pub struct XChaCha20Poly1305EncryptRequest<'a> {
    /// Encryption key.
    pub key: &'a ChaCha20Poly1305Key,
    /// XChaCha nonce; must be unique per key.
    pub nonce: XChaCha20Poly1305Nonce,
    /// Additional authenticated data, authenticated but not encrypted.
    pub aad: &'a [u8],
    /// Plaintext to encrypt.
    pub plaintext: &'a [u8],
}

/// Inputs for a single XChaCha20-Poly1305 decryption operation.
pub struct XChaCha20Poly1305DecryptRequest<'a> {
    /// Decryption key.
    pub key: &'a ChaCha20Poly1305Key,
    /// Nonce that was used to produce the ciphertext.
    pub nonce: XChaCha20Poly1305Nonce,
    /// Additional authenticated data that must match what was authenticated.
    pub aad: &'a [u8],
    /// Authenticated `ciphertext || tag` to decrypt and verify.
    pub ciphertext: &'a CiphertextWithTag,
}
