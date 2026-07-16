// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length in bytes of an AES-256-GCM key (32 bytes / 256 bits).
pub const AES_256_GCM_KEY_LENGTH: usize = 32;
/// Length in bytes of an AES-128-GCM key (16 bytes / 128 bits).
pub const AES_128_GCM_KEY_LENGTH: usize = 16;
/// Length in bytes of an AES-192-GCM key (24 bytes / 192 bits).
pub const AES_192_GCM_KEY_LENGTH: usize = 24;
/// Length in bytes of an AES-256-GCM nonce (12 bytes / 96 bits).
pub const AES_256_GCM_NONCE_LENGTH: usize = 12;
/// Length in bytes of an AES-128-GCM nonce (12 bytes / 96 bits).
pub const AES_128_GCM_NONCE_LENGTH: usize = AES_256_GCM_NONCE_LENGTH;
/// Length in bytes of an AES-192-GCM nonce (12 bytes / 96 bits).
pub const AES_192_GCM_NONCE_LENGTH: usize = AES_256_GCM_NONCE_LENGTH;
/// Length in bytes of an AES-256-GCM authentication tag (16 bytes / 128 bits).
pub const AES_256_GCM_TAG_LENGTH: usize = 16;
/// Length in bytes of an AES-128-GCM authentication tag (16 bytes / 128 bits).
pub const AES_128_GCM_TAG_LENGTH: usize = AES_256_GCM_TAG_LENGTH;
/// Length in bytes of an AES-192-GCM authentication tag (16 bytes / 128 bits).
pub const AES_192_GCM_TAG_LENGTH: usize = AES_256_GCM_TAG_LENGTH;

/// AES-128 key material.
///
/// This type exists to enforce key length at construction boundaries and to
/// guarantee key bytes are zeroized when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Aes128GcmKey {
    bytes: [u8; AES_128_GCM_KEY_LENGTH],
}

impl Aes128GcmKey {
    /// Constructs a key from raw bytes, returning an error unless the input is
    /// exactly [`AES_128_GCM_KEY_LENGTH`] bytes.
    pub fn from_slice(input: &[u8]) -> Result<Self, CryptoError> {
        if input.len() != AES_128_GCM_KEY_LENGTH {
            return Err(CryptoError::InvalidAeadKeyLength {
                expected: AES_128_GCM_KEY_LENGTH,
                actual: input.len(),
            });
        }

        let mut bytes = [0u8; AES_128_GCM_KEY_LENGTH];
        bytes.copy_from_slice(input);
        Ok(Self { bytes })
    }

    /// Returns a reference to the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; AES_128_GCM_KEY_LENGTH] {
        &self.bytes
    }
}

/// AES-192 key material.
///
/// This type exists to enforce key length at construction boundaries and to
/// guarantee key bytes are zeroized when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Aes192GcmKey {
    bytes: [u8; AES_192_GCM_KEY_LENGTH],
}

impl Aes192GcmKey {
    /// Constructs a key from raw bytes, returning an error unless the input is
    /// exactly [`AES_192_GCM_KEY_LENGTH`] bytes.
    pub fn from_slice(input: &[u8]) -> Result<Self, CryptoError> {
        if input.len() != AES_192_GCM_KEY_LENGTH {
            return Err(CryptoError::InvalidAeadKeyLength {
                expected: AES_192_GCM_KEY_LENGTH,
                actual: input.len(),
            });
        }

        let mut bytes = [0u8; AES_192_GCM_KEY_LENGTH];
        bytes.copy_from_slice(input);
        Ok(Self { bytes })
    }

    /// Returns a reference to the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; AES_192_GCM_KEY_LENGTH] {
        &self.bytes
    }
}

/// AES-256 key material.
///
/// This type exists to enforce key length at construction boundaries and to
/// guarantee key bytes are zeroized when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Aes256GcmKey {
    bytes: [u8; AES_256_GCM_KEY_LENGTH],
}

impl Aes256GcmKey {
    /// Constructs a key from raw bytes, returning an error unless the input is
    /// exactly [`AES_256_GCM_KEY_LENGTH`] bytes.
    pub fn from_slice(input: &[u8]) -> Result<Self, CryptoError> {
        if input.len() != AES_256_GCM_KEY_LENGTH {
            return Err(CryptoError::InvalidAeadKeyLength {
                expected: AES_256_GCM_KEY_LENGTH,
                actual: input.len(),
            });
        }

        let mut bytes = [0u8; AES_256_GCM_KEY_LENGTH];
        bytes.copy_from_slice(input);
        Ok(Self { bytes })
    }

    /// Returns a reference to the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; AES_256_GCM_KEY_LENGTH] {
        &self.bytes
    }
}

/// AES-128-GCM nonce material.
///
/// # Caller contract: nonce uniqueness
///
/// AES-GCM catastrophically fails under nonce reuse. This type validates only
/// the 12-byte length; callers MUST guarantee a given `(key, nonce)` pair is
/// never used to encrypt more than once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aes128GcmNonce {
    bytes: [u8; AES_128_GCM_NONCE_LENGTH],
}

impl Aes128GcmNonce {
    /// Constructs a nonce from raw bytes, returning an error unless the input
    /// is exactly [`AES_128_GCM_NONCE_LENGTH`] bytes.
    pub fn from_slice(input: &[u8]) -> Result<Self, CryptoError> {
        if input.len() != AES_128_GCM_NONCE_LENGTH {
            return Err(CryptoError::InvalidAeadNonceLength {
                expected: AES_128_GCM_NONCE_LENGTH,
                actual: input.len(),
            });
        }

        let mut bytes = [0u8; AES_128_GCM_NONCE_LENGTH];
        bytes.copy_from_slice(input);
        Ok(Self { bytes })
    }

    /// Returns a reference to the raw nonce bytes.
    pub fn as_bytes(&self) -> &[u8; AES_128_GCM_NONCE_LENGTH] {
        &self.bytes
    }
}

/// AES-192-GCM nonce material.
///
/// # Caller contract: nonce uniqueness
///
/// AES-GCM catastrophically fails under nonce reuse. This type validates only
/// the 12-byte length; callers MUST guarantee a given `(key, nonce)` pair is
/// never used to encrypt more than once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aes192GcmNonce {
    bytes: [u8; AES_192_GCM_NONCE_LENGTH],
}

impl Aes192GcmNonce {
    /// Constructs a nonce from raw bytes, returning an error unless the input
    /// is exactly [`AES_192_GCM_NONCE_LENGTH`] bytes.
    pub fn from_slice(input: &[u8]) -> Result<Self, CryptoError> {
        if input.len() != AES_192_GCM_NONCE_LENGTH {
            return Err(CryptoError::InvalidAeadNonceLength {
                expected: AES_192_GCM_NONCE_LENGTH,
                actual: input.len(),
            });
        }

        let mut bytes = [0u8; AES_192_GCM_NONCE_LENGTH];
        bytes.copy_from_slice(input);
        Ok(Self { bytes })
    }

    /// Returns a reference to the raw nonce bytes.
    pub fn as_bytes(&self) -> &[u8; AES_192_GCM_NONCE_LENGTH] {
        &self.bytes
    }
}

/// AES-GCM nonce material.
///
/// # Caller contract: nonce uniqueness
///
/// AES-256-GCM catastrophically fails under nonce reuse: encrypting two
/// different plaintexts with the same `(key, nonce)` pair leaks the XOR of
/// the plaintexts and, worse, allows forgery of further ciphertexts under
/// that key. This type validates only the 12-byte length; it deliberately
/// does not — and cannot — enforce uniqueness. The caller MUST guarantee a
/// given `(key, nonce)` pair is never used to encrypt more than once, e.g.
/// via a random 96-bit nonce from a CSPRNG or a strictly monotonic counter.
/// If uniqueness cannot be guaranteed, use `Aes256GcmSiv` (nonce-misuse
/// resistant) instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aes256GcmNonce {
    bytes: [u8; AES_256_GCM_NONCE_LENGTH],
}

impl Aes256GcmNonce {
    /// Constructs a nonce from raw bytes, returning an error unless the input
    /// is exactly [`AES_256_GCM_NONCE_LENGTH`] bytes. Validates length only,
    /// not uniqueness (see the type-level nonce-reuse contract).
    pub fn from_slice(input: &[u8]) -> Result<Self, CryptoError> {
        if input.len() != AES_256_GCM_NONCE_LENGTH {
            return Err(CryptoError::InvalidAeadNonceLength {
                expected: AES_256_GCM_NONCE_LENGTH,
                actual: input.len(),
            });
        }

        let mut bytes = [0u8; AES_256_GCM_NONCE_LENGTH];
        bytes.copy_from_slice(input);
        Ok(Self { bytes })
    }

    /// Returns a reference to the raw nonce bytes.
    pub fn as_bytes(&self) -> &[u8; AES_256_GCM_NONCE_LENGTH] {
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
    /// at least [`AES_256_GCM_TAG_LENGTH`] bytes (enough to hold the tag).
    pub fn from_vec(input: Vec<u8>) -> Result<Self, CryptoError> {
        if input.len() < AES_256_GCM_TAG_LENGTH {
            return Err(CryptoError::InvalidCiphertextLength {
                minimum: AES_256_GCM_TAG_LENGTH,
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

/// Inputs for a single AES-256-GCM encryption operation.
pub struct EncryptRequest<'a> {
    /// Encryption key.
    pub key: &'a Aes256GcmKey,
    /// Nonce; must be unique per key (see [`Aes256GcmNonce`]).
    pub nonce: Aes256GcmNonce,
    /// Additional authenticated data, authenticated but not encrypted.
    pub aad: &'a [u8],
    /// Plaintext to encrypt.
    pub plaintext: &'a [u8],
}

/// Inputs for a single AES-256-GCM decryption operation.
pub struct DecryptRequest<'a> {
    /// Decryption key.
    pub key: &'a Aes256GcmKey,
    /// Nonce that was used to produce the ciphertext.
    pub nonce: Aes256GcmNonce,
    /// Additional authenticated data that must match what was authenticated.
    pub aad: &'a [u8],
    /// Authenticated `ciphertext || tag` to decrypt and verify.
    pub ciphertext: &'a CiphertextWithTag,
}

/// Inputs for a single AES-128-GCM encryption operation.
pub struct Aes128GcmEncryptRequest<'a> {
    /// Encryption key.
    pub key: &'a Aes128GcmKey,
    /// Nonce; must be unique per key (see [`Aes128GcmNonce`]).
    pub nonce: Aes128GcmNonce,
    /// Additional authenticated data, authenticated but not encrypted.
    pub aad: &'a [u8],
    /// Plaintext to encrypt.
    pub plaintext: &'a [u8],
}

/// Inputs for a single AES-128-GCM decryption operation.
pub struct Aes128GcmDecryptRequest<'a> {
    /// Decryption key.
    pub key: &'a Aes128GcmKey,
    /// Nonce that was used to produce the ciphertext.
    pub nonce: Aes128GcmNonce,
    /// Additional authenticated data that must match what was authenticated.
    pub aad: &'a [u8],
    /// Authenticated `ciphertext || tag` to decrypt and verify.
    pub ciphertext: &'a CiphertextWithTag,
}

/// Inputs for a single AES-192-GCM encryption operation.
pub struct Aes192GcmEncryptRequest<'a> {
    /// Encryption key.
    pub key: &'a Aes192GcmKey,
    /// Nonce; must be unique per key (see [`Aes192GcmNonce`]).
    pub nonce: Aes192GcmNonce,
    /// Additional authenticated data, authenticated but not encrypted.
    pub aad: &'a [u8],
    /// Plaintext to encrypt.
    pub plaintext: &'a [u8],
}

/// Inputs for a single AES-192-GCM decryption operation.
pub struct Aes192GcmDecryptRequest<'a> {
    /// Decryption key.
    pub key: &'a Aes192GcmKey,
    /// Nonce that was used to produce the ciphertext.
    pub nonce: Aes192GcmNonce,
    /// Additional authenticated data that must match what was authenticated.
    pub aad: &'a [u8],
    /// Authenticated `ciphertext || tag` to decrypt and verify.
    pub ciphertext: &'a CiphertextWithTag,
}
