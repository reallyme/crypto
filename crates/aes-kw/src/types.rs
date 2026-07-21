// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::{
    AES_128_KW_KEK_LENGTH, AES_192_KW_KEK_LENGTH, AES_256_KW_KEK_LENGTH, AES_KW_BLOCK_LENGTH,
    AES_KW_INTEGRITY_CHECK_LENGTH, AES_KW_MAX_KEY_DATA_LENGTH, AES_KW_MIN_KEY_DATA_LENGTH,
    AES_KW_MIN_WRAPPED_KEY_LENGTH,
};
use crypto_core::{CryptoError, KeyWrapAlgorithm, KeyWrapFailureKind, KeyWrapOperation};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// AES-128 key-encryption key used by RFC 3394 AES-KW.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Aes128KwKek {
    bytes: [u8; AES_128_KW_KEK_LENGTH],
}

impl Aes128KwKek {
    /// Constructs an AES-128-KW key-encryption key from raw bytes.
    pub fn from_slice(input: &[u8]) -> Result<Self, CryptoError> {
        if input.len() != AES_128_KW_KEK_LENGTH {
            return Err(key_wrap_error(
                KeyWrapAlgorithm::Aes128Kw,
                KeyWrapOperation::Wrap,
                KeyWrapFailureKind::InvalidKekLength,
            ));
        }

        let mut bytes = [0u8; AES_128_KW_KEK_LENGTH];
        bytes.copy_from_slice(input);
        Ok(Self { bytes })
    }

    /// Borrows the raw key-encryption key bytes.
    pub fn as_bytes(&self) -> &[u8; AES_128_KW_KEK_LENGTH] {
        &self.bytes
    }
}

/// AES-192 key-encryption key used by RFC 3394 AES-KW.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Aes192KwKek {
    bytes: [u8; AES_192_KW_KEK_LENGTH],
}

impl Aes192KwKek {
    /// Constructs an AES-192-KW key-encryption key from raw bytes.
    pub fn from_slice(input: &[u8]) -> Result<Self, CryptoError> {
        if input.len() != AES_192_KW_KEK_LENGTH {
            return Err(key_wrap_error(
                KeyWrapAlgorithm::Aes192Kw,
                KeyWrapOperation::Wrap,
                KeyWrapFailureKind::InvalidKekLength,
            ));
        }

        let mut bytes = [0u8; AES_192_KW_KEK_LENGTH];
        bytes.copy_from_slice(input);
        Ok(Self { bytes })
    }

    /// Borrows the raw key-encryption key bytes.
    pub fn as_bytes(&self) -> &[u8; AES_192_KW_KEK_LENGTH] {
        &self.bytes
    }
}

/// AES-256 key-encryption key used by RFC 3394 AES-KW.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Aes256KwKek {
    bytes: [u8; AES_256_KW_KEK_LENGTH],
}

impl Aes256KwKek {
    /// Constructs an AES-256-KW key-encryption key from raw bytes.
    pub fn from_slice(input: &[u8]) -> Result<Self, CryptoError> {
        if input.len() != AES_256_KW_KEK_LENGTH {
            return Err(key_wrap_error(
                KeyWrapAlgorithm::Aes256Kw,
                KeyWrapOperation::Wrap,
                KeyWrapFailureKind::InvalidKekLength,
            ));
        }

        let mut bytes = [0u8; AES_256_KW_KEK_LENGTH];
        bytes.copy_from_slice(input);
        Ok(Self { bytes })
    }

    /// Borrows the raw key-encryption key bytes.
    pub fn as_bytes(&self) -> &[u8; AES_256_KW_KEK_LENGTH] {
        &self.bytes
    }
}

/// Plaintext key material accepted by RFC 3394 AES-KW.
pub struct AesKwKeyData {
    bytes: Zeroizing<Vec<u8>>,
}

impl Zeroize for AesKwKeyData {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

// The owned `Zeroizing<Vec<u8>>` performs the drop-time wipe. Implementing the
// marker explicitly avoids adding a second `Drop` implementation, which lets
// ownership transfers move the protected allocation instead of copying it.
impl ZeroizeOnDrop for AesKwKeyData {}

impl AesKwKeyData {
    pub(crate) fn from_zeroizing(
        algorithm: KeyWrapAlgorithm,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<Self, CryptoError> {
        validate_plaintext_len(algorithm, bytes.len())?;
        Ok(Self { bytes })
    }

    /// Borrows the plaintext key material.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the plaintext key-material length in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether this value is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Consumes the key material and returns an owned zeroizing buffer.
    pub fn into_zeroizing(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }
}

impl core::fmt::Debug for AesKwKeyData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "AesKwKeyData(len={})", self.len())
    }
}

/// Wrapped key material emitted by RFC 3394 AES-KW.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct AesKwWrappedKey {
    bytes: Zeroizing<Vec<u8>>,
}

impl AesKwWrappedKey {
    pub(crate) fn from_zeroizing(
        algorithm: KeyWrapAlgorithm,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<Self, CryptoError> {
        validate_wrapped_len(algorithm, bytes.len())?;
        Ok(Self { bytes })
    }

    /// Borrows the wrapped key material.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the wrapped key-material length in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether this value is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Consumes the wrapped key and returns owned bytes.
    ///
    /// Wrapped bytes are ciphertext, but callers should still wipe them when
    /// policy treats wrapped key blobs as sensitive storage material.
    pub fn into_vec(self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl core::fmt::Debug for AesKwWrappedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "AesKwWrappedKey(len={})", self.len())
    }
}

pub(crate) fn key_wrap_error(
    algorithm: KeyWrapAlgorithm,
    operation: KeyWrapOperation,
    kind: KeyWrapFailureKind,
) -> CryptoError {
    CryptoError::KeyWrap {
        algorithm,
        operation,
        kind,
    }
}

pub(crate) fn validate_plaintext_len(
    algorithm: KeyWrapAlgorithm,
    len: usize,
) -> Result<(), CryptoError> {
    if !(AES_KW_MIN_KEY_DATA_LENGTH..=AES_KW_MAX_KEY_DATA_LENGTH).contains(&len)
        || !len.is_multiple_of(AES_KW_BLOCK_LENGTH)
    {
        return Err(key_wrap_error(
            algorithm,
            KeyWrapOperation::Wrap,
            KeyWrapFailureKind::InvalidPlaintextLength,
        ));
    }
    Ok(())
}

pub(crate) fn validate_wrapped_len(
    algorithm: KeyWrapAlgorithm,
    len: usize,
) -> Result<(), CryptoError> {
    let max_wrapped_len = AES_KW_MAX_KEY_DATA_LENGTH
        .checked_add(AES_KW_INTEGRITY_CHECK_LENGTH)
        .ok_or_else(|| {
            key_wrap_error(
                algorithm,
                KeyWrapOperation::Unwrap,
                KeyWrapFailureKind::LengthOverflow,
            )
        })?;

    if !(AES_KW_MIN_WRAPPED_KEY_LENGTH..=max_wrapped_len).contains(&len)
        || !len.is_multiple_of(AES_KW_BLOCK_LENGTH)
    {
        return Err(key_wrap_error(
            algorithm,
            KeyWrapOperation::Unwrap,
            KeyWrapFailureKind::InvalidWrappedLength,
        ));
    }
    Ok(())
}
