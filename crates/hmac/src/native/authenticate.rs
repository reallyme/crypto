// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::{CryptoError, MacAlgorithm};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha384, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::types::{HmacKey, HmacTag};

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

// Finalized output arrays have no clearing destructor of their own. Keep the
// call-site copy guarded independently of optional upstream array features,
// including a future early return while constructing the returned tag owner.
struct FinalizedTagBytes<T: AsMut<[u8]>>(T);

impl<T: AsMut<[u8]>> Zeroize for FinalizedTagBytes<T> {
    fn zeroize(&mut self) {
        self.0.as_mut().zeroize();
    }
}

impl<T: AsMut<[u8]>> Drop for FinalizedTagBytes<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<T: AsMut<[u8]>> ZeroizeOnDrop for FinalizedTagBytes<T> {}

/// Computes an HMAC tag over `message`.
pub fn authenticate(
    algorithm: MacAlgorithm,
    key: &HmacKey,
    message: &[u8],
) -> Result<HmacTag, CryptoError> {
    match algorithm {
        MacAlgorithm::HmacSha256 => authenticate_sha256(key, message),
        MacAlgorithm::HmacSha384 => authenticate_sha384(key, message),
        MacAlgorithm::HmacSha512 => authenticate_sha512(key, message),
    }
}

/// Verifies `expected_tag` for `message` under `key`.
///
/// Verification is delegated to the RustCrypto HMAC implementation so the tag
/// comparison is constant-time for equal-length tags.
pub fn verify(
    algorithm: MacAlgorithm,
    key: &HmacKey,
    message: &[u8],
    expected_tag: &[u8],
) -> Result<(), CryptoError> {
    let expected_tag = HmacTag::from_slice(algorithm, expected_tag)?;
    match algorithm {
        MacAlgorithm::HmacSha256 => verify_sha256(key, message, expected_tag.as_bytes()),
        MacAlgorithm::HmacSha384 => verify_sha384(key, message, expected_tag.as_bytes()),
        MacAlgorithm::HmacSha512 => verify_sha512(key, message, expected_tag.as_bytes()),
    }
}

fn authenticate_sha256(key: &HmacKey, message: &[u8]) -> Result<HmacTag, CryptoError> {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes())
        .map_err(|_| crypto_core::CryptoError::PRIMITIVE_INVALID_KEY)?;
    mac.update(message);
    let bytes = FinalizedTagBytes(mac.finalize().into_bytes());
    HmacTag::from_slice(MacAlgorithm::HmacSha256, bytes.0.as_ref())
}

fn authenticate_sha384(key: &HmacKey, message: &[u8]) -> Result<HmacTag, CryptoError> {
    let mut mac = HmacSha384::new_from_slice(key.as_bytes())
        .map_err(|_| crypto_core::CryptoError::PRIMITIVE_INVALID_KEY)?;
    mac.update(message);
    let bytes = FinalizedTagBytes(mac.finalize().into_bytes());
    HmacTag::from_slice(MacAlgorithm::HmacSha384, bytes.0.as_ref())
}

fn authenticate_sha512(key: &HmacKey, message: &[u8]) -> Result<HmacTag, CryptoError> {
    let mut mac = HmacSha512::new_from_slice(key.as_bytes())
        .map_err(|_| crypto_core::CryptoError::PRIMITIVE_INVALID_KEY)?;
    mac.update(message);
    let bytes = FinalizedTagBytes(mac.finalize().into_bytes());
    HmacTag::from_slice(MacAlgorithm::HmacSha512, bytes.0.as_ref())
}

fn verify_sha256(key: &HmacKey, message: &[u8], expected_tag: &[u8]) -> Result<(), CryptoError> {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes())
        .map_err(|_| crypto_core::CryptoError::PRIMITIVE_INVALID_KEY)?;
    mac.update(message);
    mac.verify_slice(expected_tag)
        .map_err(|_| crypto_core::CryptoError::PRIMITIVE_VERIFICATION_FAILED)
}

fn verify_sha384(key: &HmacKey, message: &[u8], expected_tag: &[u8]) -> Result<(), CryptoError> {
    let mut mac = HmacSha384::new_from_slice(key.as_bytes())
        .map_err(|_| crypto_core::CryptoError::PRIMITIVE_INVALID_KEY)?;
    mac.update(message);
    mac.verify_slice(expected_tag)
        .map_err(|_| crypto_core::CryptoError::PRIMITIVE_VERIFICATION_FAILED)
}

fn verify_sha512(key: &HmacKey, message: &[u8], expected_tag: &[u8]) -> Result<(), CryptoError> {
    let mut mac = HmacSha512::new_from_slice(key.as_bytes())
        .map_err(|_| crypto_core::CryptoError::PRIMITIVE_INVALID_KEY)?;
    mac.update(message);
    mac.verify_slice(expected_tag)
        .map_err(|_| crypto_core::CryptoError::PRIMITIVE_VERIFICATION_FAILED)
}

#[cfg(test)]
#[path = "authenticate_output_tests.rs"]
mod output_owner_tests;
