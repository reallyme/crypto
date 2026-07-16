// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, MacAlgorithm, MacFailureKind};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha512};

use crate::types::{mac_hash, HmacKey, HmacTag};

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// Computes an HMAC tag over `message`.
pub fn authenticate(
    algorithm: MacAlgorithm,
    key: &HmacKey,
    message: &[u8],
) -> Result<HmacTag, CryptoError> {
    match algorithm {
        MacAlgorithm::HmacSha256 => authenticate_sha256(key, message),
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
        MacAlgorithm::HmacSha512 => verify_sha512(key, message, expected_tag.as_bytes()),
    }
}

fn authenticate_sha256(key: &HmacKey, message: &[u8]) -> Result<HmacTag, CryptoError> {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::Mac {
        hash: mac_hash(MacAlgorithm::HmacSha256),
        kind: MacFailureKind::InvalidKeyLength,
    })?;
    mac.update(message);
    let bytes = mac.finalize().into_bytes();
    HmacTag::from_slice(MacAlgorithm::HmacSha256, &bytes)
}

fn authenticate_sha512(key: &HmacKey, message: &[u8]) -> Result<HmacTag, CryptoError> {
    let mut mac = HmacSha512::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::Mac {
        hash: mac_hash(MacAlgorithm::HmacSha512),
        kind: MacFailureKind::InvalidKeyLength,
    })?;
    mac.update(message);
    let bytes = mac.finalize().into_bytes();
    HmacTag::from_slice(MacAlgorithm::HmacSha512, &bytes)
}

fn verify_sha256(key: &HmacKey, message: &[u8], expected_tag: &[u8]) -> Result<(), CryptoError> {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::Mac {
        hash: mac_hash(MacAlgorithm::HmacSha256),
        kind: MacFailureKind::InvalidKeyLength,
    })?;
    mac.update(message);
    mac.verify_slice(expected_tag)
        .map_err(|_| CryptoError::Mac {
            hash: mac_hash(MacAlgorithm::HmacSha256),
            kind: MacFailureKind::VerificationFailed,
        })
}

fn verify_sha512(key: &HmacKey, message: &[u8], expected_tag: &[u8]) -> Result<(), CryptoError> {
    let mut mac = HmacSha512::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::Mac {
        hash: mac_hash(MacAlgorithm::HmacSha512),
        kind: MacFailureKind::InvalidKeyLength,
    })?;
    mac.update(message);
    mac.verify_slice(expected_tag)
        .map_err(|_| CryptoError::Mac {
            hash: mac_hash(MacAlgorithm::HmacSha512),
            kind: MacFailureKind::VerificationFailed,
        })
}
