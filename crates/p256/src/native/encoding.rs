// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// encoding.rs

use crypto_core::{has_standard_sec1_encoding, CryptoError};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::PublicKey;

const P256_PUBLIC_KEY_COMPRESSED_LEN: usize =
    crypto_core::contract_constants::p256::P256_PUBLIC_KEY_COMPRESSED_LEN;
const P256_PUBLIC_KEY_UNCOMPRESSED_LEN: usize =
    crypto_core::contract_constants::p256::P256_PUBLIC_KEY_UNCOMPRESSED_LEN;

// Backend parsers also accept compact (0x05) points. Admit only the SEC1
// encodings supported by this API before curve validation, so byte-based key
// identities cannot be bypassed through that extra representation.
pub(super) fn parse_public_key(bytes: &[u8]) -> Result<PublicKey, CryptoError> {
    if !has_standard_sec1_encoding(
        bytes,
        P256_PUBLIC_KEY_COMPRESSED_LEN,
        P256_PUBLIC_KEY_UNCOMPRESSED_LEN,
    ) {
        return Err(CryptoError::PRIMITIVE_INVALID_KEY);
    }
    PublicKey::from_sec1_bytes(bytes).map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)
}

/// Compress an uncompressed SEC1 P-256 public key.
pub fn compress_p256(pubkey_uncompressed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if pubkey_uncompressed.len() != P256_PUBLIC_KEY_UNCOMPRESSED_LEN {
        return Err(CryptoError::PRIMITIVE_INVALID_KEY);
    }
    let pk = parse_public_key(pubkey_uncompressed)?;

    Ok(pk.to_sec1_point(true).as_bytes().to_vec())
}

/// Decompress a compressed SEC1 P-256 public key.
pub fn decompress_p256(pubkey_compressed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if pubkey_compressed.len() != P256_PUBLIC_KEY_COMPRESSED_LEN {
        return Err(CryptoError::PRIMITIVE_INVALID_KEY);
    }
    let pk = parse_public_key(pubkey_compressed)?;

    Ok(pk.to_sec1_point(false).as_bytes().to_vec())
}
