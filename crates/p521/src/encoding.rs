// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::{has_standard_sec1_encoding, CryptoError};
use p521::elliptic_curve::sec1::ToSec1Point;
use p521::PublicKey;

use crate::{P521_PUBLIC_KEY_COMPRESSED_LEN, P521_PUBLIC_KEY_UNCOMPRESSED_LEN};

// Backend parsers also accept compact (0x05) points. Admit only the SEC1
// encodings supported by this API before curve validation, so byte-based key
// identities cannot be bypassed through that extra representation.
pub(super) fn parse_public_key(bytes: &[u8]) -> Result<PublicKey, CryptoError> {
    if !has_standard_sec1_encoding(
        bytes,
        P521_PUBLIC_KEY_COMPRESSED_LEN,
        P521_PUBLIC_KEY_UNCOMPRESSED_LEN,
    ) {
        return Err(CryptoError::PRIMITIVE_INVALID_KEY);
    }
    PublicKey::from_sec1_bytes(bytes).map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)
}

/// Compress a SEC1 P-521 public key.
pub fn compress_p521(public_key_uncompressed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if public_key_uncompressed.len() != P521_PUBLIC_KEY_UNCOMPRESSED_LEN {
        return Err(CryptoError::PRIMITIVE_INVALID_KEY);
    }
    let public_key = parse_public_key(public_key_uncompressed)?;
    Ok(public_key.to_sec1_point(true).as_bytes().to_vec())
}

/// Decompress a SEC1 P-521 public key.
pub fn decompress_p521(public_key_compressed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if public_key_compressed.len() != P521_PUBLIC_KEY_COMPRESSED_LEN {
        return Err(CryptoError::PRIMITIVE_INVALID_KEY);
    }
    let public_key = parse_public_key(public_key_compressed)?;
    Ok(public_key.to_sec1_point(false).as_bytes().to_vec())
}
