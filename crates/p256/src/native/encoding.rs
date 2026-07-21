// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

// encoding.rs

use crypto_core::CryptoError;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::PublicKey;

const P256_PUBLIC_KEY_COMPRESSED_LEN: usize = 33;
const P256_PUBLIC_KEY_UNCOMPRESSED_LEN: usize = 65;
const SEC1_COMPRESSED_EVEN_PREFIX: u8 = 0x02;
const SEC1_COMPRESSED_ODD_PREFIX: u8 = 0x03;
const SEC1_UNCOMPRESSED_PREFIX: u8 = 0x04;

/// Compress an uncompressed SEC1 P-256 public key.
pub fn compress_p256(pubkey_uncompressed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if pubkey_uncompressed.len() != P256_PUBLIC_KEY_UNCOMPRESSED_LEN
        || pubkey_uncompressed.first() != Some(&SEC1_UNCOMPRESSED_PREFIX)
    {
        return Err(CryptoError::InvalidKey);
    }
    let pk =
        PublicKey::from_sec1_bytes(pubkey_uncompressed).map_err(|_| CryptoError::InvalidKey)?;

    Ok(pk.to_sec1_point(true).as_bytes().to_vec())
}

/// Decompress a compressed SEC1 P-256 public key.
pub fn decompress_p256(pubkey_compressed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if pubkey_compressed.len() != P256_PUBLIC_KEY_COMPRESSED_LEN
        || !matches!(
            pubkey_compressed.first().copied(),
            Some(SEC1_COMPRESSED_EVEN_PREFIX | SEC1_COMPRESSED_ODD_PREFIX)
        )
    {
        return Err(CryptoError::InvalidKey);
    }
    let pk = PublicKey::from_sec1_bytes(pubkey_compressed).map_err(|_| CryptoError::InvalidKey)?;

    Ok(pk.to_sec1_point(false).as_bytes().to_vec())
}
