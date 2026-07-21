// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use p384::elliptic_curve::sec1::ToSec1Point;
use p384::PublicKey;

use crate::{P384_PUBLIC_KEY_COMPRESSED_LEN, P384_PUBLIC_KEY_UNCOMPRESSED_LEN};

const SEC1_COMPRESSED_EVEN_PREFIX: u8 = 0x02;
const SEC1_COMPRESSED_ODD_PREFIX: u8 = 0x03;
const SEC1_UNCOMPRESSED_PREFIX: u8 = 0x04;

/// Compress a SEC1 P-384 public key.
pub fn compress_p384(public_key_uncompressed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if public_key_uncompressed.len() != P384_PUBLIC_KEY_UNCOMPRESSED_LEN
        || public_key_uncompressed.first() != Some(&SEC1_UNCOMPRESSED_PREFIX)
    {
        return Err(CryptoError::InvalidKey);
    }
    let public_key =
        PublicKey::from_sec1_bytes(public_key_uncompressed).map_err(|_| CryptoError::InvalidKey)?;
    Ok(public_key.to_sec1_point(true).as_bytes().to_vec())
}

/// Decompress a SEC1 P-384 public key.
pub fn decompress_p384(public_key_compressed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if public_key_compressed.len() != P384_PUBLIC_KEY_COMPRESSED_LEN
        || !matches!(
            public_key_compressed.first().copied(),
            Some(SEC1_COMPRESSED_EVEN_PREFIX | SEC1_COMPRESSED_ODD_PREFIX)
        )
    {
        return Err(CryptoError::InvalidKey);
    }
    let public_key =
        PublicKey::from_sec1_bytes(public_key_compressed).map_err(|_| CryptoError::InvalidKey)?;
    Ok(public_key.to_sec1_point(false).as_bytes().to_vec())
}
