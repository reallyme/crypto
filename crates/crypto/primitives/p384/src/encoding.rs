// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use p384::elliptic_curve::sec1::ToSec1Point;
use p384::PublicKey;

/// Compress a SEC1 P-384 public key.
pub fn compress_p384(public_key_uncompressed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let public_key =
        PublicKey::from_sec1_bytes(public_key_uncompressed).map_err(|_| CryptoError::InvalidKey)?;
    Ok(public_key.to_sec1_point(true).as_bytes().to_vec())
}

/// Decompress a SEC1 P-384 public key.
pub fn decompress_p384(public_key_compressed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let public_key =
        PublicKey::from_sec1_bytes(public_key_compressed).map_err(|_| CryptoError::InvalidKey)?;
    Ok(public_key.to_sec1_point(false).as_bytes().to_vec())
}
