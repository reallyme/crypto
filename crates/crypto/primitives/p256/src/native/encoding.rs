// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

// encoding.rs

use crypto_core::CryptoError;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::PublicKey;

/// Compress an uncompressed SEC1 P-256 public key.
pub fn compress_p256(pubkey_uncompressed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let pk =
        PublicKey::from_sec1_bytes(pubkey_uncompressed).map_err(|_| CryptoError::InvalidKey)?;

    Ok(pk.to_sec1_point(true).as_bytes().to_vec())
}

/// Decompress a compressed SEC1 P-256 public key.
pub fn decompress_p256(pubkey_compressed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let pk = PublicKey::from_sec1_bytes(pubkey_compressed).map_err(|_| CryptoError::InvalidKey)?;

    Ok(pk.to_sec1_point(false).as_bytes().to_vec())
}
