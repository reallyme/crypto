// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::PublicKey;

/// Validates this crate's canonical compressed SEC1 secp256k1 public key shape.
///
/// The lightweight encode/decode helpers only accept the 33-byte compressed
/// SEC1 form (`0x02` or `0x03` plus x-coordinate). They intentionally do not
/// parse the point; callers that need full curve validation should call
/// [`decompress_secp256k1_public_key`] or a signing/verification operation.
pub fn assert_secp256k1_public_key(pubkey: &[u8]) -> Result<&[u8], CryptoError> {
    if pubkey.len() != 33 {
        return Err(CryptoError::InvalidKey);
    }
    match pubkey[0] {
        0x02 | 0x03 => Ok(pubkey),
        _ => Err(CryptoError::InvalidKey),
    }
}

/// Returns the canonical compressed SEC1 public-key bytes after shape validation.
pub fn encode_secp256k1_public_key(pubkey: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(assert_secp256k1_public_key(pubkey)?.to_vec())
}

/// Decodes the canonical public-key representation.
///
/// secp256k1 uses the same 33-byte compressed SEC1 bytes at the API and wire
/// boundary, so decoding is a validating copy rather than a re-serialization.
pub fn decode_secp256k1_public_key(pubkey: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(assert_secp256k1_public_key(pubkey)?.to_vec())
}

/// Decompresses a compressed SEC1 secp256k1 public key.
///
/// This path parses the SEC1 point through k256, so it performs full curve
/// validation before returning affine coordinates.
/// Returns (x, y) coordinates as 32-byte values.
pub fn decompress_secp256k1_public_key(
    pubkey_compressed: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let pk = PublicKey::from_sec1_bytes(pubkey_compressed).map_err(|_| CryptoError::InvalidKey)?;
    let uncompressed = pk.to_sec1_point(false);
    let bytes = uncompressed.as_bytes();

    Ok((bytes[1..33].to_vec(), bytes[33..65].to_vec()))
}
