// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::{has_standard_sec1_encoding, CryptoError};
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::PublicKey;

const SECP256K1_PUBLIC_KEY_COMPRESSED_LEN: usize =
    crypto_core::contract_constants::secp256k1::SECP256K1_PUBLIC_KEY_COMPRESSED_LEN;
const SECP256K1_UNCOMPRESSED_PUBLIC_KEY_LEN: usize =
    crypto_core::contract_constants::secp256k1::SECP256K1_UNCOMPRESSED_PUBLIC_KEY_LEN;

// k256 also parses compact (0x05) points. Keep the public boundary on the
// documented compressed/uncompressed encodings before validating the point.
pub(super) fn parse_public_key(bytes: &[u8]) -> Result<PublicKey, CryptoError> {
    if !has_standard_sec1_encoding(
        bytes,
        SECP256K1_PUBLIC_KEY_COMPRESSED_LEN,
        SECP256K1_UNCOMPRESSED_PUBLIC_KEY_LEN,
    ) {
        return Err(CryptoError::PRIMITIVE_INVALID_KEY);
    }
    PublicKey::from_sec1_bytes(bytes).map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)
}

/// Validates this crate's canonical compressed SEC1 secp256k1 public key shape.
///
/// The lightweight encode/decode helpers only accept the 33-byte compressed
/// SEC1 form (`0x02` or `0x03` plus x-coordinate). They intentionally do not
/// parse the point; callers that need full curve validation should call
/// [`decompress_secp256k1_public_key`] or a signing/verification operation.
pub fn assert_secp256k1_public_key(pubkey: &[u8]) -> Result<&[u8], CryptoError> {
    if pubkey.len() != SECP256K1_PUBLIC_KEY_COMPRESSED_LEN
        || !has_standard_sec1_encoding(
            pubkey,
            SECP256K1_PUBLIC_KEY_COMPRESSED_LEN,
            SECP256K1_UNCOMPRESSED_PUBLIC_KEY_LEN,
        )
    {
        return Err(CryptoError::PRIMITIVE_INVALID_KEY);
    }
    Ok(pubkey)
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
    assert_secp256k1_public_key(pubkey_compressed)?;
    let pk = parse_public_key(pubkey_compressed)?;
    let uncompressed = pk.to_sec1_point(false);
    let bytes = uncompressed.as_bytes();

    Ok((bytes[1..33].to_vec(), bytes[33..65].to_vec()))
}
