// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::CryptoError;

/// Byte length of an encoded X25519 public key.
pub const X25519_PUBLIC_KEY_LEN: usize = 32;

// RFC 7748 accepts noncanonical u-coordinates for agreement. An encoded key
// used as an identifier needs one byte representation for each field element.
const FIELD_PRIME_LE: [u8; X25519_PUBLIC_KEY_LEN] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// Validate that a value is a 32-byte X25519 public key.
pub fn assert_public_key(pubkey: &[u8]) -> Result<&[u8], CryptoError> {
    let encoded: &[u8; X25519_PUBLIC_KEY_LEN] =
        pubkey.try_into().map_err(|_| CryptoError::InvalidKey)?;
    for index in (0..X25519_PUBLIC_KEY_LEN).rev() {
        match encoded[index].cmp(&FIELD_PRIME_LE[index]) {
            core::cmp::Ordering::Less => return Ok(pubkey),
            core::cmp::Ordering::Greater => return Err(CryptoError::InvalidKey),
            core::cmp::Ordering::Equal => {}
        }
    }
    Err(CryptoError::InvalidKey)
}

/// Identity encoder.
pub fn encode_public_key(pubkey: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(assert_public_key(pubkey)?.to_vec())
}

/// Identity decoder.
pub fn decode_public_key(pubkey: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(assert_public_key(pubkey)?.to_vec())
}
