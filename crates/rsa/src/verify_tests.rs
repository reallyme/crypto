// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{digest_info_prefix, signature_error, verify_pkcs1v15_encoded_message};
use crate::types::RsaHash;
use crypto_core::CryptoError;

const SHA256_DIGEST_INFO_WITHOUT_NULL: &[u8] = &[
    0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x04,
    0x20,
];

#[test]
fn pkcs1v15_requires_null_in_sha256_digest_info() -> Result<(), CryptoError> {
    let digest = [0xa5_u8; 32];
    let canonical = encoded_message(digest_info_prefix(RsaHash::Sha256), &digest)?;
    let missing_null = encoded_message(SHA256_DIGEST_INFO_WITHOUT_NULL, &digest)?;

    assert_eq!(
        verify_pkcs1v15_encoded_message(RsaHash::Sha256, &digest, &canonical),
        Ok(())
    );
    assert_eq!(
        verify_pkcs1v15_encoded_message(RsaHash::Sha256, &digest, &missing_null),
        Err(signature_error())
    );
    Ok(())
}

fn encoded_message(prefix: &[u8], digest: &[u8]) -> Result<[u8; 128], CryptoError> {
    let mut encoded = [0xff_u8; 128];
    let digest_info_length = prefix
        .len()
        .checked_add(digest.len())
        .ok_or(CryptoError::InvalidKey)?;
    let digest_info_start = encoded
        .len()
        .checked_sub(digest_info_length)
        .ok_or(CryptoError::InvalidKey)?;
    let separator = digest_info_start
        .checked_sub(1)
        .ok_or(CryptoError::InvalidKey)?;
    let digest_start = digest_info_start
        .checked_add(prefix.len())
        .ok_or(CryptoError::InvalidKey)?;
    encoded[0] = 0;
    encoded[1] = 1;
    *encoded.get_mut(separator).ok_or(CryptoError::InvalidKey)? = 0;
    encoded
        .get_mut(digest_info_start..digest_start)
        .ok_or(CryptoError::InvalidKey)?
        .copy_from_slice(prefix);
    encoded
        .get_mut(digest_start..)
        .ok_or(CryptoError::InvalidKey)?
        .copy_from_slice(digest);
    Ok(encoded)
}
