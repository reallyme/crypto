// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::open_legacy_aes256_siv;
use aes_siv_backend::aead::{Aead, KeyInit, Payload};
use crypto_core::CryptoError;
#[test]
fn opens_retained_records_and_rejects_wrong_context() -> Result<(), CryptoError> {
    let key = [7; 64];
    let nonce = aes_siv_backend::Nonce::from([0; 16]);
    let cipher = aes_siv_backend::Aes256SivAead::new_from_slice(&key)
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;
    let encrypted = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: b"retained record",
                aad: b"record-kind",
            },
        )
        .map_err(|_| CryptoError::PRIMITIVE_AUTHENTICATION_FAILED)?;
    assert_eq!(
        open_legacy_aes256_siv(&key, &[0; 16], b"record-kind", &encrypted)?.as_slice(),
        b"retained record"
    );
    assert_eq!(
        open_legacy_aes256_siv(&key, &[0; 16], b"other-kind", &encrypted),
        Err(CryptoError::PRIMITIVE_AUTHENTICATION_FAILED)
    );
    assert_eq!(
        open_legacy_aes256_siv(&[8; 64], &[0; 16], b"record-kind", &encrypted),
        Err(CryptoError::PRIMITIVE_AUTHENTICATION_FAILED)
    );
    assert_eq!(
        open_legacy_aes256_siv(&key[..63], &[0; 16], b"record-kind", &encrypted),
        Err(CryptoError::PRIMITIVE_INVALID_LENGTH)
    );
    assert_eq!(
        open_legacy_aes256_siv(&key, &[0; 15], b"record-kind", &encrypted),
        Err(CryptoError::PRIMITIVE_INVALID_LENGTH)
    );
    assert_eq!(
        open_legacy_aes256_siv(&key, &[0; 16], b"record-kind", &[0; 15]),
        Err(CryptoError::PRIMITIVE_INVALID_LENGTH)
    );
    Ok(())
}
