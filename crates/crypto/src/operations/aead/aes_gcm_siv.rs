// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use zeroize::Zeroizing;

use crate::operations::OperationError;

#[cfg(all(feature = "aes-gcm-siv", any(feature = "native", feature = "wasm")))]
use super::error::map_aead_error;

#[cfg(all(feature = "aes-gcm-siv", any(feature = "native", feature = "wasm")))]
pub(super) fn seal_aes256_gcm_siv(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, OperationError> {
    let key = crypto_aes256_gcm_siv::Aes256GcmSivKey::from_slice(key).map_err(map_aead_error)?;
    let nonce =
        crypto_aes256_gcm_siv::Aes256GcmSivNonce::from_slice(nonce).map_err(map_aead_error)?;
    let request = crypto_aes256_gcm_siv::EncryptRequest {
        key: &key,
        nonce,
        aad,
        plaintext,
    };
    crypto_aes256_gcm_siv::encrypt(&request)
        .map(crypto_aes256_gcm_siv::CiphertextWithTag::into_vec)
        .map_err(map_aead_error)
}

#[cfg(not(all(feature = "aes-gcm-siv", any(feature = "native", feature = "wasm"))))]
pub(super) fn seal_aes256_gcm_siv(
    _key: &[u8],
    _nonce: &[u8],
    _aad: &[u8],
    _plaintext: &[u8],
) -> Result<Vec<u8>, OperationError> {
    Err(OperationError::Provider {
        reason: crate::operations::ProviderErrorReason::UnsupportedAlgorithm,
    })
}

#[cfg(all(feature = "aes-gcm-siv", any(feature = "native", feature = "wasm")))]
pub(super) fn open_aes256_gcm_siv(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext_with_tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OperationError> {
    let key = crypto_aes256_gcm_siv::Aes256GcmSivKey::from_slice(key).map_err(map_aead_error)?;
    let nonce =
        crypto_aes256_gcm_siv::Aes256GcmSivNonce::from_slice(nonce).map_err(map_aead_error)?;
    let ciphertext =
        crypto_aes256_gcm_siv::CiphertextWithTag::from_vec(ciphertext_with_tag.to_vec())
            .map_err(map_aead_error)?;
    let request = crypto_aes256_gcm_siv::DecryptRequest {
        key: &key,
        nonce,
        aad,
        ciphertext: &ciphertext,
    };
    crypto_aes256_gcm_siv::decrypt(&request)
        .map(Zeroizing::new)
        .map_err(map_aead_error)
}

#[cfg(not(all(feature = "aes-gcm-siv", any(feature = "native", feature = "wasm"))))]
pub(super) fn open_aes256_gcm_siv(
    _key: &[u8],
    _nonce: &[u8],
    _aad: &[u8],
    _ciphertext_with_tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OperationError> {
    Err(OperationError::Provider {
        reason: crate::operations::ProviderErrorReason::UnsupportedAlgorithm,
    })
}
