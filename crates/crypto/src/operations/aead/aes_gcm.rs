// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use zeroize::Zeroizing;

use crate::operations::OperationError;

#[cfg(all(
    feature = "aes",
    any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))
))]
use super::error::map_aead_error;

#[cfg(all(
    feature = "aes",
    any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))
))]
pub(super) fn seal_aes128_gcm(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, OperationError> {
    let key = crypto_aes256_gcm::Aes128GcmKey::from_slice(key).map_err(map_aead_error)?;
    let nonce = crypto_aes256_gcm::Aes128GcmNonce::from_slice(nonce).map_err(map_aead_error)?;
    let request = crypto_aes256_gcm::Aes128GcmEncryptRequest {
        key: &key,
        nonce,
        aad,
        plaintext,
    };
    crypto_aes256_gcm::encrypt_aes128_gcm(&request)
        .map(crypto_aes256_gcm::CiphertextWithTag::into_vec)
        .map_err(map_aead_error)
}

#[cfg(not(all(
    feature = "aes",
    any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))
)))]
pub(super) fn seal_aes128_gcm(
    _key: &[u8],
    _nonce: &[u8],
    _aad: &[u8],
    _plaintext: &[u8],
) -> Result<Vec<u8>, OperationError> {
    Err(OperationError::Provider {
        reason: crate::operations::ProviderErrorReason::UnsupportedAlgorithm,
    })
}

#[cfg(all(
    feature = "aes",
    any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))
))]
pub(super) fn open_aes128_gcm(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext_with_tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OperationError> {
    let key = crypto_aes256_gcm::Aes128GcmKey::from_slice(key).map_err(map_aead_error)?;
    let nonce = crypto_aes256_gcm::Aes128GcmNonce::from_slice(nonce).map_err(map_aead_error)?;
    let ciphertext = crypto_aes256_gcm::CiphertextWithTag::from_vec(ciphertext_with_tag.to_vec())
        .map_err(map_aead_error)?;
    let request = crypto_aes256_gcm::Aes128GcmDecryptRequest {
        key: &key,
        nonce,
        aad,
        ciphertext: &ciphertext,
    };
    crypto_aes256_gcm::decrypt_aes128_gcm(&request)
        .map(Zeroizing::new)
        .map_err(map_aead_error)
}

#[cfg(not(all(
    feature = "aes",
    any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))
)))]
pub(super) fn open_aes128_gcm(
    _key: &[u8],
    _nonce: &[u8],
    _aad: &[u8],
    _ciphertext_with_tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OperationError> {
    Err(OperationError::Provider {
        reason: crate::operations::ProviderErrorReason::UnsupportedAlgorithm,
    })
}

#[cfg(all(
    feature = "aes",
    any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))
))]
pub(super) fn seal_aes192_gcm(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, OperationError> {
    let key = crypto_aes256_gcm::Aes192GcmKey::from_slice(key).map_err(map_aead_error)?;
    let nonce = crypto_aes256_gcm::Aes192GcmNonce::from_slice(nonce).map_err(map_aead_error)?;
    let request = crypto_aes256_gcm::Aes192GcmEncryptRequest {
        key: &key,
        nonce,
        aad,
        plaintext,
    };
    crypto_aes256_gcm::encrypt_aes192_gcm(&request)
        .map(crypto_aes256_gcm::CiphertextWithTag::into_vec)
        .map_err(map_aead_error)
}

#[cfg(not(all(
    feature = "aes",
    any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))
)))]
pub(super) fn seal_aes192_gcm(
    _key: &[u8],
    _nonce: &[u8],
    _aad: &[u8],
    _plaintext: &[u8],
) -> Result<Vec<u8>, OperationError> {
    Err(OperationError::Provider {
        reason: crate::operations::ProviderErrorReason::UnsupportedAlgorithm,
    })
}

#[cfg(all(
    feature = "aes",
    any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))
))]
pub(super) fn open_aes192_gcm(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext_with_tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OperationError> {
    let key = crypto_aes256_gcm::Aes192GcmKey::from_slice(key).map_err(map_aead_error)?;
    let nonce = crypto_aes256_gcm::Aes192GcmNonce::from_slice(nonce).map_err(map_aead_error)?;
    let ciphertext = crypto_aes256_gcm::CiphertextWithTag::from_vec(ciphertext_with_tag.to_vec())
        .map_err(map_aead_error)?;
    let request = crypto_aes256_gcm::Aes192GcmDecryptRequest {
        key: &key,
        nonce,
        aad,
        ciphertext: &ciphertext,
    };
    crypto_aes256_gcm::decrypt_aes192_gcm(&request)
        .map(Zeroizing::new)
        .map_err(map_aead_error)
}

#[cfg(not(all(
    feature = "aes",
    any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))
)))]
pub(super) fn open_aes192_gcm(
    _key: &[u8],
    _nonce: &[u8],
    _aad: &[u8],
    _ciphertext_with_tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OperationError> {
    Err(OperationError::Provider {
        reason: crate::operations::ProviderErrorReason::UnsupportedAlgorithm,
    })
}

#[cfg(all(
    feature = "aes",
    any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))
))]
pub(super) fn seal_aes256_gcm(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, OperationError> {
    let key = crypto_aes256_gcm::Aes256GcmKey::from_slice(key).map_err(map_aead_error)?;
    let nonce = crypto_aes256_gcm::Aes256GcmNonce::from_slice(nonce).map_err(map_aead_error)?;
    let request = crypto_aes256_gcm::EncryptRequest {
        key: &key,
        nonce,
        aad,
        plaintext,
    };
    crypto_aes256_gcm::encrypt(&request)
        .map(crypto_aes256_gcm::CiphertextWithTag::into_vec)
        .map_err(map_aead_error)
}

#[cfg(not(all(
    feature = "aes",
    any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))
)))]
pub(super) fn seal_aes256_gcm(
    _key: &[u8],
    _nonce: &[u8],
    _aad: &[u8],
    _plaintext: &[u8],
) -> Result<Vec<u8>, OperationError> {
    Err(OperationError::Provider {
        reason: crate::operations::ProviderErrorReason::UnsupportedAlgorithm,
    })
}

#[cfg(all(
    feature = "aes",
    any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))
))]
pub(super) fn open_aes256_gcm(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext_with_tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OperationError> {
    let key = crypto_aes256_gcm::Aes256GcmKey::from_slice(key).map_err(map_aead_error)?;
    let nonce = crypto_aes256_gcm::Aes256GcmNonce::from_slice(nonce).map_err(map_aead_error)?;
    let ciphertext = crypto_aes256_gcm::CiphertextWithTag::from_vec(ciphertext_with_tag.to_vec())
        .map_err(map_aead_error)?;
    let request = crypto_aes256_gcm::DecryptRequest {
        key: &key,
        nonce,
        aad,
        ciphertext: &ciphertext,
    };
    crypto_aes256_gcm::decrypt(&request)
        .map(Zeroizing::new)
        .map_err(map_aead_error)
}

#[cfg(not(all(
    feature = "aes",
    any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))
)))]
pub(super) fn open_aes256_gcm(
    _key: &[u8],
    _nonce: &[u8],
    _aad: &[u8],
    _ciphertext_with_tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OperationError> {
    Err(OperationError::Provider {
        reason: crate::operations::ProviderErrorReason::UnsupportedAlgorithm,
    })
}
