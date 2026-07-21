// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use zeroize::Zeroizing;

use crate::operations::OperationError;

#[cfg(all(
    feature = "chacha20-poly1305",
    any(feature = "native", feature = "wasm")
))]
use super::error::map_aead_error;

#[cfg(all(
    feature = "chacha20-poly1305",
    any(feature = "native", feature = "wasm")
))]
pub(super) fn seal_chacha20_poly1305(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, OperationError> {
    let key =
        crypto_chacha20_poly1305::ChaCha20Poly1305Key::from_slice(key).map_err(map_aead_error)?;
    let nonce = crypto_chacha20_poly1305::ChaCha20Poly1305Nonce::from_slice(nonce)
        .map_err(map_aead_error)?;
    let request = crypto_chacha20_poly1305::EncryptRequest {
        key: &key,
        nonce,
        aad,
        plaintext,
    };
    crypto_chacha20_poly1305::encrypt(&request)
        .map(crypto_chacha20_poly1305::CiphertextWithTag::into_vec)
        .map_err(map_aead_error)
}

#[cfg(not(all(
    feature = "chacha20-poly1305",
    any(feature = "native", feature = "wasm")
)))]
pub(super) fn seal_chacha20_poly1305(
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
    feature = "chacha20-poly1305",
    any(feature = "native", feature = "wasm")
))]
pub(super) fn open_chacha20_poly1305(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext_with_tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OperationError> {
    let key =
        crypto_chacha20_poly1305::ChaCha20Poly1305Key::from_slice(key).map_err(map_aead_error)?;
    let nonce = crypto_chacha20_poly1305::ChaCha20Poly1305Nonce::from_slice(nonce)
        .map_err(map_aead_error)?;
    let ciphertext =
        crypto_chacha20_poly1305::CiphertextWithTag::from_vec(ciphertext_with_tag.to_vec())
            .map_err(map_aead_error)?;
    let request = crypto_chacha20_poly1305::DecryptRequest {
        key: &key,
        nonce,
        aad,
        ciphertext: &ciphertext,
    };
    crypto_chacha20_poly1305::decrypt(&request)
        .map(Zeroizing::new)
        .map_err(map_aead_error)
}

#[cfg(not(all(
    feature = "chacha20-poly1305",
    any(feature = "native", feature = "wasm")
)))]
pub(super) fn open_chacha20_poly1305(
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
    feature = "chacha20-poly1305",
    any(feature = "native", feature = "wasm")
))]
pub(super) fn seal_xchacha20_poly1305(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, OperationError> {
    let key =
        crypto_chacha20_poly1305::ChaCha20Poly1305Key::from_slice(key).map_err(map_aead_error)?;
    let nonce = crypto_chacha20_poly1305::XChaCha20Poly1305Nonce::from_slice(nonce)
        .map_err(map_aead_error)?;
    let request = crypto_chacha20_poly1305::XChaCha20Poly1305EncryptRequest {
        key: &key,
        nonce,
        aad,
        plaintext,
    };
    crypto_chacha20_poly1305::encrypt_xchacha20_poly1305(&request)
        .map(crypto_chacha20_poly1305::CiphertextWithTag::into_vec)
        .map_err(map_aead_error)
}

#[cfg(not(all(
    feature = "chacha20-poly1305",
    any(feature = "native", feature = "wasm")
)))]
pub(super) fn seal_xchacha20_poly1305(
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
    feature = "chacha20-poly1305",
    any(feature = "native", feature = "wasm")
))]
pub(super) fn open_xchacha20_poly1305(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext_with_tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OperationError> {
    let key =
        crypto_chacha20_poly1305::ChaCha20Poly1305Key::from_slice(key).map_err(map_aead_error)?;
    let nonce = crypto_chacha20_poly1305::XChaCha20Poly1305Nonce::from_slice(nonce)
        .map_err(map_aead_error)?;
    let ciphertext =
        crypto_chacha20_poly1305::CiphertextWithTag::from_vec(ciphertext_with_tag.to_vec())
            .map_err(map_aead_error)?;
    let request = crypto_chacha20_poly1305::XChaCha20Poly1305DecryptRequest {
        key: &key,
        nonce,
        aad,
        ciphertext: &ciphertext,
    };
    crypto_chacha20_poly1305::decrypt_xchacha20_poly1305(&request)
        .map(Zeroizing::new)
        .map_err(map_aead_error)
}

#[cfg(not(all(
    feature = "chacha20-poly1305",
    any(feature = "native", feature = "wasm")
)))]
pub(super) fn open_xchacha20_poly1305(
    _key: &[u8],
    _nonce: &[u8],
    _aad: &[u8],
    _ciphertext_with_tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OperationError> {
    Err(OperationError::Provider {
        reason: crate::operations::ProviderErrorReason::UnsupportedAlgorithm,
    })
}
