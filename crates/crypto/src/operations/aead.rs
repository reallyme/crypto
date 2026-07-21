// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Semantic owner for AEAD seal and open operations.

mod aes_gcm;
mod aes_gcm_siv;
mod chacha20_poly1305;
#[cfg(any(
    all(
        feature = "aes",
        any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))
    ),
    all(feature = "aes-gcm-siv", any(feature = "native", feature = "wasm")),
    all(
        feature = "chacha20-poly1305",
        any(feature = "native", feature = "wasm")
    )
))]
mod error;

use crypto_core::AeadAlgorithm;
use zeroize::Zeroizing;

use super::OperationError;
use crate::secret_material::{bind_operation_policy, SecretMaterialOperation};

/// Encrypts `plaintext` and returns `ciphertext || tag`.
///
/// The operation layer owns AEAD algorithm selection so dispatch, protobuf, FFI,
/// and SDK adapters cannot diverge on nonce, tag, or authentication semantics.
pub fn seal(
    algorithm: AeadAlgorithm,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::AeadSeal);
    match algorithm {
        AeadAlgorithm::Aes128Gcm => aes_gcm::seal_aes128_gcm(key, nonce, aad, plaintext),
        AeadAlgorithm::Aes192Gcm => aes_gcm::seal_aes192_gcm(key, nonce, aad, plaintext),
        AeadAlgorithm::Aes256Gcm => aes_gcm::seal_aes256_gcm(key, nonce, aad, plaintext),
        AeadAlgorithm::Aes256GcmSiv => aes_gcm_siv::seal_aes256_gcm_siv(key, nonce, aad, plaintext),
        AeadAlgorithm::ChaCha20Poly1305 => {
            chacha20_poly1305::seal_chacha20_poly1305(key, nonce, aad, plaintext)
        }
        AeadAlgorithm::XChaCha20Poly1305 => {
            chacha20_poly1305::seal_xchacha20_poly1305(key, nonce, aad, plaintext)
        }
    }
}

/// Decrypts and authenticates `ciphertext || tag`.
///
/// Returned plaintext is zeroizing so adapters cannot accidentally retain
/// decrypted material longer than their public API requires.
pub fn open(
    algorithm: AeadAlgorithm,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext_with_tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::AeadOpen);
    match algorithm {
        AeadAlgorithm::Aes128Gcm => aes_gcm::open_aes128_gcm(key, nonce, aad, ciphertext_with_tag),
        AeadAlgorithm::Aes192Gcm => aes_gcm::open_aes192_gcm(key, nonce, aad, ciphertext_with_tag),
        AeadAlgorithm::Aes256Gcm => aes_gcm::open_aes256_gcm(key, nonce, aad, ciphertext_with_tag),
        AeadAlgorithm::Aes256GcmSiv => {
            aes_gcm_siv::open_aes256_gcm_siv(key, nonce, aad, ciphertext_with_tag)
        }
        AeadAlgorithm::ChaCha20Poly1305 => {
            chacha20_poly1305::open_chacha20_poly1305(key, nonce, aad, ciphertext_with_tag)
        }
        AeadAlgorithm::XChaCha20Poly1305 => {
            chacha20_poly1305::open_xchacha20_poly1305(key, nonce, aad, ciphertext_with_tag)
        }
    }
}
