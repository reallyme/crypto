// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use zeroize::Zeroizing;

use crate::traits::{AeadCipherAlgorithm, AeadParams};
use crate::AlgorithmError;
use crypto_core::AeadAlgorithm;

/// ChaCha20-Poly1305 AEAD adapter.
pub struct ChaCha20Poly1305Algo;

impl AeadCipherAlgorithm for ChaCha20Poly1305Algo {
    const ALG: AeadAlgorithm = AeadAlgorithm::ChaCha20Poly1305;

    fn encrypt(params: &AeadParams<'_>, plaintext: &[u8]) -> Result<Vec<u8>, AlgorithmError> {
        #[cfg(any(feature = "native", feature = "wasm"))]
        {
            let key = crypto_chacha20_poly1305::ChaCha20Poly1305Key::from_slice(params.key)?;
            let nonce = crypto_chacha20_poly1305::ChaCha20Poly1305Nonce::from_slice(params.nonce)?;
            let request = crypto_chacha20_poly1305::EncryptRequest {
                key: &key,
                nonce,
                aad: params.aad,
                plaintext,
            };
            let sealed = crypto_chacha20_poly1305::encrypt(&request)?;
            Ok(sealed.into_vec())
        }

        #[cfg(not(any(feature = "native", feature = "wasm")))]
        {
            let _ = (params, plaintext);
            Err(AlgorithmError::UnsupportedAeadAlgorithm(Self::ALG))
        }
    }

    fn decrypt(
        params: &AeadParams<'_>,
        ciphertext_with_tag: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, AlgorithmError> {
        #[cfg(any(feature = "native", feature = "wasm"))]
        {
            let key = crypto_chacha20_poly1305::ChaCha20Poly1305Key::from_slice(params.key)?;
            let nonce = crypto_chacha20_poly1305::ChaCha20Poly1305Nonce::from_slice(params.nonce)?;
            let ciphertext = crypto_chacha20_poly1305::CiphertextWithTag::from_vec(
                ciphertext_with_tag.to_vec(),
            )?;
            let request = crypto_chacha20_poly1305::DecryptRequest {
                key: &key,
                nonce,
                aad: params.aad,
                ciphertext: &ciphertext,
            };
            let plaintext = crypto_chacha20_poly1305::decrypt(&request)?;
            Ok(Zeroizing::new(plaintext))
        }

        #[cfg(not(any(feature = "native", feature = "wasm")))]
        {
            let _ = (params, ciphertext_with_tag);
            Err(AlgorithmError::UnsupportedAeadAlgorithm(Self::ALG))
        }
    }
}

/// XChaCha20-Poly1305 AEAD adapter.
pub struct XChaCha20Poly1305Algo;

impl AeadCipherAlgorithm for XChaCha20Poly1305Algo {
    const ALG: AeadAlgorithm = AeadAlgorithm::XChaCha20Poly1305;

    fn encrypt(params: &AeadParams<'_>, plaintext: &[u8]) -> Result<Vec<u8>, AlgorithmError> {
        #[cfg(any(feature = "native", feature = "wasm"))]
        {
            let key = crypto_chacha20_poly1305::ChaCha20Poly1305Key::from_slice(params.key)?;
            let nonce = crypto_chacha20_poly1305::XChaCha20Poly1305Nonce::from_slice(params.nonce)?;
            let request = crypto_chacha20_poly1305::XChaCha20Poly1305EncryptRequest {
                key: &key,
                nonce,
                aad: params.aad,
                plaintext,
            };
            let sealed = crypto_chacha20_poly1305::encrypt_xchacha20_poly1305(&request)?;
            Ok(sealed.into_vec())
        }

        #[cfg(not(any(feature = "native", feature = "wasm")))]
        {
            let _ = (params, plaintext);
            Err(AlgorithmError::UnsupportedAeadAlgorithm(Self::ALG))
        }
    }

    fn decrypt(
        params: &AeadParams<'_>,
        ciphertext_with_tag: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, AlgorithmError> {
        #[cfg(any(feature = "native", feature = "wasm"))]
        {
            let key = crypto_chacha20_poly1305::ChaCha20Poly1305Key::from_slice(params.key)?;
            let nonce = crypto_chacha20_poly1305::XChaCha20Poly1305Nonce::from_slice(params.nonce)?;
            let ciphertext = crypto_chacha20_poly1305::CiphertextWithTag::from_vec(
                ciphertext_with_tag.to_vec(),
            )?;
            let request = crypto_chacha20_poly1305::XChaCha20Poly1305DecryptRequest {
                key: &key,
                nonce,
                aad: params.aad,
                ciphertext: &ciphertext,
            };
            let plaintext = crypto_chacha20_poly1305::decrypt_xchacha20_poly1305(&request)?;
            Ok(Zeroizing::new(plaintext))
        }

        #[cfg(not(any(feature = "native", feature = "wasm")))]
        {
            let _ = (params, ciphertext_with_tag);
            Err(AlgorithmError::UnsupportedAeadAlgorithm(Self::ALG))
        }
    }
}
