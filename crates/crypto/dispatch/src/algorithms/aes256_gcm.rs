// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use zeroize::Zeroizing;

use crate::traits::{AeadCipherAlgorithm, AeadParams};
use crate::AlgorithmError;
use crypto_core::AeadAlgorithm;

/// AES-256-GCM AEAD adapter.
pub struct Aes256GcmAlgo;

impl AeadCipherAlgorithm for Aes256GcmAlgo {
    const ALG: AeadAlgorithm = AeadAlgorithm::Aes256Gcm;

    fn encrypt(params: &AeadParams<'_>, plaintext: &[u8]) -> Result<Vec<u8>, AlgorithmError> {
        #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
        {
            let key = crypto_aes256_gcm::Aes256GcmKey::from_slice(params.key)?;
            let nonce = crypto_aes256_gcm::Aes256GcmNonce::from_slice(params.nonce)?;
            let request = crypto_aes256_gcm::EncryptRequest {
                key: &key,
                nonce,
                aad: params.aad,
                plaintext,
            };
            let sealed = crypto_aes256_gcm::encrypt(&request)?;
            Ok(sealed.into_vec())
        }

        #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
        {
            let _ = (params, plaintext);
            Err(AlgorithmError::UnsupportedAeadAlgorithm(Self::ALG))
        }
    }

    fn decrypt(
        params: &AeadParams<'_>,
        ciphertext_with_tag: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, AlgorithmError> {
        #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
        {
            let key = crypto_aes256_gcm::Aes256GcmKey::from_slice(params.key)?;
            let nonce = crypto_aes256_gcm::Aes256GcmNonce::from_slice(params.nonce)?;
            let ciphertext =
                crypto_aes256_gcm::CiphertextWithTag::from_vec(ciphertext_with_tag.to_vec())?;
            let request = crypto_aes256_gcm::DecryptRequest {
                key: &key,
                nonce,
                aad: params.aad,
                ciphertext: &ciphertext,
            };
            let plaintext = crypto_aes256_gcm::decrypt(&request)?;
            Ok(Zeroizing::new(plaintext))
        }

        #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
        {
            let _ = (params, ciphertext_with_tag);
            Err(AlgorithmError::UnsupportedAeadAlgorithm(Self::ALG))
        }
    }
}
