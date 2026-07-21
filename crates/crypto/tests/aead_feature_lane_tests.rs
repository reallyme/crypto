// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![cfg(all(
    not(feature = "aes"),
    not(feature = "aes-gcm-siv"),
    not(feature = "chacha20-poly1305")
))]

use reallyme_crypto::operations::{OperationError, ProviderErrorReason};
use reallyme_crypto::AeadAlgorithm;

const AEAD_ALGORITHMS: &[AeadAlgorithm] = &[
    AeadAlgorithm::Aes128Gcm,
    AeadAlgorithm::Aes192Gcm,
    AeadAlgorithm::Aes256Gcm,
    AeadAlgorithm::Aes256GcmSiv,
    AeadAlgorithm::ChaCha20Poly1305,
    AeadAlgorithm::XChaCha20Poly1305,
];

#[test]
fn disabled_aead_providers_fail_closed_for_seal_and_open() {
    for algorithm in AEAD_ALGORITHMS.iter().copied() {
        assert_eq!(
            reallyme_crypto::operations::aead::seal(
                algorithm,
                b"key",
                b"nonce",
                b"aad",
                b"plaintext",
            ),
            Err(OperationError::Provider {
                reason: ProviderErrorReason::UnsupportedAlgorithm,
            }),
        );
        assert_eq!(
            reallyme_crypto::operations::aead::open(
                algorithm,
                b"key",
                b"nonce",
                b"aad",
                b"ciphertext",
            ),
            Err(OperationError::Provider {
                reason: ProviderErrorReason::UnsupportedAlgorithm,
            }),
        );
    }
}
