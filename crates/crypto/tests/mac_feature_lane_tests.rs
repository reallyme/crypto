// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Feature-off tests for the MAC operation owner.

#![allow(missing_docs)]
#![cfg(not(feature = "hmac"))]

use reallyme_crypto::MacAlgorithm;

#[test]
fn disabled_mac_provider_fails_closed_for_authenticate_and_verify() {
    for algorithm in [
        MacAlgorithm::HmacSha256,
        MacAlgorithm::HmacSha384,
        MacAlgorithm::HmacSha512,
    ] {
        assert_eq!(
            reallyme_crypto::operations::mac::authenticate(algorithm, b"key", b"message"),
            Err(crypto_core::CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
        );
        assert_eq!(
            reallyme_crypto::operations::mac::verify(algorithm, b"key", b"message", b"tag",),
            Err(crypto_core::CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
        );
    }
}
