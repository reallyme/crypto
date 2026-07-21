// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Compile-time coverage for public facade vocabulary re-exports.

use reallyme_crypto::{AeadAlgorithm, Algorithm, CryptoError, HashAlgorithm, MacAlgorithm};

#[test]
fn facade_reexports_public_algorithm_and_error_vocabulary() {
    assert_eq!(Algorithm::Ed25519.as_str(), "Ed25519");
    assert_eq!(AeadAlgorithm::Aes256Gcm.as_str(), "AES-256-GCM");
    assert_eq!(HashAlgorithm::Sha2_256.as_str(), "SHA2-256");
    assert_eq!(MacAlgorithm::HmacSha256.as_str(), "HMAC-SHA-256");
    assert_eq!(MacAlgorithm::HmacSha384.as_str(), "HMAC-SHA-384");

    // A type annotation is sufficient to make removal of the root error
    // re-export a compile-time API regression without constructing an error.
    let error: Option<CryptoError> = None;
    assert!(error.is_none());
}
