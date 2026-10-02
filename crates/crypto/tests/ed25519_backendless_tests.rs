// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A selected algorithm without a backend must fail through typed operations.

#![cfg(all(feature = "ed25519", not(any(feature = "native", feature = "wasm"))))]

use crypto_core::CryptoError;

#[test]
fn ed25519_facade_fails_closed_without_a_backend() {
    let seed = [0x42; 32];
    let public_key = [0u8; 32];
    let signature = [0u8; 64];

    assert!(matches!(
        reallyme_crypto::ed25519::generate_ed25519_keypair(),
        Err(CryptoError::Unsupported)
    ));
    assert!(matches!(
        reallyme_crypto::ed25519::generate_ed25519_keypair_from_seed(&seed),
        Err(CryptoError::Unsupported)
    ));
    assert!(matches!(
        reallyme_crypto::ed25519::sign_ed25519(&seed, b"message"),
        Err(CryptoError::Unsupported)
    ));
    assert!(matches!(
        reallyme_crypto::ed25519::verify_ed25519(&public_key, b"message", &signature),
        Err(CryptoError::Unsupported)
    ));
}
