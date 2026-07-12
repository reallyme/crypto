// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::unwrap_used
)]
#[cfg(feature = "native")]
#[test]
fn native_feature_lane_executes_tests() {
    let package_name = std::env::var("CARGO_PKG_NAME")
        .expect("cargo should set CARGO_PKG_NAME for integration tests");
    assert_eq!(package_name, "reallyme-crypto-dispatch");
}

#[cfg(feature = "wasm")]
#[test]
fn wasm_feature_lane_executes_tests() {
    let package_name = std::env::var("CARGO_PKG_NAME")
        .expect("cargo should set CARGO_PKG_NAME for integration tests");
    assert_eq!(package_name, "reallyme-crypto-dispatch");
}

#[cfg(not(feature = "ed25519"))]
#[test]
fn disabled_signature_algorithm_fails_closed() {
    let err = crypto_dispatch::generate_keypair(crypto_core::Algorithm::Ed25519)
        .expect_err("disabled Ed25519 dispatch must fail closed");

    match err {
        crypto_dispatch::AlgorithmError::UnsupportedAlgorithm(crypto_core::Algorithm::Ed25519) => {}
        _ => panic!("disabled Ed25519 returned an unexpected error variant"),
    }
}

#[cfg(not(feature = "sha3"))]
#[test]
fn disabled_hash_algorithm_fails_closed() {
    let err = crypto_dispatch::hash_digest(crypto_core::HashAlgorithm::Sha3_256, b"message")
        .expect_err("disabled SHA-3 dispatch must fail closed");

    match err {
        crypto_dispatch::AlgorithmError::UnsupportedHashAlgorithm(
            crypto_core::HashAlgorithm::Sha3_256,
        ) => {}
        _ => panic!("disabled SHA-3 returned an unexpected error variant"),
    }
}

#[cfg(not(feature = "aes-gcm-siv"))]
#[test]
fn disabled_aead_algorithm_fails_closed() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let params = crypto_dispatch::AeadParams {
        key: &key,
        nonce: &nonce,
        aad: b"feature-lane",
    };

    let err =
        crypto_dispatch::aead_encrypt(crypto_core::AeadAlgorithm::Aes256GcmSiv, &params, b"data")
            .expect_err("disabled AES-GCM-SIV dispatch must fail closed");

    match err {
        crypto_dispatch::AlgorithmError::UnsupportedAeadAlgorithm(
            crypto_core::AeadAlgorithm::Aes256GcmSiv,
        ) => {}
        _ => panic!("disabled AES-GCM-SIV returned an unexpected error variant"),
    }
}

#[cfg(not(feature = "hmac"))]
#[test]
fn disabled_mac_algorithm_fails_closed() {
    let params = crypto_dispatch::MacParams { key: b"key" };
    let err = crypto_dispatch::mac_authenticate(
        crypto_core::MacAlgorithm::HmacSha256,
        &params,
        b"message",
    )
    .expect_err("disabled HMAC dispatch must fail closed");

    match err {
        crypto_dispatch::AlgorithmError::UnsupportedMacAlgorithm(
            crypto_core::MacAlgorithm::HmacSha256,
        ) => {}
        _ => panic!("disabled HMAC returned an unexpected error variant"),
    }
}
