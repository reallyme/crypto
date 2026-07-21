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
