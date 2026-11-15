// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

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
        crypto_dispatch::AlgorithmError::PROVIDER_UNSUPPORTED_ALGORITHM => {}
        _ => panic!("disabled Ed25519 returned an unexpected error variant"),
    }
}

#[cfg(all(
    target_arch = "wasm32",
    feature = "wasm",
    feature = "secp256k1",
    feature = "ml-kem-768",
    not(feature = "native")
))]
#[wasm_bindgen_test::wasm_bindgen_test]
fn reduced_wasm_registry_respects_lane_and_key_family() {
    use crypto_core::{Algorithm, CryptoError};
    use crypto_dispatch::{provider_decision, ProviderLane, ProviderOperation};

    const UNSUPPORTED: CryptoError = CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM;
    let signing = provider_decision(ProviderOperation::Sign, Algorithm::Secp256k1);
    let decapsulation = provider_decision(ProviderOperation::KemDecapsulate, Algorithm::MlKem768);
    assert!(signing.is_selected() && decapsulation.is_selected());
    assert_eq!(signing.lane, ProviderLane::Wasm);
    assert_eq!(decapsulation.lane, ProviderLane::Wasm);

    assert_eq!(
        crypto_dispatch::derive_keypair(Algorithm::Secp256k1, &[]).err(),
        Some(UNSUPPORTED)
    );
    assert_eq!(
        crypto_dispatch::sign(Algorithm::MlKem768, &[], &[]).err(),
        Some(UNSUPPORTED)
    );
    assert_eq!(
        crypto_dispatch::kem_decapsulate(Algorithm::Secp256k1, &[], &[]).err(),
        Some(UNSUPPORTED)
    );
    assert_eq!(
        crypto_dispatch::kem_decapsulate(Algorithm::MlKem768, &[], &[]).err(),
        Some(CryptoError::PRIMITIVE_INVALID_KEY),
    );
}
