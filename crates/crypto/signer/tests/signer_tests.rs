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
#[cfg(all(feature = "native", feature = "ed25519"))]
#[test]
fn dispatch_signer_signs_and_verifies() {
    use crypto_core::Algorithm;
    use crypto_dispatch::{generate_keypair, verify};
    use crypto_signer::{DispatchSigner, Signer};

    let (public_key, secret_key) =
        generate_keypair(Algorithm::Ed25519).expect("native key generation should succeed");

    let signer = DispatchSigner::new(Algorithm::Ed25519, secret_key);
    let message = b"signer lane test";
    let signature = signer
        .sign(message)
        .expect("native signer should produce a signature");

    verify(Algorithm::Ed25519, &public_key, message, &signature).expect("verification failed");
}

#[cfg(all(feature = "native", feature = "ed25519"))]
#[test]
fn dispatch_verifier_accepts_valid_and_rejects_tampered() {
    use crypto_core::Algorithm;
    use crypto_dispatch::generate_keypair;
    use crypto_signer::{DispatchSigner, DispatchVerifier, Signer, Verifier};

    let (public_key, secret_key) =
        generate_keypair(Algorithm::Ed25519).expect("native key generation should succeed");
    let signer = DispatchSigner::new(Algorithm::Ed25519, secret_key);
    let verifier = DispatchVerifier::new(Algorithm::Ed25519, public_key);

    let message = b"verifier lane test";
    let mut signature = signer
        .sign(message)
        .expect("native signer should produce a signature");

    verifier
        .verify(message, &signature)
        .expect("valid signature should verify");

    // A tampered signature must fail closed with the invalid-signature kind.
    signature[0] ^= 0x01;
    let error = verifier
        .verify(message, &signature)
        .expect_err("tampered signature must not verify");
    assert!(error.is_signature_invalid());

    // A tampered message must fail the same way.
    signature[0] ^= 0x01;
    let error = verifier
        .verify(b"different message", &signature)
        .expect_err("wrong message must not verify");
    assert!(error.is_signature_invalid());
}

#[cfg(feature = "wasm")]
#[test]
fn wasm_feature_lane_executes_tests() {
    let package_name = std::env::var("CARGO_PKG_NAME")
        .expect("cargo should set CARGO_PKG_NAME for integration tests");
    assert_eq!(package_name, "reallyme-crypto-signer");
}
