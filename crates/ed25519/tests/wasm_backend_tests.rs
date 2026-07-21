// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! WASM tests proving Ed25519 uses the package-owned Rust implementation.

#![allow(clippy::unwrap_used)]
#![cfg(all(feature = "wasm", target_arch = "wasm32"))]

use crypto_ed25519::{generate_ed25519_keypair_from_seed, sign_ed25519, verify_ed25519};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn wasm_lane_uses_package_owned_rust_signing() {
    let (public_key, secret_key) = generate_ed25519_keypair_from_seed(&[0x7c; 32]);
    let signature = sign_ed25519(&secret_key, b"message").unwrap();

    verify_ed25519(&public_key, b"message", &signature).unwrap();
    assert!(verify_ed25519(&public_key, b"tampered", &signature).is_err());
}
