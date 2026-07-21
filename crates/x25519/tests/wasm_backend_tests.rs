// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! WASM tests proving X25519 uses the package-owned Rust implementation.

#![allow(clippy::unwrap_used)]
#![cfg(all(feature = "wasm", target_arch = "wasm32"))]

use crypto_x25519::{derive_x25519_shared_secret, generate_x25519_keypair_from_seed};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn wasm_lane_uses_package_owned_rust_key_agreement() {
    let (alice_public, alice_secret) = generate_x25519_keypair_from_seed(&[0x41; 32]);
    let (bob_public, bob_secret) = generate_x25519_keypair_from_seed(&[0x42; 32]);

    let alice_shared = derive_x25519_shared_secret(&alice_secret, &bob_public).unwrap();
    let bob_shared = derive_x25519_shared_secret(&bob_secret, &alice_public).unwrap();

    assert_eq!(&*alice_shared, &*bob_shared);
    assert!(derive_x25519_shared_secret(&alice_secret, &[0; 32]).is_err());
}
