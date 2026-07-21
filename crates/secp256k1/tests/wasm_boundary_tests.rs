// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! BIP-340 package-owned WASM coverage.

#![cfg(all(feature = "wasm", target_arch = "wasm32"))]

use crypto_secp256k1::{
    derive_bip340_schnorr_public_key, sign_bip340_schnorr, verify_bip340_schnorr,
};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

const SECRET_KEY: [u8; 32] = [0x21; 32];
const MESSAGE32: [u8; 32] = [0x42; 32];
const AUX_RAND32: [u8; 32] = [0x63; 32];

#[wasm_bindgen_test]
fn wasm_lane_uses_package_owned_rust_bip340() {
    let public_key = derive_bip340_schnorr_public_key(&SECRET_KEY).unwrap();
    let signature = sign_bip340_schnorr(&SECRET_KEY, &MESSAGE32, &AUX_RAND32).unwrap();

    verify_bip340_schnorr(&signature, &MESSAGE32, &public_key).unwrap();
    assert!(verify_bip340_schnorr(&signature, &[0x24; 32], &public_key).is_err());
}
