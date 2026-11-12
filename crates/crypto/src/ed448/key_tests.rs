// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::Ed448Key;
use secrecy::ExposeSecret;
use zeroize::Zeroize;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
#[allow(clippy::unwrap_used)]
fn explicit_cleanup_erases_live_seed_storage_and_public_association() {
    let mut key = Ed448Key::import(&[0xa5; 57]).unwrap();
    assert!(key.seed.expose_secret().iter().all(|byte| *byte == 0xa5));
    key.zeroize();
    assert!(key.seed.expose_secret().iter().all(|byte| *byte == 0));
    assert_eq!(key.public, [0; 57]);
    assert!(key.destroyed);
}
