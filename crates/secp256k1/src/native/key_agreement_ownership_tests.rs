// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{Secp256k1SharedSecret, SECP256K1_SHARED_SECRET_LEN};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn raw_secret_has_actual_destruction_and_explicit_live_clearing() {
    fn clearing<T: ZeroizeOnDrop>() {}
    clearing::<Secp256k1SharedSecret>();
    // A marker without Drop previously passed trait checks yet left this plain
    // array uncleared. needs_drop distinguishes that ownership defect directly.
    assert!(core::mem::needs_drop::<Secp256k1SharedSecret>());
    let mut secret = Secp256k1SharedSecret([0xa5; SECP256K1_SHARED_SECRET_LEN]);
    assert!(secret.as_bytes().iter().all(|byte| *byte == 0xa5));
    secret.zeroize();
    assert!(secret.as_bytes().iter().all(|byte| *byte == 0));
}
