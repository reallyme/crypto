// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::assertions_on_constants)]

//! Feature-lane guard tests for the RSA primitive.

#[cfg(any(feature = "native", feature = "wasm"))]
use crypto_rsa::{RSA_MAX_MODULUS_BITS, RSA_MIN_MODULUS_BITS};

#[cfg(any(feature = "native", feature = "wasm"))]
fn assert_rsa_width_policy() {
    assert_eq!(RSA_MIN_MODULUS_BITS, 1024);
    assert_eq!(RSA_MAX_MODULUS_BITS, 8192);
}

// A disabled lane must not make a valid narrow consumer configuration fail.
// Both selected lanes retain the same public width-policy assertions.
#[cfg(feature = "native")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn native_feature_lane_executes_tests() {
    assert_rsa_width_policy();
}

#[cfg(feature = "wasm")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn wasm_feature_lane_executes_tests() {
    assert_rsa_width_policy();
}
