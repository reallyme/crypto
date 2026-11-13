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

#[cfg(any(feature = "native", feature = "wasm"))]
fn assert_package_name() {
    // Cargo supplies package metadata at compilation. WASM test runtimes do
    // not expose the host environment, so the lane check uses that fixed value.
    let package_name = env!("CARGO_PKG_NAME");
    assert_eq!(package_name, "reallyme-crypto-hkdf");
}

#[cfg(feature = "native")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn native_feature_lane_executes_tests() {
    assert_package_name();
}

#[cfg(feature = "wasm")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn wasm_feature_lane_executes_tests() {
    assert_package_name();
}
