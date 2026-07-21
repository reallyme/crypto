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
    assert_eq!(package_name, "reallyme-crypto-aes256-gcm");
}

#[cfg(all(feature = "wasm", not(target_arch = "wasm32")))]
#[test]
fn wasm_feature_is_enabled_but_runtime_tests_require_wasm32_target() {
    // This test ensures `cargo test --features wasm` on host is not a silent no-op.
    // Real wasm adapter execution tests live behind `target_arch = "wasm32"`.
    let package_name = std::env::var("CARGO_PKG_NAME")
        .expect("cargo should set CARGO_PKG_NAME for integration tests");
    assert_eq!(package_name, "reallyme-crypto-aes256-gcm");
}
