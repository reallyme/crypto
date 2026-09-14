// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]

#[test]
#[cfg(feature = "native")]
fn native_feature_lane_executes_tests() {
    assert_eq!(env!("CARGO_PKG_NAME"), "reallyme-crypto-sha3");
}

#[test]
#[cfg(feature = "wasm")]
fn wasm_feature_lane_executes_tests() {
    assert_eq!(env!("CARGO_PKG_NAME"), "reallyme-crypto-sha3");
}
