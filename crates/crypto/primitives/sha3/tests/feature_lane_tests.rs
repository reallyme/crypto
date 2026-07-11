// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

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
