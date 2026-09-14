// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]
#![allow(clippy::assertions_on_constants)]

#[test]
#[cfg(feature = "native")]
fn native_feature_lane_executes_tests() {
    assert!(cfg!(feature = "native"));
}

#[test]
#[cfg(feature = "wasm")]
fn wasm_feature_lane_executes_tests() {
    assert!(cfg!(feature = "wasm"));
}
