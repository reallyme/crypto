// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]

#[test]
fn selected_feature_lane_compiles() {
    const {
        assert!(cfg!(any(feature = "native", feature = "wasm")));
    }
}
