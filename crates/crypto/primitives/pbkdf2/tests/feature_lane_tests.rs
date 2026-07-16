// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]

#[test]
fn selected_feature_lane_compiles() {
    const {
        assert!(cfg!(any(feature = "native", feature = "wasm")));
    }
}
