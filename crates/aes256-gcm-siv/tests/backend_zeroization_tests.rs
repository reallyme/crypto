// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]
#![cfg(any(feature = "native", feature = "wasm"))]

#[test]
fn polyval_keyed_state_has_drop_cleanup() {
    // Check the real authentication backend without inspecting freed memory.
    assert!(core::mem::needs_drop::<polyval::Polyval>());
}
