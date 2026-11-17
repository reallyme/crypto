// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]
#![cfg(any(feature = "native", feature = "wasm"))]

#[test]
fn poly1305_one_time_state_has_drop_cleanup() {
    assert!(core::mem::needs_drop::<poly1305::Poly1305>());
}
