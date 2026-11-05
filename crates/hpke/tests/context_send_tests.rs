// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compile-time ownership-contract coverage for live HPKE contexts.

#![allow(missing_docs)]
#![cfg(feature = "backend-native")]

use crypto_hpke::{HpkeReceiverContext, HpkeSenderContext};

#[test]
fn primitive_live_contexts_are_send() {
    assert_send::<HpkeSenderContext>();
    assert_send::<HpkeReceiverContext>();
}

fn assert_send<T: Send>() {}
