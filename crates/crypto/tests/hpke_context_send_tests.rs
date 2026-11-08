// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compile-time ownership-contract coverage for facade and raw HPKE contexts.

#![allow(missing_docs)]
#![cfg(feature = "hpke-api")]

use reallyme_crypto::hpke::{
    HpkeReceiverContext, HpkeSenderContext, RawHpkeReceiverContext, RawHpkeSenderContext,
};

#[test]
fn facade_and_raw_live_contexts_are_send() {
    assert_send::<HpkeSenderContext>();
    assert_send::<HpkeReceiverContext>();
    assert_send::<RawHpkeSenderContext>();
    assert_send::<RawHpkeReceiverContext>();
}

fn assert_send<T: Send>() {}
