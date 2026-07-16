// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used, missing_docs)]

#[path = "common/mod.rs"]
mod common;

use envelopes_jwk::{p256::p256_public_key_to_jwk, p256::p256_public_key_to_jwk_jcs, JwkOptions};

#[test]
fn p256_accepts_uncompressed() {
    let mut pk = vec![0x04];
    pk.extend([1u8; 64]);

    let jwk = p256_public_key_to_jwk(&pk, JwkOptions::default()).unwrap();
    assert_eq!(jwk.crv, "P-256");
    assert_eq!(jwk.kty, "EC");
}

#[test]
fn p256_jcs() {
    let mut pk = vec![0x04];
    pk.extend([3u8; 64]);

    let jcs = p256_public_key_to_jwk_jcs(&pk, JwkOptions::default()).unwrap();
    common::assert_jcs(&jcs);
}
