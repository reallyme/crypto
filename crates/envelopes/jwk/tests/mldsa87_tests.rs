// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used, missing_docs)]

#[path = "common/mod.rs"]
mod common;

use envelopes_jwk::{mldsa87_public_key_to_jwk, mldsa87_public_key_to_jwk_jcs, JwkOptions};

#[test]
fn mldsa87_jwk_basic() {
    let pk = vec![0xAA; 2592];

    let jwk = mldsa87_public_key_to_jwk(&pk, JwkOptions::default()).unwrap();
    assert_eq!(jwk.kty, "AKP");
    assert_eq!(jwk.alg, "ML-DSA-87");
}

#[test]
fn mldsa87_jcs() {
    let pk = vec![0xBB; 2592];
    let jcs = mldsa87_public_key_to_jwk_jcs(&pk, JwkOptions::default()).unwrap();

    common::assert_jcs(&jcs);
}
