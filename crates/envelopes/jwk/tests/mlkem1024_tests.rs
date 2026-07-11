// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used, missing_docs)]

use envelopes_jwk::{
    mlkem1024_public_key_to_jwk, mlkem1024_public_key_to_jwk_jcs, test_support, JwkOptions,
};

#[test]
fn mlkem1024_jwk_basic() {
    let pk = vec![0xCC; 1568];

    let jwk = mlkem1024_public_key_to_jwk(&pk, JwkOptions::default()).unwrap();
    assert_eq!(jwk.kty, "AKP");
    assert_eq!(jwk.alg, "ML-KEM-1024");
}

#[test]
fn mlkem1024_jcs() {
    let pk = vec![0xDD; 1568];
    let jcs = mlkem1024_public_key_to_jwk_jcs(&pk, JwkOptions::default()).unwrap();

    test_support::assert_jcs(&jcs);
}
