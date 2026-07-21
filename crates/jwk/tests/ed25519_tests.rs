// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used, missing_docs)]

#[path = "common/mod.rs"]
mod common;

use envelopes_jwk::{x25519_public_key_to_jwk, x25519_public_key_to_jwk_jcs, JwkOptions};

#[test]
fn x25519_jwk_basic() {
    let pk = [9u8; 32];

    let jwk = x25519_public_key_to_jwk(
        &pk,
        JwkOptions {
            alg: true,
            use_sig: false, // key agreement, not signature
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(jwk.kty, "OKP");
    assert_eq!(jwk.crv, "X25519");
    assert_eq!(jwk.alg.as_deref(), Some("ECDH-ES"));
    assert_eq!(jwk.use_.as_deref(), Some("enc"));
}

#[test]
fn x25519_jwk_jcs() {
    let pk = [2u8; 32];
    let jcs = x25519_public_key_to_jwk_jcs(&pk, JwkOptions::default()).unwrap();

    common::assert_jcs(&jcs);
}
