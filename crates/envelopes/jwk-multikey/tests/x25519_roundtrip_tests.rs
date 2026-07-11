// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used, missing_docs)]

use codec_multikey::encode_multikey;
use envelopes_jwk::JwkOptions;
use envelopes_jwk_multikey::*;

#[test]
fn x25519_multikey_jwk_roundtrip() {
    // Deterministic 32-byte X25519 public key
    let public_key = [9u8; 32];

    // OK Canonical X25519 multikey
    let multikey = encode_multikey("x25519-pub", &public_key).expect("encode multikey");

    let jwk = multikey_to_jwk(
        &multikey,
        JwkOptions {
            alg: true,
            use_enc: true, // Required for X25519 key agreement JWKs.
            ..Default::default()
        },
    )
    .expect("multikey → jwk");

    let out = jwk_to_multikey(&jwk).expect("jwk → multikey");

    assert_eq!(multikey, out);
}
