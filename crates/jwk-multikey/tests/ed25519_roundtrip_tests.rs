// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used, missing_docs)]

use codec_multikey::encode_multikey;
use envelopes_jwk::JwkOptions;
use envelopes_jwk_multikey::{jwk_to_multikey, multikey_to_jwk};

#[test]
fn ed25519_multikey_jwk_roundtrip() {
    // Deterministic 32-byte Ed25519 public key
    let public_key = [7u8; 32];

    // OK Use the CORRECT multicodec name
    let multikey = encode_multikey("ed25519-pub", &public_key).expect("encode multikey");

    let jwk = multikey_to_jwk(&multikey, JwkOptions::default()).expect("multikey → jwk");

    let out = jwk_to_multikey(&jwk).expect("jwk → multikey");

    assert_eq!(multikey, out);
}
