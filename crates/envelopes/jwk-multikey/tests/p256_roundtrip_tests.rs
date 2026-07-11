// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used, missing_docs)]

use crypto_core::Algorithm;
use crypto_dispatch::{generate_keypair, public_key_to_multikey};
use envelopes_jwk::JwkOptions;
use envelopes_jwk_multikey::*;

#[test]
fn p256_multikey_jwk_roundtrip() {
    // Generate a REAL P-256 keypair via dispatch
    let (public_key, _secret_key) =
        generate_keypair(Algorithm::P256).expect("generate p256 keypair");

    // Convert public key → multikey using dispatch
    let multikey =
        public_key_to_multikey(Algorithm::P256, &public_key).expect("public key → multikey");

    // multikey → jwk
    let jwk = multikey_to_jwk(&multikey, JwkOptions::default()).expect("multikey → jwk");

    // jwk → multikey
    let out = jwk_to_multikey(&jwk).expect("jwk → multikey");

    assert_eq!(multikey, out);
}
