// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used, missing_docs)]

use codec_multikey::encode_multikey;
use envelopes_jwk::JwkOptions;
use envelopes_jwk_multikey::{jwk_to_multikey, multikey_to_jwk};

#[test]
fn mldsa87_multikey_jwk_roundtrip() {
    // Deterministic 2592-byte ML-DSA-87 public key
    let public_key = vec![0xAB; 2592];

    // OK MUST use correct multicodec name
    let multikey = encode_multikey("mldsa-87-pub", &public_key).expect("encode multikey");

    let jwk = multikey_to_jwk(&multikey, JwkOptions::default()).expect("multikey → jwk");

    let out = jwk_to_multikey(&jwk).expect("jwk → multikey");

    assert_eq!(multikey, out);
}
