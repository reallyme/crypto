// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used, missing_docs)]

use codec_multikey::encode_multikey;
use envelopes_jwk::JwkOptions;
use envelopes_jwk_multikey::*;

#[test]
fn mlkem1024_multikey_jwk_roundtrip() {
    // Deterministic 1568-byte ML-KEM-1024 public key
    let public_key = vec![0xCD; 1568];

    // OK MUST use correct multicodec name
    let multikey = encode_multikey("mlkem-1024-pub", &public_key).expect("encode multikey");

    let jwk = multikey_to_jwk(&multikey, JwkOptions::default()).expect("multikey → jwk");

    let out = jwk_to_multikey(&jwk).expect("jwk → multikey");

    assert_eq!(multikey, out);
}
