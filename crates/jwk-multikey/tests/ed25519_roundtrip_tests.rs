// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used, missing_docs)]

use codec_multikey::encode_multikey;
use envelopes_jwk::JwkOptions;
use envelopes_jwk_multikey::{jwk_to_multikey, multikey_to_jwk};

#[test]
fn ed25519_multikey_jwk_roundtrip() {
    let public_key =
        codec_base64url::base64url_to_bytes("bd_77DacquIWpfuZCAps4BN5nYvqANOYBNepDXNQLYI")
            .expect("conformance public key");

    // OK Use the CORRECT multicodec name
    let multikey = encode_multikey("ed25519-pub", &public_key).expect("encode multikey");

    let jwk = multikey_to_jwk(&multikey, JwkOptions::default()).expect("multikey → jwk");

    let out = jwk_to_multikey(&jwk).expect("jwk → multikey");

    assert_eq!(multikey, out);
}
