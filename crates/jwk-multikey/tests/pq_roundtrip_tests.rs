// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used, missing_docs)]

use codec_multikey::encode_multikey;
use envelopes_jwk::JwkOptions;
use envelopes_jwk_multikey::{jwk_to_multikey, multikey_to_jwk};

fn assert_roundtrip(codec: &str, length: usize, curve: &str) {
    let public_key = vec![0x5a; length];
    let multikey = encode_multikey(codec, &public_key).expect("valid public-key fixture");
    let jwk = multikey_to_jwk(
        &multikey,
        JwkOptions {
            alg: true,
            use_sig: curve.starts_with("ML-DSA"),
            use_enc: curve.starts_with("ML-KEM"),
            kid: None,
        },
    )
    .expect("supported PQ multikey");
    assert_eq!(jwk_to_multikey(&jwk).expect("supported PQ JWK"), multikey);
}

#[test]
fn all_supported_pq_parameter_sets_roundtrip() {
    for (codec, length, curve) in [
        ("mldsa-44-pub", 1312, "ML-DSA-44"),
        ("mldsa-65-pub", 1952, "ML-DSA-65"),
        ("mldsa-87-pub", 2592, "ML-DSA-87"),
        ("mlkem-512-pub", 800, "ML-KEM-512"),
        ("mlkem-768-pub", 1184, "ML-KEM-768"),
        ("mlkem-1024-pub", 1568, "ML-KEM-1024"),
    ] {
        assert_roundtrip(codec, length, curve);
    }
}
