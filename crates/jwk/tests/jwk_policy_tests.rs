// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used, missing_docs)]

use envelopes_jwk::{public_key_bytes_from_jwk, Jwk, Jwks};
use serde_json::Value;

#[test]
fn shared_jwk_metadata_policy() {
    let policy: Value = serde_json::from_str(include_str!("../../../vectors/jwk_policy.json"))
        .expect("committed JWK policy vector must parse");
    for value in policy["valid_jwk"]
        .as_array()
        .expect("valid JWK cases must be an array")
    {
        let jwk: Jwk = serde_json::from_value(value.clone()).expect("valid JWK must parse");
        public_key_bytes_from_jwk(&jwk).expect("valid JWK must decode");
    }
    for value in policy["invalid_jwk"]
        .as_array()
        .expect("invalid JWK cases must be an array")
    {
        let rejected = serde_json::from_value::<Jwk>(value.clone())
            .map(|jwk| public_key_bytes_from_jwk(&jwk).is_err())
            .unwrap_or(true);
        assert!(rejected, "invalid JWK must be rejected");
    }
    for value in policy["valid_jwks"]
        .as_array()
        .expect("valid JWKS cases must be an array")
    {
        let keys: Jwks = serde_json::from_value(value.clone()).expect("valid JWKS must parse");
        assert_eq!(keys.keys.len(), 1);
        public_key_bytes_from_jwk(&keys.keys[0]).expect("valid JWKS key must decode");
    }
}
