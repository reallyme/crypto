// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used, missing_docs)]

use envelopes_jwk::{
    ed25519_public_key_to_jwk, public_key_bytes_from_jwk, Jwk, JwkOptions, Jwks, JwtError,
};

#[test]
fn jwks_wraps_public_keys() {
    let public_key = [7_u8; 32];
    let ed25519 = ed25519_public_key_to_jwk(&public_key, JwkOptions::default()).unwrap();
    let jwks = Jwks::new(vec![Jwk::Okp(ed25519.into())]);

    let encoded = serde_json::to_string(&jwks).unwrap();
    let decoded: Jwks = serde_json::from_str(&encoded).unwrap();

    assert_eq!(decoded.keys.len(), 1);
    assert_eq!(decoded.keys[0].public_key_bytes().unwrap(), public_key);
}

#[test]
fn public_key_extractor_rejects_malformed_akp_key() {
    let jwk = Jwk::Akp(envelopes_jwk::AkpJwk {
        kty: "AKP".into(),
        alg: "ML-DSA-44".into(),
        public_key: "AA".into(),
        use_: None,
        kid: None,
    });

    assert_eq!(
        public_key_bytes_from_jwk(&jwk),
        Err(JwtError::InvalidMlDsa44Key)
    );
}

#[test]
fn public_key_extractor_rejects_wrong_ed25519_length() {
    let value = serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "AQID"
    });
    let jwk: Jwk = serde_json::from_value(value).unwrap();

    assert_eq!(
        public_key_bytes_from_jwk(&jwk),
        Err(JwtError::InvalidEd25519Key)
    );
}

#[test]
fn public_jwk_deserialization_rejects_private_key_members() {
    for private_member in [
        "d",
        "p",
        "q",
        "dp",
        "dq",
        "qi",
        "oth",
        "k",
        "priv",
        "privateKey",
        "secretKey",
    ] {
        let mut value = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        });
        value[private_member] = serde_json::Value::String("redacted-test-value".into());

        assert!(serde_json::from_value::<Jwk>(value).is_err());
    }
}

#[test]
fn public_jwk_deserialization_keeps_benign_extensions_compatible() {
    let value = serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "x-reallyme-future": "compatible"
    });

    assert!(serde_json::from_value::<Jwk>(value).is_ok());
}
