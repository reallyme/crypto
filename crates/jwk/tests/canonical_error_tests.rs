// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used, missing_docs)]

use crypto_core::CryptoError;
use envelopes_jwk::{Jwk, JwkOptions, JwtError, OkpJwk};
use serde_json::json;

#[test]
fn public_error_name_is_the_canonical_error_type() {
    let error: CryptoError = JwtError::PRIMITIVE_INVALID_PUBLIC_KEY;
    assert_eq!(error, CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY);
}

#[test]
fn unknown_identity_and_inconsistent_metadata_keep_distinct_reasons() {
    let unknown = Jwk::Okp(OkpJwk {
        kty: "OKP".to_owned(),
        crv: "unregistered".to_owned(),
        x: "AA".to_owned(),
        alg: None,
        use_: None,
        kid: None,
    });
    assert_eq!(
        unknown.public_key_bytes(),
        Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    );
    let conflicting = Jwk::Okp(OkpJwk {
        kty: "EC".to_owned(),
        crv: "Ed25519".to_owned(),
        x: "AA".to_owned(),
        alg: None,
        use_: None,
        kid: None,
    });
    assert_eq!(
        conflicting.public_key_bytes(),
        Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
}

#[test]
fn malformed_shape_is_distinct_from_configured_member_limit() {
    let malformed = serde_json::from_value::<Jwk>(json!({"kty":true})).expect_err("invalid shape");
    assert!(malformed
        .to_string()
        .starts_with(&CryptoError::PRIMITIVE_MALFORMED_JSON.to_string()));
    let mut value = serde_json::Map::new();
    value.insert("kty".to_owned(), json!("OKP"));
    value.insert("crv".to_owned(), json!("Ed25519"));
    value.insert("x".to_owned(), json!("AA"));
    for index in 0..14 {
        value.insert(format!("x-extension-{index}"), json!(null));
    }
    let bounded =
        serde_json::from_value::<Jwk>(serde_json::Value::Object(value)).expect_err("member limit");
    assert!(bounded
        .to_string()
        .starts_with(&CryptoError::PRIMITIVE_RESOURCE_LIMIT_EXCEEDED.to_string()));
}

#[test]
fn caller_key_identifier_noncharacter_is_not_an_internal_output_failure() {
    let options = JwkOptions {
        kid: Some("\u{fdd0}".to_owned()),
        ..JwkOptions::default()
    };
    assert_eq!(
        envelopes_jwk::mlkem512_public_key_to_jwk_jcs(&[0_u8; 800], options),
        Err(CryptoError::PRIMITIVE_INVALID_ENCODING)
    );
}
