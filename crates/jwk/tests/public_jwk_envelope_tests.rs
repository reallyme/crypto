// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used, clippy::panic, missing_docs)]

use codec_base64url::bytes_to_base64url;
use envelopes_jwk::{
    ed25519_public_key_to_jwk, p256::p256_public_key_to_jwk, secp256k1_public_key_to_jwk,
    x25519_public_key_to_jwk, Jwk, JwkOptions, JwtError,
};
use serde_json::json;

const P256_GENERATOR_COMPRESSED: [u8; 33] = [
    0x02, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
    0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
    0x96,
];

const SECP256K1_GENERATOR_COMPRESSED: [u8; 33] = [
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
    0x98,
];

#[test]
fn ec_jwk_rejects_mismatched_same_parity_y_coordinates() {
    assert_ec_wrong_y_rejected(CurveCase::P256, YMutation::SameParity);
    assert_ec_wrong_y_rejected(CurveCase::Secp256k1, YMutation::SameParity);
}

#[test]
fn ec_jwk_rejects_mismatched_opposite_parity_y_coordinates() {
    assert_ec_wrong_y_rejected(CurveCase::P256, YMutation::OppositeParity);
    assert_ec_wrong_y_rejected(CurveCase::Secp256k1, YMutation::OppositeParity);
}

#[test]
fn okp_jwk_rejects_conflicting_alg_and_use_when_present() {
    let ed25519 =
        ed25519_public_key_to_jwk(&[0x11; 32], JwkOptions::default()).expect("valid Ed25519 JWK");
    let mut ed25519_as_x25519 =
        serde_json::to_value(&ed25519).expect("JWK serializes for mutation");
    ed25519_as_x25519["alg"] = json!("ECDH-ES");
    let jwk: Jwk = serde_json::from_value(ed25519_as_x25519).expect("OKP shape parses");
    assert_eq!(jwk.public_key_bytes(), Err(JwtError::UnsupportedKeyFormat));

    let mut ed25519_wrong_use =
        serde_json::to_value(&ed25519).expect("JWK serializes for mutation");
    ed25519_wrong_use["use"] = json!("enc");
    let jwk: Jwk = serde_json::from_value(ed25519_wrong_use).expect("OKP shape parses");
    assert_eq!(jwk.public_key_bytes(), Err(JwtError::UnsupportedKeyFormat));

    let x25519 =
        x25519_public_key_to_jwk(&[0x22; 32], JwkOptions::default()).expect("valid X25519 JWK");
    let mut x25519_as_ed25519 = serde_json::to_value(&x25519).expect("JWK serializes for mutation");
    x25519_as_ed25519["alg"] = json!("EdDSA");
    let jwk: Jwk = serde_json::from_value(x25519_as_ed25519).expect("OKP shape parses");
    assert_eq!(jwk.public_key_bytes(), Err(JwtError::UnsupportedKeyFormat));

    let mut x25519_wrong_use = serde_json::to_value(&x25519).expect("JWK serializes for mutation");
    x25519_wrong_use["use"] = json!("sig");
    let jwk: Jwk = serde_json::from_value(x25519_wrong_use).expect("OKP shape parses");
    assert_eq!(jwk.public_key_bytes(), Err(JwtError::UnsupportedKeyFormat));
}

#[test]
fn okp_jwk_allows_matching_or_omitted_alg_and_use() {
    let ed25519 = ed25519_public_key_to_jwk(
        &[0x33; 32],
        JwkOptions {
            alg: true,
            use_sig: true,
            ..Default::default()
        },
    )
    .expect("valid Ed25519 JWK");
    let jwk: Jwk = serde_json::from_value(serde_json::to_value(&ed25519).expect("serialize"))
        .expect("matching Ed25519 metadata parses");
    assert_eq!(jwk.public_key_bytes().expect("valid key"), [0x33; 32]);

    let x25519 =
        x25519_public_key_to_jwk(&[0x44; 32], JwkOptions::default()).expect("valid X25519 JWK");
    let jwk: Jwk = serde_json::from_value(serde_json::to_value(&x25519).expect("serialize"))
        .expect("omitted X25519 alg parses");
    assert_eq!(jwk.public_key_bytes().expect("valid key"), [0x44; 32]);
}

#[test]
fn jwk_deserialization_uses_explicit_kty_dispatch() {
    let okp_with_ec_y = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": bytes_to_base64url(&[0x55; 32]),
        "y": bytes_to_base64url(&[0x66; 32])
    });
    assert!(serde_json::from_value::<Jwk>(okp_with_ec_y).is_err());

    let ec_with_okp_shape = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": bytes_to_base64url(&[0x55; 32])
    });
    assert!(serde_json::from_value::<Jwk>(ec_with_okp_shape).is_err());

    let akp_with_ec_member = json!({
        "kty": "AKP",
        "alg": "ML-DSA-87",
        "pub": bytes_to_base64url(&[0x77; 2592]),
        "x": bytes_to_base64url(&[0x88; 32])
    });
    assert!(serde_json::from_value::<Jwk>(akp_with_ec_member).is_err());
}

#[test]
fn jwk_deserialization_rejects_private_and_unknown_public_members() {
    let private_okp = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": bytes_to_base64url(&[0x99; 32]),
        "d": bytes_to_base64url(&[0xaa; 32])
    });
    assert!(serde_json::from_value::<Jwk>(private_okp).is_err());

    let unknown_okp = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": bytes_to_base64url(&[0xbb; 32]),
        "key_ops": ["verify"]
    });
    assert!(serde_json::from_value::<Jwk>(unknown_okp).is_err());
}

#[test]
fn jwk_deserialization_rejects_duplicate_members_before_dispatch() {
    let duplicate_key_type = r#"{
        "kty":"OKP",
        "crv":"Ed25519",
        "x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "kty":"EC"
    }"#;
    let duplicate_public_key = r#"{
        "kty":"OKP",
        "crv":"Ed25519",
        "x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "x":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    }"#;

    for input in [duplicate_key_type, duplicate_public_key] {
        assert!(serde_json::from_str::<Jwk>(input).is_err());
    }
}

#[test]
fn public_key_extraction_rejects_oversized_members_before_decode() {
    let oversized = "A".repeat(8_192);
    let jwk = Jwk::Okp(envelopes_jwk::OkpJwk {
        kty: "OKP".to_owned(),
        crv: "Ed25519".to_owned(),
        x: oversized,
        alg: Some("EdDSA".to_owned()),
        use_: Some("sig".to_owned()),
        kid: None,
    });

    assert_eq!(jwk.public_key_bytes(), Err(JwtError::InvalidEd25519Key));
}

#[derive(Clone, Copy)]
enum CurveCase {
    P256,
    Secp256k1,
}

#[derive(Clone, Copy)]
enum YMutation {
    SameParity,
    OppositeParity,
}

fn assert_ec_wrong_y_rejected(curve: CurveCase, mutation: YMutation) {
    let mut jwk = match curve {
        CurveCase::P256 => {
            p256_public_key_to_jwk(&P256_GENERATOR_COMPRESSED, JwkOptions::default())
                .expect("valid P-256 JWK")
        }
        CurveCase::Secp256k1 => {
            secp256k1_public_key_to_jwk(&SECP256K1_GENERATOR_COMPRESSED, JwkOptions::default())
                .expect("valid secp256k1 JWK")
        }
    };
    let mut y = codec_base64url::base64url_to_bytes(&jwk.y).expect("valid y coordinate");
    match mutation {
        YMutation::SameParity => y[0] ^= 0x02,
        YMutation::OppositeParity => y[31] ^= 0x01,
    }
    jwk.y = bytes_to_base64url(&y);

    let jwk = Jwk::Ec(jwk);
    match curve {
        CurveCase::P256 => assert_eq!(jwk.public_key_bytes(), Err(JwtError::InvalidP256Key)),
        CurveCase::Secp256k1 => {
            assert_eq!(jwk.public_key_bytes(), Err(JwtError::InvalidSecp256k1Key));
        }
    }
}
