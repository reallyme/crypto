// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]

use codec_base64url::bytes_to_base64url;
use envelopes_jwk::{EcJwk, Jwk, JwkOptions, OkpJwk};
use envelopes_jwk_multikey::{jwk_to_multikey, multikey_to_jwk, JwkMultikeyError};

#[test]
fn rejects_unknown_multikey() {
    let bad = "zInvalidKey";

    assert!(multikey_to_jwk(bad, JwkOptions::default()).is_err());
}

#[test]
fn rejects_unsupported_algorithm() {
    let fake = "zFooBarBazUnsupported";

    let res = multikey_to_jwk(fake, JwkOptions::default());
    assert!(res.is_err());
}

#[test]
fn rejects_wrong_length_ec_coordinates() {
    let jwk = Jwk::Ec(EcJwk {
        kty: "EC".to_owned(),
        crv: "secp256k1".to_owned(),
        x: bytes_to_base64url(&[0_u8; 31]),
        y: bytes_to_base64url(&[0_u8; 32]),
        alg: None,
        use_: None,
        kid: None,
    });

    assert_eq!(jwk_to_multikey(&jwk), Err(JwkMultikeyError::InvalidJwk));
}

#[test]
fn rejects_coordinates_that_are_not_a_curve_point() {
    let jwk = Jwk::Ec(EcJwk {
        kty: "EC".to_owned(),
        crv: "secp256k1".to_owned(),
        x: bytes_to_base64url(&[0_u8; 32]),
        y: bytes_to_base64url(&[0_u8; 32]),
        alg: None,
        use_: None,
        kid: None,
    });

    #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
    assert_eq!(jwk_to_multikey(&jwk), Err(JwkMultikeyError::InvalidJwk));

    #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
    assert_eq!(
        jwk_to_multikey(&jwk),
        Err(JwkMultikeyError::UnsupportedAlgorithm)
    );
}

#[test]
fn rejects_jwk_metadata_that_conflicts_with_public_key_type() {
    let jwk = Jwk::Okp(OkpJwk {
        kty: "OKP".to_owned(),
        crv: "Ed25519".to_owned(),
        x: bytes_to_base64url(&[0x42; 32]),
        alg: Some("ECDH-ES".to_owned()),
        use_: Some("enc".to_owned()),
        kid: None,
    });

    assert_eq!(jwk_to_multikey(&jwk), Err(JwkMultikeyError::InvalidJwk));
}

#[test]
fn rejects_mismatched_ec_coordinates_through_shared_jwk_validator() {
    let jwk = Jwk::Ec(EcJwk {
        kty: "EC".to_owned(),
        crv: "secp256k1".to_owned(),
        x: bytes_to_base64url(&[
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
            0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
            0x16, 0xf8, 0x17, 0x98,
        ]),
        y: bytes_to_base64url(&[
            0x4a, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11,
            0x08, 0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f,
            0xfb, 0x10, 0xd4, 0xb8,
        ]),
        alg: Some("ES256K".to_owned()),
        use_: Some("sig".to_owned()),
        kid: None,
    });

    assert_eq!(jwk_to_multikey(&jwk), Err(JwkMultikeyError::InvalidJwk));
}
