// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]

use codec_base64url::bytes_to_base64url;
use envelopes_jwk::{EcJwk, Jwk, JwkOptions};
use envelopes_jwk_multikey::*;

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
