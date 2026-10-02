// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::unwrap_used, missing_docs)]

#[path = "common/mod.rs"]
mod common;

use envelopes_jwk::{
    p256::p256_public_key_to_jwk, p256::p256_public_key_to_jwk_jcs, JwkOptions, JwtError,
};

const P256_GENERATOR_COMPRESSED: [u8; 33] = [
    0x02, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
    0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
    0x96,
];

fn valid_uncompressed_key() -> Vec<u8> {
    crypto_p256::decompress_public_key(&P256_GENERATOR_COMPRESSED).unwrap()
}

#[test]
fn p256_accepts_uncompressed() {
    let pk = valid_uncompressed_key();

    let jwk = p256_public_key_to_jwk(&pk, JwkOptions::default()).unwrap();
    assert_eq!(jwk.crv, "P-256");
    assert_eq!(jwk.kty, "EC");
}

#[test]
fn p256_jcs() {
    let pk = valid_uncompressed_key();

    let jcs = p256_public_key_to_jwk_jcs(&pk, JwkOptions::default()).unwrap();
    common::assert_jcs(&jcs);
}

#[test]
fn p256_rejects_uncompressed_off_curve_point() {
    let mut invalid = vec![0xff_u8; 65];
    invalid[0] = 0x04;
    assert!(matches!(
        p256_public_key_to_jwk(&invalid, JwkOptions::default()),
        Err(JwtError::InvalidP256Key)
    ));
}
