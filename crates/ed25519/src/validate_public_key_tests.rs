// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use super::{is_canonical_point_encoding, validate_public_key_identity};
use crypto_core::CryptoError;
use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
use curve25519_dalek::edwards::CompressedEdwardsY;

#[test]
fn canonical_encoding_check_rejects_an_aliased_decompressed_point() {
    let mut alias = [0xff_u8; 32];
    alias[0] = 0xee;
    alias[31] = 0x7f;
    let point = CompressedEdwardsY(alias)
        .decompress()
        .expect("identity alias decodes");
    assert!(!is_canonical_point_encoding(&point, &alias));
    assert_eq!(
        validate_public_key_identity(&alias),
        Err(CryptoError::InvalidKey)
    );
}

#[test]
fn mixed_order_canonical_point_is_not_an_identity() {
    let mixed = ED25519_BASEPOINT_POINT + EIGHT_TORSION[1];
    let encoded = mixed.compress().to_bytes();
    assert!(is_canonical_point_encoding(&mixed, &encoded));
    assert!(!mixed.is_small_order());
    assert!(!mixed.is_torsion_free());
    assert_eq!(
        validate_public_key_identity(&encoded),
        Err(CryptoError::InvalidKey)
    );
}
