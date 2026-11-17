// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::unwrap_used, missing_docs)]

use envelopes_jwk::{
    secp256k1_public_key_to_jwk, secp256k1_public_key_to_jwk_jcs, JwkOptions, JwtError,
};

#[test]
fn secp256k1_basic() {
    // Compressed SEC1 encoding of the secp256k1 generator point.
    let bytes = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];

    let jwk = secp256k1_public_key_to_jwk(&bytes, JwkOptions::default()).unwrap();

    assert_eq!(jwk.kty, "EC");
    assert_eq!(jwk.crv, "secp256k1");
    assert!(!jwk.x.is_empty());
    assert!(!jwk.y.is_empty());
}

#[test]
fn secp256k1_jwk_rejects_nonstandard_compressed_prefixes() {
    // The generator's x-coordinate is valid, so 0x05 would otherwise decode
    // through the backend's compact-point extension instead of failing.
    let generator = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];
    for prefix in u8::MIN..=u8::MAX {
        if matches!(prefix, 0x02 | 0x03) {
            continue;
        }
        let mut invalid = generator;
        invalid[0] = prefix;
        assert_eq!(
            secp256k1_public_key_to_jwk(&invalid, JwkOptions::default()).err(),
            Some(JwtError::PRIMITIVE_INVALID_PUBLIC_KEY),
        );
        assert_eq!(
            secp256k1_public_key_to_jwk_jcs(&invalid, JwkOptions::default()).err(),
            Some(JwtError::PRIMITIVE_INVALID_PUBLIC_KEY),
        );
    }
}
