// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::parse_low_s;
use crypto_core::CryptoError;

#[kani::proof]
#[kani::unwind(65)]
fn strict_secp256k1_parse_accepts_only_nonzero_low_s() {
    // floor(n / 2) for the secp256k1 subgroup order.
    const HALF_ORDER: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0,
    ];
    let s: [u8; 32] = kani::any();
    let mut compact = [0_u8; 64];
    compact[31] = 1;
    compact[32..].copy_from_slice(&s);
    let result = parse_low_s(&compact);
    if s != [0; 32] && s <= HALF_ORDER {
        assert!(result.is_ok());
    } else {
        assert_eq!(result.err(), Some(CryptoError::PRIMITIVE_INVALID_SIGNATURE));
    }
    kani::cover!(s == HALF_ORDER, "accept the low-S boundary");
    kani::cover!(
        s > HALF_ORDER && s[0] < 0x90,
        "reject a valid high-S scalar"
    );
}
