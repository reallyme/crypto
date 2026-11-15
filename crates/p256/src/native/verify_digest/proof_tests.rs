// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::parse_low_s;
use crypto_core::CryptoError;

#[kani::proof]
#[kani::unwind(65)]
fn strict_p256_parse_accepts_only_nonzero_low_s() {
    // floor(n / 2) for the P-256 subgroup order, independently of the backend.
    const HALF_ORDER: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31,
        0x92, 0xa8,
    ];
    let s: [u8; 32] = kani::any();
    let mut compact = [0_u8; 64];
    compact[31] = 1; // A known valid r isolates the S policy.
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
