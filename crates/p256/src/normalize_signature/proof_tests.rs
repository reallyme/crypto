// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    normalize_p256_ecdsa_jose_signature_low_s, signature_encoding_error,
    P256_ECDSA_JOSE_SIGNATURE_LEN, SCALAR_LEN,
};

#[kani::proof]
#[kani::unwind(65)]
fn p256_normalization_matches_subgroup_arithmetic_and_is_idempotent() {
    // Big-endian subgroup order and half-order, expressed as two words so
    // the reference subtraction is independent of the bytewise borrow loop.
    const ORDER_HI: u128 = 0xffff_ffff_0000_0000_ffff_ffff_ffff_ffff;
    const ORDER_LO: u128 = 0xbce6_faad_a717_9e84_f3b9_cac2_fc63_2551;
    const HALF_HI: u128 = ORDER_HI / 2;
    const HALF_LO: u128 = (ORDER_HI << 127) | (ORDER_LO / 2);

    let hi: u128 = kani::any();
    let lo: u128 = kani::any();
    let mut jose = [0_u8; P256_ECDSA_JOSE_SIGNATURE_LEN];
    jose[SCALAR_LEN - 1] = 1;
    jose[SCALAR_LEN..SCALAR_LEN + 16].copy_from_slice(&hi.to_be_bytes());
    jose[SCALAR_LEN + 16..].copy_from_slice(&lo.to_be_bytes());

    let actual = normalize_p256_ecdsa_jose_signature_low_s(&jose);
    if (hi, lo) == (0, 0) || (hi, lo) >= (ORDER_HI, ORDER_LO) {
        assert_eq!(actual.err(), Some(signature_encoding_error()));
        return;
    }

    let (expected_hi, expected_lo) = if (hi, lo) <= (HALF_HI, HALF_LO) {
        (hi, lo)
    } else {
        let (low, borrow) = ORDER_LO.overflowing_sub(lo);
        (ORDER_HI - hi - u128::from(borrow), low)
    };
    let normalized = actual.expect("a valid signature must normalize");
    assert_eq!(normalized[..SCALAR_LEN], jose[..SCALAR_LEN]);
    assert_eq!(
        normalized[SCALAR_LEN..SCALAR_LEN + 16],
        expected_hi.to_be_bytes()
    );
    assert_eq!(normalized[SCALAR_LEN + 16..], expected_lo.to_be_bytes());
    assert!((expected_hi, expected_lo) > (0, 0));
    assert!((expected_hi, expected_lo) <= (HALF_HI, HALF_LO));
    assert_eq!(
        normalize_p256_ecdsa_jose_signature_low_s(&normalized),
        Ok(normalized)
    );
    kani::cover!(
        (hi, lo) > (HALF_HI, HALF_LO),
        "normalize a high-S signature"
    );
}
