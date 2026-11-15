// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{MontgomeryPoint, SharedSecret};

#[kani::proof]
#[kani::unwind(65)]
fn x25519_backend_contribution_is_nonzero_on_canonical_outputs() {
    let mut modulus = [0xff; 32];
    modulus[0] = 0xed;
    modulus[31] = 0x7f; // RFC 7748 prime 2^255 - 19 in little-endian order.
    let bytes: [u8; 32] = kani::any();
    kani::assume(bytes.iter().rev().cmp(modulus.iter().rev()).is_lt());
    let secret = SharedSecret(MontgomeryPoint(bytes));
    let nonzero = bytes.iter().any(|&byte| byte != 0);
    assert_eq!(secret.was_contributory(), nonzero);
    kani::cover!(!nonzero, "canonical zero output");
    kani::cover!(nonzero, "canonical nonzero output");
}
