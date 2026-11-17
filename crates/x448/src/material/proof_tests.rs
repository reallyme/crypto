// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{X448PrivateKey, X448PublicKey, X448_PUBLIC_KEY_LEN};
use crypto_core::CryptoError;

#[kani::proof]
fn x448_rejects_invalid_key_lengths_at_import() {
    let bytes: [u8; X448_PUBLIC_KEY_LEN + 1] = kani::any();
    let length: usize = kani::any();
    kani::assume(length <= bytes.len() && length != X448_PUBLIC_KEY_LEN);
    assert_eq!(
        X448PrivateKey::from_bytes(&bytes[..length]).err(),
        Some(CryptoError::PRIMITIVE_INVALID_KEY),
    );
    assert_eq!(
        X448PublicKey::from_bytes(&bytes[..length]).err(),
        Some(CryptoError::PRIMITIVE_INVALID_KEY),
    );
}

#[kani::proof]
#[kani::unwind(64)]
fn x448_public_import_rejects_low_order_coordinates_and_aliases() {
    // All low-order encodings: 0, 1, -1, and the aliases p and p+1.
    let mut modulus = [0xff; X448_PUBLIC_KEY_LEN];
    modulus[28] = 0xfe; // p = 2^448 - 2^224 - 1.
    let mut minus_one = modulus;
    minus_one[0] = 0xfe;
    let mut one = [0_u8; X448_PUBLIC_KEY_LEN];
    one[0] = 1;
    let mut modulus_plus_one = [0xff; X448_PUBLIC_KEY_LEN];
    modulus_plus_one[..28].fill(0);

    let bytes: [u8; X448_PUBLIC_KEY_LEN] = kani::any();
    let rejected = bytes == [0; X448_PUBLIC_KEY_LEN]
        || bytes == one
        || bytes == minus_one
        || bytes == modulus
        || bytes == modulus_plus_one;
    match X448PublicKey::from_bytes(&bytes) {
        Ok(key) => {
            assert!(!rejected);
            assert_eq!(key.as_bytes(), &bytes);
        }
        Err(error) => {
            assert!(rejected);
            assert_eq!(error, CryptoError::PRIMITIVE_INVALID_KEY);
        }
    }
}
