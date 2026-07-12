// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(clippy::expect_used)]
#![cfg(any(
    feature = "native",
    all(feature = "wasm", target_arch = "wasm32", not(feature = "native"))
))]

use crypto_core::CryptoError;
use crypto_p256::generate_p256_keypair_from_secret_key;

#[test]
fn raw_secret_key_import_is_deterministic_and_rejects_invalid_scalar() -> Result<(), CryptoError> {
    let mut secret = [0u8; 32];
    secret[31] = 1;
    let (public_a, secret_a) = generate_p256_keypair_from_secret_key(&secret)?;
    let (public_b, secret_b) = generate_p256_keypair_from_secret_key(&secret)?;

    assert_eq!(public_a, public_b);
    assert_eq!(secret_a, secret_b);
    assert_eq!(secret_a.as_slice(), secret.as_slice());
    assert!(generate_p256_keypair_from_secret_key(&[0u8; 32]).is_err());
    Ok(())
}
