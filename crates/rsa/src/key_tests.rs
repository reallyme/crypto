// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::build_public_key;
use crypto_core::CryptoError;

#[test]
fn public_exponent_precision_is_independent_of_modulus_size() -> Result<(), CryptoError> {
    for modulus_length in [128, 256, 512, 1024] {
        let modulus = vec![0xff; modulus_length];
        for exponent in [&[3][..], &[1, 0, 1], &[0xff; 8]] {
            let key = build_public_key(&modulus, exponent)?;
            assert!(key.exponent().bits_precision() <= 64);
            assert_eq!(key.size(), modulus_length);
        }
    }
    Ok(())
}

#[test]
fn public_exponent_bounds_remain_enforced() {
    let modulus = [0xff; 128];
    for exponent in [&[0][..], &[1], &[2], &[0xff; 9]] {
        assert!(matches!(
            build_public_key(&modulus, exponent),
            Err(CryptoError::InvalidKey)
        ));
    }
}

#[test]
fn exponent_precision_preserves_public_modular_exponentiation() -> Result<(), CryptoError> {
    let modulus = [0xff; 128];
    let mut signature = [0x55; 128];
    signature[0] = 0;
    for exponent in [&[3][..], &[1, 0, 1], &[1, 0, 0, 0, 1], &[0xff; 8]] {
        let compact = build_public_key(&modulus, exponent)?;
        // Compare against the previous modulus-sized representation through
        // the actual signature-recovery path, not just integer decoding.
        let previous = super::RsaPublicKey {
            exponent: crypto_bigint::BoxedUint::from_be_slice(
                exponent,
                compact.modulus.bits_precision(),
            )
            .map_err(|_| CryptoError::InvalidKey)?,
            modulus: compact.modulus.clone(),
            modulus_bits: compact.modulus_bits,
            size: compact.size,
        };
        assert_eq!(
            crate::pss::recover_encoded_message(&compact, &signature)?,
            crate::pss::recover_encoded_message(&previous, &signature)?,
        );
    }
    Ok(())
}
