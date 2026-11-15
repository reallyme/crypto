// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]
#![cfg(all(
    feature = "native",
    feature = "ml-kem-512",
    feature = "ml-kem-768",
    feature = "ml-kem-1024"
))]

use crypto_core::CryptoError;

const SEED_BYTES: usize = 64;
const RANDOMNESS_BYTES: usize = 32;
const MATRIX_SEED_BYTES: usize = 32;
const CHUNK_BYTES: usize = 3;
const FIRST_INVALID_COEFFICIENT: u16 = 3329;
const MAX_ENCODED_COEFFICIENT: u16 = 4095;

fn check_key(
    mut public: Vec<u8>,
    assert_key: impl Fn(&[u8]) -> Result<&[u8], CryptoError>,
    encapsulate: impl Fn(&[u8], &[u8]) -> Result<(Vec<u8>, zeroize::Zeroizing<Vec<u8>>), CryptoError>,
) -> Result<(), CryptoError> {
    let randomness = [0; RANDOMNESS_BYTES];
    let key_len = public.len();
    let packed_len = key_len
        .checked_sub(MATRIX_SEED_BYTES)
        .ok_or(CryptoError::PRIMITIVE_INVALID_KEY)?;
    assert!(packed_len.is_multiple_of(CHUNK_BYTES));
    assert_eq!(assert_key(&public)?, public.as_slice());
    encapsulate(&public, &randomness)?;

    for offset in (0..packed_len).step_by(CHUNK_BYTES) {
        let end = offset
            .checked_add(CHUNK_BYTES)
            .ok_or(CryptoError::PRIMITIVE_INVALID_KEY)?;
        let original = <[u8; CHUNK_BYTES]>::try_from(&public[offset..end])
            .map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;
        for value in [FIRST_INVALID_COEFFICIENT, MAX_ENCODED_COEFFICIENT] {
            let [low, high] = value.to_le_bytes();
            // Replace one coefficient while preserving the other one's nibble.
            let invalid_low = [low, (original[1] & 0xf0) | high, original[2]];
            let invalid_high = [
                original[0],
                (original[1] & 0x0f) | (low << 4),
                (high << 4) | (low >> 4),
            ];
            for changed in [invalid_low, invalid_high] {
                public[offset..end].copy_from_slice(&changed);
                assert_eq!(
                    assert_key(&public).err(),
                    Some(CryptoError::PRIMITIVE_INVALID_KEY),
                    "key import at offset {offset}"
                );
                assert_eq!(
                    encapsulate(&public, &randomness).err(),
                    Some(CryptoError::PRIMITIVE_INVALID_KEY),
                    "encapsulation at offset {offset}"
                );
            }
        }
        public[offset..end].copy_from_slice(&original);
    }
    assert_eq!(assert_key(&public)?, public.as_slice());
    Ok(())
}

#[test]
fn every_packed_coefficient_participates_in_public_key_validation() -> Result<(), CryptoError> {
    let seed = [7_u8; SEED_BYTES];
    check_key(
        crypto_ml_kem_512::generate_ml_kem_512_keypair_from_seed(&seed)?.0,
        crypto_ml_kem_512::assert_ml_kem_512_public_key,
        crypto_ml_kem_512::ml_kem_512_encapsulate_derand,
    )?;
    check_key(
        crypto_ml_kem_768::generate_ml_kem_768_keypair_from_seed(&seed)?.0,
        crypto_ml_kem_768::assert_ml_kem_768_public_key,
        crypto_ml_kem_768::ml_kem_768_encapsulate_derand,
    )?;
    check_key(
        crypto_ml_kem_1024::generate_ml_kem_1024_keypair_from_seed(&seed)?.0,
        crypto_ml_kem_1024::assert_ml_kem_1024_public_key,
        crypto_ml_kem_1024::ml_kem_1024_encapsulate_derand,
    )
}
