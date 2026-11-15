// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    assert_ml_kem_512_public_key, parse_encoded_public_key, EncapsulationKey,
    ML_KEM_512_PUBLIC_KEY_LEN,
};
use crate::native::encapsulate::{ml_kem_512_encapsulate, ml_kem_512_encapsulate_derand};
use crypto_core::CryptoError;

fn model_noncanonical_key(
    encoded: &ml_kem::Key<EncapsulationKey>,
) -> Result<EncapsulationKey, CryptoError> {
    // Only correctly sized inputs carry this marker. The locked modulus
    // check is verified separately through its polynomial round trip.
    assert_eq!(encoded[0], 1);
    kani::cover!(true, "the typed key reaches the modulus check");
    Err(CryptoError::PRIMITIVE_INVALID_KEY)
}

#[kani::proof]
#[kani::stub(parse_encoded_public_key, model_noncanonical_key)]
fn key_import_and_encapsulation_share_the_fail_closed_gate() {
    let mut bytes = [0_u8; ML_KEM_512_PUBLIC_KEY_LEN + 1];
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    bytes[0] = u8::from(len == ML_KEM_512_PUBLIC_KEY_LEN);
    let key = &bytes[..len];

    let invalid = Some(CryptoError::PRIMITIVE_INVALID_KEY);
    assert_eq!(assert_ml_kem_512_public_key(key).err(), invalid);
    assert_eq!(ml_kem_512_encapsulate(key).err(), invalid);
    assert_eq!(ml_kem_512_encapsulate_derand(key, &[0; 32]).err(), invalid);
}
