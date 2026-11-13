// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Independent integer known answers and public RSA operation boundaries.
use crypto_core::CryptoError;
use crypto_rsa::{rsa_public_representatives, RsaPublicKeyDerEncoding, RsaPublicRepresentatives};
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
enum TestErrorReason {
    #[error("invalid synthetic public fixture")]
    Fixture,
    #[error("RSA operation failed")]
    Rsa(#[from] CryptoError),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    pkcs1: String,
    spki: String,
    signature: String,
    ordinary: String,
    complement: String,
}
fn bytes(text: &str) -> Result<Vec<u8>, TestErrorReason> {
    let (pairs, remainder) = text.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(TestErrorReason::Fixture);
    }
    pairs
        .iter()
        .map(|pair| {
            let digit = |value| match value {
                b'0'..=b'9' => Ok(value - b'0'),
                b'a'..=b'f' => Ok(value - b'a' + 10),
                _ => Err(TestErrorReason::Fixture),
            };
            Ok(digit(pair[0])?
                .checked_mul(16)
                .ok_or(TestErrorReason::Fixture)?
                | digit(pair[1])?)
        })
        .collect()
}
fn cases() -> Result<Vec<Case>, TestErrorReason> {
    serde_json::from_str(include_str!("representatives.json")).map_err(|_| TestErrorReason::Fixture)
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn public_representatives_match_84_independent_integer_answers() -> Result<(), TestErrorReason> {
    let cases = cases()?;
    assert_eq!(cases.len(), 84);
    for case in cases {
        let signature = bytes(&case.signature)?;
        for (encoding, key) in [
            (RsaPublicKeyDerEncoding::Spki, case.spki),
            (RsaPublicKeyDerEncoding::Pkcs1, case.pkcs1),
        ] {
            let output = rsa_public_representatives(&bytes(&key)?, encoding, &signature)?;
            assert_eq!(output.ordinary(), bytes(&case.ordinary)?);
            assert_eq!(output.complement(), bytes(&case.complement)?);
        }
    }
    Ok(())
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn exact_width_range_key_and_ownership_boundaries_are_explicit() -> Result<(), TestErrorReason> {
    fn erases<T: zeroize::ZeroizeOnDrop>() {}
    erases::<RsaPublicRepresentatives>();
    let case = cases()?.pop().ok_or(TestErrorReason::Fixture)?;
    let key = bytes(&case.spki)?;
    let mut signature = bytes(&case.signature)?;
    for length in [
        0,
        1,
        signature
            .len()
            .checked_sub(1)
            .ok_or(TestErrorReason::Fixture)?,
        1025,
    ] {
        assert_eq!(
            rsa_public_representatives(&key, RsaPublicKeyDerEncoding::Spki, &vec![0; length]).err(),
            Some(CryptoError::PRIMITIVE_INVALID_LENGTH)
        );
    }
    let last = signature.last_mut().ok_or(TestErrorReason::Fixture)?;
    *last = last.checked_add(1).ok_or(TestErrorReason::Fixture)?;
    assert_eq!(
        rsa_public_representatives(&key, RsaPublicKeyDerEncoding::Spki, &signature).err(),
        Some(CryptoError::PRIMITIVE_INVALID_SIGNATURE)
    );
    for invalid in [&[][..], &[48, 0][..], &[0; 4097][..]] {
        assert_eq!(
            rsa_public_representatives(invalid, RsaPublicKeyDerEncoding::Spki, &signature).err(),
            Some(CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)
        );
    }
    Ok(())
}
