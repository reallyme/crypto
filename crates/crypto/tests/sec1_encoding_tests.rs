// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]
#![cfg(feature = "ecdsa-explicit")]

use crypto_core::CryptoError;
use reallyme_crypto::ecdsa_explicit::{
    der_to_fixed, validate_public_key, verify, EcdsaCurve, EcdsaEncoding, EcdsaHash, EcdsaInput,
    EcdsaKey,
};
use secrecy::ExposeSecret;
use zeroize::Zeroizing;

#[test]
fn explicit_verification_and_agreement_reject_compact_point_aliases() -> Result<(), CryptoError> {
    const MESSAGE: &[u8] = b"strict explicit ECDSA SEC1 boundary";
    for (curve, width) in [
        (EcdsaCurve::P256, 32usize),
        (EcdsaCurve::P384, 48),
        (EcdsaCurve::P521, 66),
    ] {
        for scalar in [1, 2] {
            let mut secret = Zeroizing::new(vec![0u8; width]);
            *secret
                .last_mut()
                .ok_or(CryptoError::PRIMITIVE_INVALID_KEY)? = scalar;
            let key = EcdsaKey::import(curve, &secret)?;
            let public = key.public_key();
            let x_end = width
                .checked_add(1)
                .ok_or(CryptoError::PRIMITIVE_INVALID_LENGTH)?;
            let last = public
                .last()
                .ok_or(CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)?;
            let mut compressed = vec![0x02 | (last & 1)];
            compressed.extend_from_slice(
                public
                    .get(1..x_end)
                    .ok_or(CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)?,
            );
            let input = EcdsaInput::Message {
                hash: EcdsaHash::Sha256,
                bytes: MESSAGE,
            };
            let der = key.sign(input, EcdsaEncoding::Der)?;
            let fixed = der_to_fixed(curve, &der)?;
            let expected = key.agree(public)?;
            for standard in [public, compressed.as_slice()] {
                validate_public_key(curve, standard)?;
                assert_eq!(
                    key.agree(standard)?.expose_secret(),
                    expected.expose_secret()
                );
                for (encoding, signature) in [
                    (EcdsaEncoding::Der, &der),
                    (EcdsaEncoding::FixedWidth, &fixed),
                ] {
                    verify(curve, standard, input, signature, encoding)?;
                }
            }
            for prefix in [0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0xff] {
                let mut invalid = compressed.clone();
                invalid[0] = prefix;
                assert_eq!(
                    validate_public_key(curve, &invalid),
                    Err(CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)
                );
                assert_eq!(
                    key.agree(&invalid).err(),
                    Some(CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)
                );
                for (encoding, signature) in [
                    (EcdsaEncoding::Der, &der),
                    (EcdsaEncoding::FixedWidth, &fixed),
                ] {
                    assert_eq!(
                        verify(curve, &invalid, input, signature, encoding),
                        Err(CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)
                    );
                }
            }
        }
    }
    Ok(())
}
