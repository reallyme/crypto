// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! JOSE ECDSA signature transcoding tests for P-256.

use crypto_core::CryptoError;
use crypto_p256::{
    p256_ecdsa_der_to_jose_signature, p256_ecdsa_der_to_jose_signature_permissive,
    p256_ecdsa_jose_signature_to_der, P256_ECDSA_JOSE_SIGNATURE_LEN,
};
use hex_literal::hex;

#[cfg(feature = "native")]
use crypto_p256::{
    generate_p256_keypair_from_secret_key, sign_p256_der_prehash, verify_p256_der_prehash,
};

#[cfg(feature = "native")]
use p256::ecdsa::Signature as P256Signature;

fn raw_signature_from_scalars(r: [u8; 32], s: [u8; 32]) -> [u8; P256_ECDSA_JOSE_SIGNATURE_LEN] {
    let mut raw = [0u8; P256_ECDSA_JOSE_SIGNATURE_LEN];
    raw[..32].copy_from_slice(&r);
    raw[32..].copy_from_slice(&s);
    raw
}

fn scalar_with_first(first: u8) -> [u8; 32] {
    let mut scalar = [0u8; 32];
    scalar[0] = first;
    scalar
}

fn scalar_with_last(last: u8) -> [u8; 32] {
    let mut scalar = [0u8; 32];
    scalar[31] = last;
    scalar
}

fn boundary_jose_signatures() -> [[u8; P256_ECDSA_JOSE_SIGNATURE_LEN]; 7] {
    [
        raw_signature_from_scalars([0u8; 32], [0u8; 32]),
        raw_signature_from_scalars(scalar_with_last(0x01), scalar_with_last(0x02)),
        raw_signature_from_scalars(scalar_with_first(0x7f), scalar_with_first(0x01)),
        raw_signature_from_scalars(scalar_with_first(0x80), scalar_with_first(0x81)),
        raw_signature_from_scalars([0xffu8; 32], [0xffu8; 32]),
        raw_signature_from_scalars(
            hex!("00000000000000000000000000000000000000000000000000000000000000ff"),
            scalar_with_last(0x7f),
        ),
        raw_signature_from_scalars(
            hex!("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            hex!("8000000000000000000000000000000000000000000000000000000000000000"),
        ),
    ]
}

#[test]
fn converts_p256_der_signature_to_jose_and_back() -> Result<(), CryptoError> {
    let der = hex!(
        "30450220
         6e3038666f0655a681c1636c9191509227335c61527ff220426809a695e07ed7\
         022100
         a37377a349087a2446d5839c0db705caf20b9e42edc4b819892e4bbe866754c6"
    );
    let raw = hex!(
        "6e3038666f0655a681c1636c9191509227335c61527ff220426809a695e07ed7
         a37377a349087a2446d5839c0db705caf20b9e42edc4b819892e4bbe866754c6"
    );

    let converted = p256_ecdsa_der_to_jose_signature(&der)?;
    assert_eq!(converted.as_slice(), raw.as_slice());

    let roundtrip = p256_ecdsa_jose_signature_to_der(&converted)?;
    assert_eq!(roundtrip, der);
    Ok(())
}

#[test]
fn boundary_jose_signatures_roundtrip_through_der() -> Result<(), CryptoError> {
    for raw in boundary_jose_signatures() {
        let der = p256_ecdsa_jose_signature_to_der(&raw)?;
        let converted = p256_ecdsa_der_to_jose_signature(&der)?;
        assert_eq!(converted, raw);
    }
    Ok(())
}

#[cfg(feature = "native")]
#[test]
fn boundary_der_outputs_are_accepted_by_p256_der_oracle() -> Result<(), CryptoError> {
    let boundary_signatures = boundary_jose_signatures();
    let scalar_valid_signatures = [
        boundary_signatures[1],
        boundary_signatures[2],
        boundary_signatures[3],
        boundary_signatures[5],
        boundary_signatures[6],
    ];

    for raw in scalar_valid_signatures {
        let der = p256_ecdsa_jose_signature_to_der(&raw)?;
        assert!(P256Signature::from_der(&der).is_ok());
    }
    Ok(())
}

#[test]
fn adds_der_sign_padding_for_high_bit_scalars() -> Result<(), CryptoError> {
    let mut raw = [0u8; P256_ECDSA_JOSE_SIGNATURE_LEN];
    raw[0] = 0x80;
    raw[32] = 0x81;

    let der = p256_ecdsa_jose_signature_to_der(&raw)?;
    assert_eq!(der[0], 0x30);
    assert_eq!(der[4], 0x00);
    assert_eq!(der[39], 0x00);

    let converted = p256_ecdsa_der_to_jose_signature(&der)?;
    assert_eq!(converted, raw);
    Ok(())
}

#[test]
fn accepts_short_der_integers_and_left_pads_to_jose_width() -> Result<(), CryptoError> {
    let der = hex!("3006020101020102");
    let raw = p256_ecdsa_der_to_jose_signature(&der)?;

    assert_eq!(raw[..31], [0u8; 31]);
    assert_eq!(raw[31], 0x01);
    assert_eq!(raw[32..63], [0u8; 31]);
    assert_eq!(raw[63], 0x02);
    assert_eq!(p256_ecdsa_jose_signature_to_der(&raw)?, der);
    Ok(())
}

#[test]
fn strict_rejects_but_permissive_accepts_redundant_positive_integer_padding(
) -> Result<(), CryptoError> {
    let der = hex!(
        "3027
         0222
         00007f0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
         020101"
    );
    assert!(p256_ecdsa_der_to_jose_signature(&der).is_err());

    let raw = p256_ecdsa_der_to_jose_signature_permissive(&der)?;

    assert_eq!(raw[0], 0x7f);
    assert_eq!(raw[1], 0x01);
    assert_eq!(raw[31], 0x1f);
    assert_eq!(raw[63], 0x01);

    let canonical_der = p256_ecdsa_jose_signature_to_der(&raw)?;
    assert_ne!(canonical_der, der);
    assert_eq!(p256_ecdsa_der_to_jose_signature(&canonical_der)?, raw);
    Ok(())
}

#[test]
fn strict_rejects_but_permissive_accepts_der_long_form_lengths() -> Result<(), CryptoError> {
    let outer_long_form = hex!("308106020101020102");
    let integer_long_form = hex!("300702810101020102");

    let expected = p256_ecdsa_der_to_jose_signature(&hex!("3006020101020102"))?;
    assert!(p256_ecdsa_der_to_jose_signature(&outer_long_form).is_err());
    assert!(p256_ecdsa_der_to_jose_signature(&integer_long_form).is_err());
    assert_eq!(
        p256_ecdsa_der_to_jose_signature_permissive(&outer_long_form)?,
        expected
    );
    assert_eq!(
        p256_ecdsa_der_to_jose_signature_permissive(&integer_long_form)?,
        expected
    );
    Ok(())
}

#[test]
fn rejects_wrong_jose_length() {
    let raw = [0u8; P256_ECDSA_JOSE_SIGNATURE_LEN - 1];

    assert!(p256_ecdsa_jose_signature_to_der(&raw).is_err());
}

#[test]
fn rejects_malformed_der_signature() {
    let wrong_tag = [0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
    let trailing = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00];
    let negative_integer = [0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01];
    let oversized_scalar = [
        0x30, 0x29, 0x02, 0x22, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x02, 0x01, 0x01,
    ];

    assert!(p256_ecdsa_der_to_jose_signature(&wrong_tag).is_err());
    assert!(p256_ecdsa_der_to_jose_signature(&trailing).is_err());
    assert!(p256_ecdsa_der_to_jose_signature(&negative_integer).is_err());
    assert!(p256_ecdsa_der_to_jose_signature(&oversized_scalar).is_err());
}

#[test]
fn rejects_invalid_der_length_forms() {
    let indefinite_length = hex!("3080020101020102");
    let too_many_length_octets = hex!("3083000006020101020102");

    assert!(p256_ecdsa_der_to_jose_signature(&indefinite_length).is_err());
    assert!(p256_ecdsa_der_to_jose_signature(&too_many_length_octets).is_err());
}

#[cfg(feature = "native")]
#[test]
fn native_p256_signature_transcodes_through_jose_and_still_verifies() -> Result<(), CryptoError> {
    let secret = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let message = b"reallyme p256 jose transcoding";
    let (public_key, secret_key) = generate_p256_keypair_from_secret_key(&secret)?;

    let der = sign_p256_der_prehash(&secret_key, message)?;
    verify_p256_der_prehash(&der, message, &public_key)?;

    let raw = p256_ecdsa_der_to_jose_signature(&der)?;
    assert_eq!(raw.len(), P256_ECDSA_JOSE_SIGNATURE_LEN);

    let roundtrip_der = p256_ecdsa_jose_signature_to_der(&raw)?;
    verify_p256_der_prehash(&roundtrip_der, message, &public_key)?;
    Ok(())
}
