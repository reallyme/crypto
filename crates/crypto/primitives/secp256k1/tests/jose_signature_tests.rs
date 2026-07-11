// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! JOSE ECDSA signature transcoding tests for secp256k1.

use crypto_core::CryptoError;
use crypto_secp256k1::{
    secp256k1_ecdsa_der_to_jose_signature, secp256k1_ecdsa_der_to_jose_signature_permissive,
    secp256k1_ecdsa_jose_signature_to_der, SECP256K1_ECDSA_JOSE_SIGNATURE_LEN,
};
use hex_literal::hex;

#[cfg(all(feature = "native", not(all(feature = "wasm", target_arch = "wasm32"))))]
use crypto_secp256k1::{
    generate_secp256k1_keypair_from_secret_key, sign_secp256k1, verify_secp256k1,
};

#[cfg(all(feature = "native", not(all(feature = "wasm", target_arch = "wasm32"))))]
use k256::ecdsa::Signature as Secp256k1Signature;

fn raw_signature_from_scalars(
    r: [u8; 32],
    s: [u8; 32],
) -> [u8; SECP256K1_ECDSA_JOSE_SIGNATURE_LEN] {
    let mut raw = [0u8; SECP256K1_ECDSA_JOSE_SIGNATURE_LEN];
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

fn boundary_jose_signatures() -> [[u8; SECP256K1_ECDSA_JOSE_SIGNATURE_LEN]; 7] {
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
fn converts_secp256k1_jose_signature_to_der_and_back() -> Result<(), CryptoError> {
    let raw = hex!(
        "ee3f9089351bd0d9c622d6d2668c491d257bd61f3d1d8ffa1cf237ed5c119069
         9495b22b9ae98ef7474b8da5424b2a7fa44a2e5ee8dfd3e55ccebccb49b32138"
    );

    let der = secp256k1_ecdsa_jose_signature_to_der(&raw)?;
    assert_eq!(der[0], 0x30);
    assert_eq!(der[4], 0x00);
    assert_eq!(der[39], 0x00);

    let converted = secp256k1_ecdsa_der_to_jose_signature(&der)?;
    assert_eq!(converted.as_slice(), raw.as_slice());
    Ok(())
}

#[test]
fn boundary_jose_signatures_roundtrip_through_der() -> Result<(), CryptoError> {
    for raw in boundary_jose_signatures() {
        let der = secp256k1_ecdsa_jose_signature_to_der(&raw)?;
        let converted = secp256k1_ecdsa_der_to_jose_signature(&der)?;
        assert_eq!(converted, raw);
    }
    Ok(())
}

#[cfg(all(feature = "native", not(all(feature = "wasm", target_arch = "wasm32"))))]
#[test]
fn boundary_der_outputs_are_accepted_by_secp256k1_der_oracle() -> Result<(), CryptoError> {
    let boundary_signatures = boundary_jose_signatures();
    let scalar_valid_signatures = [
        boundary_signatures[1],
        boundary_signatures[2],
        boundary_signatures[3],
        boundary_signatures[5],
        boundary_signatures[6],
    ];

    for raw in scalar_valid_signatures {
        let der = secp256k1_ecdsa_jose_signature_to_der(&raw)?;
        assert!(Secp256k1Signature::from_der(&der).is_ok());
    }
    Ok(())
}

#[test]
fn preserves_low_value_scalars_without_extra_padding() -> Result<(), CryptoError> {
    let mut raw = [0u8; SECP256K1_ECDSA_JOSE_SIGNATURE_LEN];
    raw[31] = 0x01;
    raw[63] = 0x02;

    let der = secp256k1_ecdsa_jose_signature_to_der(&raw)?;
    assert_eq!(der, vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);

    let converted = secp256k1_ecdsa_der_to_jose_signature(&der)?;
    assert_eq!(converted, raw);
    Ok(())
}

#[test]
fn accepts_short_der_integers_and_left_pads_to_jose_width() -> Result<(), CryptoError> {
    let der = hex!("3006020101020102");
    let raw = secp256k1_ecdsa_der_to_jose_signature(&der)?;

    assert_eq!(raw[..31], [0u8; 31]);
    assert_eq!(raw[31], 0x01);
    assert_eq!(raw[32..63], [0u8; 31]);
    assert_eq!(raw[63], 0x02);
    assert_eq!(secp256k1_ecdsa_jose_signature_to_der(&raw)?, der);
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
    assert!(secp256k1_ecdsa_der_to_jose_signature(&der).is_err());

    let raw = secp256k1_ecdsa_der_to_jose_signature_permissive(&der)?;

    assert_eq!(raw[0], 0x7f);
    assert_eq!(raw[1], 0x01);
    assert_eq!(raw[31], 0x1f);
    assert_eq!(raw[63], 0x01);

    let canonical_der = secp256k1_ecdsa_jose_signature_to_der(&raw)?;
    assert_ne!(canonical_der, der);
    assert_eq!(secp256k1_ecdsa_der_to_jose_signature(&canonical_der)?, raw);
    Ok(())
}

#[test]
fn strict_rejects_but_permissive_accepts_der_long_form_lengths() -> Result<(), CryptoError> {
    let outer_long_form = hex!("308106020101020102");
    let integer_long_form = hex!("300702810101020102");

    let expected = secp256k1_ecdsa_der_to_jose_signature(&hex!("3006020101020102"))?;
    assert!(secp256k1_ecdsa_der_to_jose_signature(&outer_long_form).is_err());
    assert!(secp256k1_ecdsa_der_to_jose_signature(&integer_long_form).is_err());
    assert_eq!(
        secp256k1_ecdsa_der_to_jose_signature_permissive(&outer_long_form)?,
        expected
    );
    assert_eq!(
        secp256k1_ecdsa_der_to_jose_signature_permissive(&integer_long_form)?,
        expected
    );
    Ok(())
}

#[test]
fn rejects_wrong_jose_length() {
    let raw = [0u8; SECP256K1_ECDSA_JOSE_SIGNATURE_LEN + 1];

    assert!(secp256k1_ecdsa_jose_signature_to_der(&raw).is_err());
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

    assert!(secp256k1_ecdsa_der_to_jose_signature(&wrong_tag).is_err());
    assert!(secp256k1_ecdsa_der_to_jose_signature(&trailing).is_err());
    assert!(secp256k1_ecdsa_der_to_jose_signature(&negative_integer).is_err());
    assert!(secp256k1_ecdsa_der_to_jose_signature(&oversized_scalar).is_err());
}

#[test]
fn rejects_invalid_der_length_forms() {
    let indefinite_length = hex!("3080020101020102");
    let too_many_length_octets = hex!("3083000006020101020102");

    assert!(secp256k1_ecdsa_der_to_jose_signature(&indefinite_length).is_err());
    assert!(secp256k1_ecdsa_der_to_jose_signature(&too_many_length_octets).is_err());
}

#[cfg(all(feature = "native", not(all(feature = "wasm", target_arch = "wasm32"))))]
#[test]
fn native_secp256k1_signature_transcodes_through_der_and_still_verifies() -> Result<(), CryptoError>
{
    let secret = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let message = b"reallyme secp256k1 jose transcoding";
    let (public_key, secret_key) = generate_secp256k1_keypair_from_secret_key(&secret)?;

    let raw = sign_secp256k1(&secret_key, message)?;
    verify_secp256k1(&raw, message, &public_key)?;

    let der = secp256k1_ecdsa_jose_signature_to_der(&raw)?;
    let roundtrip_raw = secp256k1_ecdsa_der_to_jose_signature(&der)?;
    assert_eq!(roundtrip_raw.as_slice(), raw.as_slice());
    verify_secp256k1(&roundtrip_raw, message, &public_key)?;
    Ok(())
}
