// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! JOSE ECDSA signature transcoding tests for P-256.

use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};
use crypto_p256::{
    p256_ecdsa_der_to_jose_signature, p256_ecdsa_jose_signature_to_der,
    P256_ECDSA_JOSE_SIGNATURE_LEN,
};
use hex_literal::hex;

#[cfg(feature = "native")]
use crypto_p256::{
    generate_p256_keypair_from_secret_key, sign_p256_sha256_message_low_s_der,
    verify_p256_sha256_message_der_interoperable,
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

fn boundary_jose_signatures() -> [[u8; P256_ECDSA_JOSE_SIGNATURE_LEN]; 6] {
    [
        raw_signature_from_scalars(scalar_with_last(0x01), scalar_with_last(0x02)),
        raw_signature_from_scalars(scalar_with_first(0x7f), scalar_with_first(0x01)),
        raw_signature_from_scalars(scalar_with_first(0x80), scalar_with_first(0x81)),
        raw_signature_from_scalars(
            hex!("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550"),
            hex!("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550"),
        ),
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

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
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

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn boundary_jose_signatures_roundtrip_through_der() -> Result<(), CryptoError> {
    for raw in boundary_jose_signatures() {
        let der = p256_ecdsa_jose_signature_to_der(&raw)?;
        let converted = p256_ecdsa_der_to_jose_signature(&der)?;
        assert_eq!(converted, raw);
    }
    Ok(())
}

#[cfg(feature = "native")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn boundary_der_outputs_are_accepted_by_p256_der_oracle() -> Result<(), CryptoError> {
    for raw in boundary_jose_signatures() {
        let der = p256_ecdsa_jose_signature_to_der(&raw)?;
        assert!(P256Signature::from_der(&der).is_ok());
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
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

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
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

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rejects_redundant_positive_integer_padding() {
    let der = hex!(
        "3027
         0222
         00007f0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
         020101"
    );
    assert!(p256_ecdsa_der_to_jose_signature(&der).is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rejects_noncanonical_der_long_form_lengths() {
    let outer_long_form = hex!("308106020101020102");
    let integer_long_form = hex!("300702810101020102");

    assert!(p256_ecdsa_der_to_jose_signature(&outer_long_form).is_err());
    assert!(p256_ecdsa_der_to_jose_signature(&integer_long_form).is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rejects_wrong_jose_length() {
    let raw = [0u8; P256_ECDSA_JOSE_SIGNATURE_LEN - 1];

    assert!(p256_ecdsa_jose_signature_to_der(&raw).is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rejects_zero_and_out_of_range_p256_scalars() {
    let one = scalar_with_last(0x01);
    let order = hex!("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    for raw in [
        raw_signature_from_scalars([0u8; 32], one),
        raw_signature_from_scalars(one, [0u8; 32]),
        raw_signature_from_scalars(order, one),
        raw_signature_from_scalars(one, order),
    ] {
        assert!(p256_ecdsa_jose_signature_to_der(&raw).is_err());
    }

    let zero_r = hex!("3006020100020101");
    let zero_s = hex!("3006020101020100");
    let order_r =
        hex!("3026022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551020101");
    let order_s =
        hex!("3026020101022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    for der in [
        zero_r.as_slice(),
        zero_s.as_slice(),
        order_r.as_slice(),
        order_s.as_slice(),
    ] {
        assert!(p256_ecdsa_der_to_jose_signature(der).is_err());
    }

    #[cfg(feature = "native")]
    {
        assert!(P256Signature::from_der(&order_r).is_err());
        assert!(P256Signature::from_der(&order_s).is_err());
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
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

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rejects_invalid_der_length_forms() {
    let indefinite_length = hex!("3080020101020102");
    let too_many_length_octets = hex!("3083000006020101020102");

    assert!(p256_ecdsa_der_to_jose_signature(&indefinite_length).is_err());
    assert!(p256_ecdsa_der_to_jose_signature(&too_many_length_octets).is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn codec_der_rejects_malformed_signatures_even_with_ber_enabled() {
    use der_core::Decode;

    // This entry point exists only when the unified BER feature is enabled.
    assert!(matches!(u8::from_ber(&[0x02, 0x01, 0x01]), Ok(1)));
    const MALFORMED: &[&[u8]] = &[
        &[],
        &hex!("30050200020101"),
        &hex!("3006220101020101"),
        &hex!("3009020101020101020101"),
        &hex!("3003020101"),
        &hex!("3088ffffffffffffffff"),
        &hex!("30800201010201010000"),
        &hex!("300702020001020101"),
        &hex!("3006020180020101"),
        &hex!("300602010102010100"),
        &[0; 73],
    ];
    let expected = CryptoError::Signature {
        backend: SignatureBackend::Native,
        operation: SignatureOperation::Verify,
        kind: SignatureFailureKind::InvalidSignature,
    };
    for der in MALFORMED {
        assert_eq!(p256_ecdsa_der_to_jose_signature(der), Err(expected.clone()));
        #[cfg(any(feature = "native", feature = "wasm"))]
        {
            let public = hex!(
                "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
                   4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
            );
            assert_eq!(
                crypto_p256::verify_p256_sha256_message_der_interoperable(
                    der,
                    b"strict DER boundary",
                    &public,
                ),
                Err(expected.clone())
            );
        }
    }
}

#[cfg(feature = "native")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn native_p256_signature_transcodes_through_jose_and_still_verifies() -> Result<(), CryptoError> {
    let secret = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let message = b"reallyme p256 jose transcoding";
    let (public_key, secret_key) = generate_p256_keypair_from_secret_key(&secret)?;

    let der = sign_p256_sha256_message_low_s_der(&secret_key, message)?;
    verify_p256_sha256_message_der_interoperable(&der, message, &public_key)?;

    let raw = p256_ecdsa_der_to_jose_signature(&der)?;
    assert_eq!(raw.len(), P256_ECDSA_JOSE_SIGNATURE_LEN);

    let roundtrip_der = p256_ecdsa_jose_signature_to_der(&raw)?;
    verify_p256_sha256_message_der_interoperable(&roundtrip_der, message, &public_key)?;
    Ok(())
}
