// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
#![allow(clippy::field_reassign_with_default)] // Populate already-clearing transport owners.
#![cfg(all(feature = "operation-response", feature = "ecdsa-explicit"))]

use buffa::{EnumValue, Enumeration, Message, MessageField};
use crypto_core::CryptoError;
#[cfg(not(any(feature = "native", feature = "wasm")))]
use crypto_proto::generated::proto::reallyme::crypto::v1::CryptoP256LowSSignRequest;
#[cfg(any(feature = "native", feature = "wasm"))]
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_ecdsa_input::Input, CryptoEcdsaInput, CryptoEcdsaMessageInput,
    CryptoEcdsaPrehashInput, CryptoP256LowSSignRequest, HashAlgorithm,
};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoEcdsaCurveIdentifier, CryptoEcdsaSignatureTranscodeRequest,
    CryptoP256PrivateKeyContainerImportRequest, CryptoP256PublicKeyContainerImportRequest,
    CryptoP256SignatureNormalizeRequest, EcdsaCurve as ProtoCurve, EcdsaEncoding,
    P256KeyContainerFormat,
};
#[cfg(any(feature = "native", feature = "wasm"))]
use reallyme_crypto::ecdsa_explicit::EcdsaKey;
use reallyme_crypto::ecdsa_explicit::{format_contract as contract, EcdsaCurve};
#[cfg(any(feature = "native", feature = "wasm"))]
use zeroize::Zeroize;
use zeroize::ZeroizeOnDrop;

#[cfg(any(feature = "native", feature = "wasm"))]
fn message(bytes: &[u8]) -> CryptoEcdsaInput {
    let mut body = CryptoEcdsaMessageInput::default();
    body.hash = HashAlgorithm::HASH_ALGORITHM_SHA2_256.into();
    body.message.extend_from_slice(bytes);
    let mut output = CryptoEcdsaInput::default();
    output.input = Some(Input::Message(Box::new(body)));
    output
}
#[cfg(any(feature = "native", feature = "wasm"))]
fn sign_request(bytes: &[u8]) -> CryptoP256LowSSignRequest {
    CryptoP256LowSSignRequest {
        input: MessageField::some(message(bytes)),
        __buffa_unknown_fields: Default::default(),
    }
}
fn curve(value: ProtoCurve) -> CryptoEcdsaCurveIdentifier {
    CryptoEcdsaCurveIdentifier {
        curve: value.into(),
        __buffa_unknown_fields: Default::default(),
    }
}
fn transcode(
    value: ProtoCurve,
    source: EcdsaEncoding,
    target: EcdsaEncoding,
    bytes: &[u8],
) -> CryptoEcdsaSignatureTranscodeRequest {
    let mut request = CryptoEcdsaSignatureTranscodeRequest::default();
    request.curve = MessageField::some(curve(value));
    request.source_encoding = source.into();
    request.target_encoding = target.into();
    request.signature.extend_from_slice(bytes);
    request
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn all_curves_transcode_and_disabled_curves_fail_with_existing_typed_error(
) -> Result<(), CryptoError> {
    for value in ProtoCurve::values() {
        if *value == ProtoCurve::ECDSA_CURVE_UNSPECIFIED {
            continue;
        }
        let native = EcdsaCurve::try_from(&curve(*value))?;
        let width = match native {
            EcdsaCurve::P256 | EcdsaCurve::BrainpoolP256r1 => 32,
            EcdsaCurve::P384 | EcdsaCurve::BrainpoolP384r1 => 48,
            EcdsaCurve::P521 => 66,
            EcdsaCurve::BrainpoolP320r1 => 40,
            EcdsaCurve::BrainpoolP512r1 => 64,
        };
        let mut raw = vec![0; width * 2];
        raw[width - 1] = 1;
        raw[width * 2 - 1] = 1;
        let probe = transcode(
            *value,
            EcdsaEncoding::ECDSA_ENCODING_FIXED_WIDTH,
            EcdsaEncoding::ECDSA_ENCODING_DER,
            &raw,
        );
        match reallyme_crypto::ecdsa_explicit::fixed_to_der(native, &raw) {
            Ok(expected) => {
                let der = contract::transcode_signature(&probe)?;
                assert_eq!(der.signature, expected);
                let reverse = transcode(
                    *value,
                    EcdsaEncoding::ECDSA_ENCODING_DER,
                    EcdsaEncoding::ECDSA_ENCODING_FIXED_WIDTH,
                    &der.signature,
                );
                assert_eq!(contract::transcode_signature(&reverse)?.signature, raw);
            }
            Err(error) => {
                assert!(matches!(contract::transcode_signature(&probe),Err(e) if e==error))
            }
        }
    }
    let request = transcode(
        ProtoCurve::ECDSA_CURVE_NIST_P256,
        EcdsaEncoding::ECDSA_ENCODING_DER,
        EcdsaEncoding::ECDSA_ENCODING_FIXED_WIDTH,
        &[0x30, 6, 2, 1, 1, 2, 1, 1],
    );
    assert_eq!(
        request.encode_to_vec(),
        [0x0a, 2, 8, 100, 0x10, 100, 0x18, 110, 0x22, 8, 0x30, 6, 2, 1, 1, 2, 1, 1]
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn representation_selectors_malformed_der_and_same_encoding_fail_closed() {
    let mut probe = transcode(
        ProtoCurve::ECDSA_CURVE_NIST_P256,
        EcdsaEncoding::ECDSA_ENCODING_DER,
        EcdsaEncoding::ECDSA_ENCODING_FIXED_WIDTH,
        &[0x30, 7, 2, 2, 0, 1, 2, 1, 1],
    );
    assert!(
        matches!(contract::transcode_signature(&probe),Err(e) if e==CryptoError::PRIMITIVE_INVALID_SIGNATURE)
    );
    probe.target_encoding = probe.source_encoding;
    assert!(
        matches!(contract::transcode_signature(&probe),Err(e) if e==CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    for selector in [0, 1, -1, i32::MAX] {
        probe.source_encoding = EnumValue::from(selector);
        assert!(
            matches!(contract::transcode_signature(&probe),Err(e) if e==CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
        );
    }
    let mut wire = probe.encode_to_vec();
    wire.extend_from_slice(&[0xf8, 7, 1]);
    let probe = CryptoEcdsaSignatureTranscodeRequest::decode_from_slice(&wire).unwrap();
    assert!(
        matches!(contract::transcode_signature(&probe),Err(e) if e==CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn low_s_normalization_preserves_encoding_and_rejects_bad_scalars() -> Result<(), CryptoError> {
    let r =
        hex::decode("6e3038666f0655a681c1636c9191509227335c61527ff220426809a695e07ed7").unwrap();
    let high =
        hex::decode("a37377a349087a2446d5839c0db705caf20b9e42edc4b819892e4bbe866754c6").unwrap();
    let low =
        hex::decode("5c8c885bb6f785dcb92a7c63f248fa34cadb5c6ab952e66b6a8b7f0475fbd08b").unwrap();
    let mut raw = r.clone();
    raw.extend_from_slice(&high);
    let mut expected = r;
    expected.extend_from_slice(&low);
    for encoding in [
        EcdsaEncoding::ECDSA_ENCODING_DER,
        EcdsaEncoding::ECDSA_ENCODING_FIXED_WIDTH,
    ] {
        let bytes = if encoding == EcdsaEncoding::ECDSA_ENCODING_DER {
            crypto_p256::p256_ecdsa_jose_signature_to_der(&raw)?
        } else {
            raw.clone()
        };
        let expected = if encoding == EcdsaEncoding::ECDSA_ENCODING_DER {
            crypto_p256::p256_ecdsa_jose_signature_to_der(&expected)?
        } else {
            expected.clone()
        };
        let mut probe = CryptoP256SignatureNormalizeRequest::default();
        probe.encoding = encoding.into();
        probe.signature = bytes;
        assert_eq!(
            reallyme_crypto::format_contract::normalize_p256_signature(&probe)?.signature,
            expected
        );
        probe.signature.fill(0);
        assert!(
            matches!(reallyme_crypto::format_contract::normalize_p256_signature(&probe), Err(error) if error == CryptoError::PRIMITIVE_INVALID_SIGNATURE)
        );
    }
    Ok(())
}

#[cfg(any(feature = "native", feature = "wasm"))]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn low_s_message_digest_strict_verification_and_high_s_compatibility_are_distinct(
) -> Result<(), CryptoError> {
    use crypto_proto::generated::proto::reallyme::crypto::v1::CryptoP256LowSVerifyRequest;
    let scalar =
        hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
    let key = EcdsaKey::import(EcdsaCurve::P256, &scalar)?;
    let bytes = b"exact\0message\xff bytes";
    let signature = contract::sign_p256_low_s(&key, &sign_request(bytes))?;
    assert_eq!(
        signature.signature,
        crypto_p256::sign_p256_sha256_message_low_s_der(&scalar, bytes)?
    );
    let digest = crypto_sha2_256::digest(bytes);
    let mut prehash = CryptoEcdsaPrehashInput::default();
    prehash.hash = HashAlgorithm::HASH_ALGORITHM_SHA2_256.into();
    prehash.digest.extend_from_slice(digest.as_bytes());
    let input = CryptoEcdsaInput {
        input: Some(Input::Prehash(Box::new(prehash))),
        __buffa_unknown_fields: Default::default(),
    };
    let request = CryptoP256LowSSignRequest {
        input: MessageField::some(input),
        __buffa_unknown_fields: Default::default(),
    };
    assert_eq!(
        contract::sign_p256_low_s(&key, &request)?.signature,
        signature.signature
    );
    let mut verify = CryptoP256LowSVerifyRequest::default();
    verify.signature_der.extend_from_slice(&signature.signature);
    verify.sha256_digest.extend_from_slice(digest.as_bytes());
    verify.public_key_sec1.extend_from_slice(key.public_key());
    contract::verify_p256_low_s(&verify)?;
    let mut raw = crypto_p256::p256_ecdsa_der_to_jose_signature(&signature.signature)?;
    let order =
        hex::decode("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551").unwrap();
    let mut borrow = 0u16;
    for i in (0..32).rev() {
        let left = u16::from(order[i]);
        let right = u16::from(raw[32 + i]) + borrow;
        if left >= right {
            raw[32 + i] = u8::try_from(left - right).unwrap();
            borrow = 0;
        } else {
            raw[32 + i] = u8::try_from(256 + left - right).unwrap();
            borrow = 1;
        }
    }
    verify.signature_der = crypto_p256::p256_ecdsa_jose_signature_to_der(&raw)?;
    assert!(
        matches!(contract::verify_p256_low_s(&verify),Err(e) if e==CryptoError::PRIMITIVE_INVALID_SIGNATURE)
    );
    crypto_p256::verify_p256_sha256_message_der_interoperable(
        &verify.signature_der,
        bytes,
        key.public_key(),
    )?;
    // Restore the valid low-S signature so this failure is caused by the
    // changed digest rather than the independent high-S rejection above.
    verify.signature_der.clear();
    verify.signature_der.extend_from_slice(&signature.signature);
    contract::verify_p256_low_s(&verify)?;
    verify.sha256_digest[0] ^= 1;
    assert!(
        matches!(contract::verify_p256_low_s(&verify), Err(error) if error == CryptoError::PRIMITIVE_INVALID_SIGNATURE)
    );
    verify.sha256_digest.clear();
    assert!(
        matches!(contract::verify_p256_low_s(&verify),Err(e) if e==CryptoError::PRIMITIVE_INVALID_LENGTH)
    );
    let mut wrong_hash = CryptoEcdsaMessageInput::default();
    wrong_hash.hash = HashAlgorithm::HASH_ALGORITHM_SHA2_384.into();
    wrong_hash.message.extend_from_slice(bytes);
    let wrong_hash = CryptoP256LowSSignRequest {
        input: MessageField::some(CryptoEcdsaInput {
            input: Some(Input::Message(Box::new(wrong_hash))),
            __buffa_unknown_fields: Default::default(),
        }),
        __buffa_unknown_fields: Default::default(),
    };
    assert!(
        matches!(contract::sign_p256_low_s(&key, &wrong_hash), Err(error) if error == CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    );
    let other = EcdsaKey::import(EcdsaCurve::P384, &[1; 48])?;
    assert!(
        matches!(contract::sign_p256_low_s(&other, &sign_request(bytes)), Err(error) if error == CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    );
    let mut destroyed = EcdsaKey::import(EcdsaCurve::P256, &scalar)?;
    destroyed.zeroize();
    assert!(
        matches!(contract::sign_p256_low_s(&destroyed, &sign_request(bytes)), Err(error) if error == CryptoError::PRIMITIVE_INVALID_PRIVATE_KEY)
    );
    let empty = contract::sign_p256_low_s(&key, &sign_request(&[]))?;
    assert_eq!(
        empty.signature,
        crypto_p256::sign_p256_sha256_message_low_s_der(&scalar, &[])?
    );
    assert!(
        matches!(contract::sign_p256_low_s(&key,&CryptoP256LowSSignRequest::default()),Err(e) if e==CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn import_selectors_and_protected_owners_reject_unrecognized_modifiers() {
    fn clearing<T: ZeroizeOnDrop>() {
        assert!(core::mem::needs_drop::<T>());
    }
    clearing::<CryptoP256PrivateKeyContainerImportRequest>();
    clearing::<CryptoP256PublicKeyContainerImportRequest>();
    clearing::<CryptoP256LowSSignRequest>();
    for format in P256KeyContainerFormat::values() {
        if *format == P256KeyContainerFormat::P256_KEY_CONTAINER_FORMAT_UNSPECIFIED {
            continue;
        }
        let request = CryptoP256PrivateKeyContainerImportRequest {
            format: (*format).into(),
            document: Vec::new(),
            __buffa_unknown_fields: Default::default(),
        };
        #[cfg(feature = "native")]
        let expected = match format {
            P256KeyContainerFormat::P256_KEY_CONTAINER_FORMAT_PKCS8_DER
            | P256KeyContainerFormat::P256_KEY_CONTAINER_FORMAT_SEC1_DER
            | P256KeyContainerFormat::P256_KEY_CONTAINER_FORMAT_PKCS8_PEM
            | P256KeyContainerFormat::P256_KEY_CONTAINER_FORMAT_SEC1_PEM
            | P256KeyContainerFormat::P256_KEY_CONTAINER_FORMAT_PRIVATE_PEM => {
                CryptoError::PRIMITIVE_INVALID_KEY
            }
            _ => CryptoError::PRIMITIVE_INVALID_PARAMETER,
        };
        #[cfg(not(feature = "native"))]
        let expected = CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM;
        assert!(matches!(contract::import_p256_private(&request), Err(error) if error == expected));
    }
    for value in [0, -1, 1, 99, 999, i32::MAX] {
        let request = CryptoP256PrivateKeyContainerImportRequest {
            format: EnumValue::from(value),
            document: Vec::new(),
            __buffa_unknown_fields: Default::default(),
        };
        assert!(
            matches!(contract::import_p256_private(&request),Err(e) if e==CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
        );
    }
    let request =
        CryptoP256PrivateKeyContainerImportRequest::decode_from_slice(&[8, 100, 0xf8, 7, 1])
            .unwrap();
    assert!(
        matches!(contract::import_p256_private(&request),Err(e) if e==CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    );
    let mut request = CryptoP256PrivateKeyContainerImportRequest::default();
    request.document.extend_from_slice(&[1; 32]);
    buffa::Message::clear(&mut request);
    assert!(request.document.is_empty() || request.document.iter().all(|b| *b == 0));
}

#[cfg(feature = "native")]
#[test]
fn native_container_formats_delegate_without_private_export() -> Result<(), CryptoError> {
    use crypto_proto::generated::proto::reallyme::crypto::v1::CryptoP256CompressedPublicKeyRequest;
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
    // SEC1 and SPKI bytes match crates/p256/tests/pem_import_tests.rs. The
    // PKCS8 fixture wraps that same SEC1 document; no upstream PEM feature or
    // additional cryptographic key is needed to exercise all import policies.
    const SEC1_PRIVATE_KEY_PEM: &str = "\
-----BEGIN EC PRIVATE KEY-----\n\
MHcCAQEEIOgPgBUgYyf6m41b5IRklKSREgDo3I44nxKH/E++HkiYoAoGCCqGSM49\n\
AwEHoUQDQgAEUJG3pn7PaQ+/lGOs0+lv90XlK4cAZ63VYQGkC8pyM9o2X+4OgR3p\n\
mOIRWJJrKvGAQrFT5T1NhwZrafAHMBBblw==\n\
-----END EC PRIVATE KEY-----\n";
    const SPKI_PUBLIC_KEY_PEM: &str = "\
-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUJG3pn7PaQ+/lGOs0+lv90XlK4cA\n\
Z63VYQGkC8pyM9o2X+4OgR3pmOIRWJJrKvGAQrFT5T1NhwZrafAHMBBblw==\n\
-----END PUBLIC KEY-----\n";
    const PKCS8_PRIVATE_KEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----\n\
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg6A+AFSBjJ/qbjVvk\n\
hGSUpJESAOjcjjifEof8T74eSJigCgYIKoZIzj0DAQehRANCAARQkbemfs9pD7+U\n\
Y6zT6W/3ReUrhwBnrdVhAaQLynIz2jZf7g6BHemY4hFYkmsq8YBCsVPlPU2HBmtp\n\
8AcwEFuX\n\
-----END PRIVATE KEY-----\n";
    let scalar = crypto_p256::private_key_from_sec1_pem(SEC1_PRIVATE_KEY_PEM)?;
    let secret = p256::SecretKey::from_slice(scalar.as_slice()).unwrap();
    let pkcs8 = secret.to_pkcs8_der().unwrap();
    let sec1 = secret.to_sec1_der().unwrap();
    let expected = crypto_p256::public_key_from_spki_pem(SPKI_PUBLIC_KEY_PEM)?;
    assert_eq!(
        crypto_p256::compressed_public_key_from_private_key(&scalar)?,
        expected
    );
    for (format, bytes) in [
        (
            P256KeyContainerFormat::P256_KEY_CONTAINER_FORMAT_PKCS8_DER,
            pkcs8.as_bytes(),
        ),
        (
            P256KeyContainerFormat::P256_KEY_CONTAINER_FORMAT_SEC1_DER,
            sec1.as_slice(),
        ),
        (
            P256KeyContainerFormat::P256_KEY_CONTAINER_FORMAT_PKCS8_PEM,
            PKCS8_PRIVATE_KEY_PEM.as_bytes(),
        ),
        (
            P256KeyContainerFormat::P256_KEY_CONTAINER_FORMAT_SEC1_PEM,
            SEC1_PRIVATE_KEY_PEM.as_bytes(),
        ),
        (
            P256KeyContainerFormat::P256_KEY_CONTAINER_FORMAT_PRIVATE_PEM,
            PKCS8_PRIVATE_KEY_PEM.as_bytes(),
        ),
        (
            P256KeyContainerFormat::P256_KEY_CONTAINER_FORMAT_PRIVATE_PEM,
            SEC1_PRIVATE_KEY_PEM.as_bytes(),
        ),
    ] {
        let mut request = CryptoP256PrivateKeyContainerImportRequest::default();
        request.format = format.into();
        request.document.extend_from_slice(bytes);
        let key = contract::import_p256_private(&request)?;
        assert_eq!(
            contract::compressed_p256_public_key(
                &key,
                &CryptoP256CompressedPublicKeyRequest::default()
            )?
            .sec1,
            expected
        );
    }
    let public = secret.public_key();
    let der = public.to_public_key_der().unwrap();
    for (format, bytes) in [
        (
            P256KeyContainerFormat::P256_KEY_CONTAINER_FORMAT_SPKI_DER,
            der.as_bytes(),
        ),
        (
            P256KeyContainerFormat::P256_KEY_CONTAINER_FORMAT_SPKI_PEM,
            SPKI_PUBLIC_KEY_PEM.as_bytes(),
        ),
    ] {
        let mut request = CryptoP256PublicKeyContainerImportRequest::default();
        request.format = format.into();
        request.document.extend_from_slice(bytes);
        assert_eq!(contract::import_p256_public(&request)?.sec1, expected);
    }
    for bytes in [&[][..], &[255, 255][..], vec![0; 4097].as_slice()] {
        let mut request = CryptoP256PrivateKeyContainerImportRequest::default();
        request.format = P256KeyContainerFormat::P256_KEY_CONTAINER_FORMAT_PKCS8_DER.into();
        request.document.extend_from_slice(bytes);
        assert!(
            matches!(contract::import_p256_private(&request), Err(error) if error == CryptoError::PRIMITIVE_INVALID_KEY)
        );
    }
    let mut request = CryptoP256PrivateKeyContainerImportRequest::default();
    request.format = P256KeyContainerFormat::P256_KEY_CONTAINER_FORMAT_PKCS8_PEM.into();
    request.document.extend_from_slice(&[255]);
    assert!(
        matches!(contract::import_p256_private(&request),Err(e) if e==CryptoError::PRIMITIVE_INVALID_KEY)
    );
    Ok(())
}

#[cfg(not(feature = "native"))]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn native_only_container_import_does_not_enable_a_fallback() {
    let request = CryptoP256PrivateKeyContainerImportRequest {
        format: P256KeyContainerFormat::P256_KEY_CONTAINER_FORMAT_PKCS8_DER.into(),
        document: vec![1; 16],
        __buffa_unknown_fields: Default::default(),
    };
    assert!(
        matches!(contract::import_p256_private(&request),Err(e) if e==CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    );
    let request = CryptoP256PublicKeyContainerImportRequest {
        format: P256KeyContainerFormat::P256_KEY_CONTAINER_FORMAT_SPKI_DER.into(),
        document: vec![1; 16],
        __buffa_unknown_fields: Default::default(),
    };
    assert!(
        matches!(contract::import_p256_public(&request),Err(e) if e==CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn standalone_explicit_point_validation_matches_every_existing_curve() -> Result<(), CryptoError> {
    use crypto_proto::generated::proto::reallyme::crypto::v1::CryptoEcdsaPublicKeyValidationRequest;
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("data/ecdsa_explicit.json")).unwrap();
    for vector in fixture["vectors"].as_array().unwrap() {
        let native = match vector["curve"].as_str().unwrap() {
            "P256" => EcdsaCurve::P256,
            "P384" => EcdsaCurve::P384,
            "P521" => EcdsaCurve::P521,
            "BrainpoolP256r1" => EcdsaCurve::BrainpoolP256r1,
            "BrainpoolP320r1" => EcdsaCurve::BrainpoolP320r1,
            "BrainpoolP384r1" => EcdsaCurve::BrainpoolP384r1,
            "BrainpoolP512r1" => EcdsaCurve::BrainpoolP512r1,
            _ => return Err(CryptoError::BACKEND_INTERNAL),
        };
        let mut request = CryptoEcdsaPublicKeyValidationRequest::default();
        request.curve = MessageField::some(curve(native.into()));
        request.public_key_sec1 = hex::decode(vector["public"].as_str().unwrap()).unwrap();
        match reallyme_crypto::ecdsa_explicit::validate_public_key(native, &request.public_key_sec1)
        {
            Ok(()) => {
                contract::validate_public_key(&request)?;
            }
            Err(expected) => {
                assert!(matches!(contract::validate_public_key(&request),Err(e)if e==expected))
            }
        }
        request.public_key_sec1.clear();
        let expected = match native {
            EcdsaCurve::P256 | EcdsaCurve::P384 | EcdsaCurve::P521 => {
                CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY
            }
            _ if cfg!(any(
                feature = "brainpool",
                all(feature = "brainpool-openssl", not(target_arch = "wasm32"))
            )) =>
            {
                CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY
            }
            _ => CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM,
        };
        assert!(matches!(contract::validate_public_key(&request), Err(error) if error == expected));
    }
    Ok(())
}
