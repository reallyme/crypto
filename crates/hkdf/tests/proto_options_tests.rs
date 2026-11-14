// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::expect_used)]
#![cfg(feature = "proto")]
use buffa::{EnumValue, Enumeration, Message, MessageField};
use crypto_core::CryptoError;
use crypto_hkdf::proto_options::{
    HkdfDeriveInputs, HkdfDomainKey32Inputs, HkdfExpandSha384Inputs, HkdfExtractSha384Inputs,
};
use crypto_hkdf::{DomainKeyPurpose, DomainTag, HKDF_SHA384_MAX_OUTPUT_LENGTH};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoHkdfDeriveInputs, CryptoHkdfDomainKey32Request, CryptoHkdfDomainTag,
    CryptoHkdfExpandSha384Request, CryptoHkdfExtractSha384Request, CryptoHkdfSuiteIdentifier,
    HashAlgorithm, HkdfDomainKeyPurpose as ProtoPurpose,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn domain_purpose_has_total_generated_parity() {
    for value in ProtoPurpose::values() {
        let native = DomainKeyPurpose::try_from(EnumValue::from(*value));
        if value.to_i32() == 0 {
            assert_eq!(native, Err(CryptoError::PRIMITIVE_INVALID_PARAMETER));
        } else {
            assert_eq!(ProtoPurpose::from(native.expect("known purpose")), *value);
        }
    }
    for unknown in [-1, 1, 99, i32::MAX] {
        assert_eq!(
            DomainKeyPurpose::try_from(EnumValue::<ProtoPurpose>::from(unknown)),
            Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
        );
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn native_derive_inputs_preserve_binary_info_and_optional_empty_salt() {
    for salt in [None, Some(Vec::new()), Some(vec![0, 0xff])] {
        let wire = CryptoHkdfDeriveInputs {
            suite: MessageField::some(CryptoHkdfSuiteIdentifier {
                hash: HashAlgorithm::HASH_ALGORITHM_SHA2_384.into(),
            }),
            input_key_material: vec![0x42; 32].into(),
            salt: salt.map(Into::into),
            info: vec![0, 0xff, 0xc3, 0xa9].into(),
        };
        let native = HkdfDeriveInputs::try_from(&wire).expect("native inputs");
        let returned = CryptoHkdfDeriveInputs::try_from(&native.as_request()).expect("wire inputs");
        assert_eq!(returned.input_key_material, wire.input_key_material);
        assert_eq!(returned.salt, wire.salt);
        assert_eq!(returned.info, wire.info);
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn sha384_extract_and_expand_preserve_exact_material_and_context() {
    for salt in [None, Some(Vec::new()), Some(vec![0x11; 16])] {
        let request = CryptoHkdfExtractSha384Request {
            input_key_material: vec![0x42; 32].into(),
            salt: salt.map(Into::into),
        };
        let native = HkdfExtractSha384Inputs::try_from(&request).expect("extract inputs");
        let returned = CryptoHkdfExtractSha384Request::try_from(&native).expect("extract wire");
        assert_eq!(returned.salt, request.salt);
        assert_eq!(returned.input_key_material, request.input_key_material);
    }
    let wire = expand_request();
    let native = HkdfExpandSha384Inputs::<32>::try_from(&wire).expect("expand inputs");
    let returned = CryptoHkdfExpandSha384Request::try_from(&native).expect("expand wire");
    assert_eq!(returned.pseudorandom_key, wire.pseudorandom_key);
    assert_eq!(returned.info, wire.info);
    assert_eq!(returned.output_length, 32);
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn expand_rejects_wrong_lengths_and_unknown_modifiers() -> Result<(), buffa::DecodeError> {
    let mut wire = expand_request();
    for invalid in [
        0,
        31,
        u32::try_from(HKDF_SHA384_MAX_OUTPUT_LENGTH + 1).expect("small bound"),
    ] {
        wire.output_length = invalid;
        assert_eq!(
            HkdfExpandSha384Inputs::<32>::try_from(&wire).err(),
            Some(CryptoError::PRIMITIVE_INVALID_LENGTH)
        );
    }
    wire = expand_request();
    wire.pseudorandom_key.resize(47, 0).expect("short fixture");
    assert_eq!(
        HkdfExpandSha384Inputs::<32>::try_from(&wire).err(),
        Some(CryptoError::PRIMITIVE_INVALID_KEY)
    );
    wire = expand_request();
    assert_unknown_wire(&wire, &[0xa0, 0x06, 0x01]);
    Ok(())
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn domain_tag_rejects_normalization_and_preserves_existing_profile_inputs(
) -> Result<(), buffa::DecodeError> {
    let mut tag = CryptoHkdfDomainTag {
        value: b"tenant/ab_09-x".to_vec().into(),
    };
    let native_tag = DomainTag::try_from(&tag).expect("valid exact tag");
    assert_eq!(native_tag.as_bytes(), tag.value.as_slice());
    assert_eq!(CryptoHkdfDomainTag::from(&native_tag).value, tag.value);
    for (bytes, expected) in [
        (b"Tenant".to_vec(), CryptoError::PRIMITIVE_INVALID_ENCODING),
        (Vec::new(), CryptoError::PRIMITIVE_INVALID_LENGTH),
        (vec![b'a'; 49], CryptoError::PRIMITIVE_INVALID_LENGTH),
    ] {
        tag.value = bytes.into();
        assert_eq!(DomainTag::try_from(&tag).err(), Some(expected));
    }
    tag.value = b"tenant/ab_09-x".to_vec().into();
    let wire = CryptoHkdfDomainKey32Request {
        input_key_material: vec![0x42; 32].into(),
        salt: Some(Vec::new().into()),
        purpose: ProtoPurpose::HKDF_DOMAIN_KEY_PURPOSE_AUTH_PROOF_KEY.into(),
        domain_tag: MessageField::some(tag),
    };
    let native = HkdfDomainKey32Inputs::try_from(&wire).expect("existing fixed profile inputs");
    let returned = CryptoHkdfDomainKey32Request::try_from(&native).expect("fixed profile wire");
    assert_eq!(returned.salt, wire.salt);
    assert_eq!(returned.purpose, wire.purpose);
    assert_eq!(
        returned.domain_tag.as_option().expect("tag").value,
        wire.domain_tag.as_option().expect("tag").value
    );
    let bad = CryptoHkdfDomainTag::from(&native_tag);
    assert_unknown_wire(&bad, &[0xa0, 0x06, 0x01]);
    Ok(())
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn request_owners_clear_owned_material() {
    fn require_cleanup<T: ZeroizeOnDrop>() {}
    require_cleanup::<HkdfDeriveInputs>();
    require_cleanup::<HkdfExtractSha384Inputs>();
    require_cleanup::<HkdfExpandSha384Inputs<32>>();
    require_cleanup::<HkdfDomainKey32Inputs>();
    let mut native =
        HkdfExpandSha384Inputs::<32>::try_from(&expand_request()).expect("expand inputs");
    native.zeroize();
    assert!(native.prk().as_bytes().iter().all(|byte| *byte == 0));
    assert!(native.info().as_bytes().is_empty());
}
#[cfg(not(feature = "sha3"))]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn domain_metadata_does_not_enable_sha3_execution() {
    let wire = CryptoHkdfDomainKey32Request {
        input_key_material: vec![0x42; 32],
        salt: None,
        purpose: ProtoPurpose::HKDF_DOMAIN_KEY_PURPOSE_AEAD_CONTENT_KEY.into(),
        domain_tag: MessageField::some(CryptoHkdfDomainTag {
            value: b"tenant".to_vec(),
        }),
    };
    let native = HkdfDomainKey32Inputs::try_from(&wire).expect("metadata exists independently");
    assert_eq!(
        crypto_hkdf::derive_domain_key_32(
            native.ikm(),
            native.salt(),
            native.purpose(),
            native.domain_tag()
        )
        .err(),
        Some(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    );
}
fn expand_request() -> CryptoHkdfExpandSha384Request {
    CryptoHkdfExpandSha384Request {
        pseudorandom_key: vec![0x42; 48].into(),
        info: vec![0, 0xff, 1].into(),
        output_length: 32,
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn derive_extract_and_domain_inputs_reject_missing_or_unknown_modifiers(
) -> Result<(), buffa::DecodeError> {
    let mut derive = CryptoHkdfDeriveInputs {
        suite: MessageField::none(),
        input_key_material: vec![0x42; 32].into(),
        salt: None,
        info: Vec::new().into(),
    };
    assert_eq!(
        HkdfDeriveInputs::try_from(&derive).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    let suite = CryptoHkdfSuiteIdentifier {
        hash: HashAlgorithm::HASH_ALGORITHM_SHA2_384.into(),
    };
    let mut modified_child = suite.encode_to_vec();
    modified_child.extend_from_slice(&[0xa0, 0x06, 0x01]);
    derive.suite = MessageField::some(suite);
    let mut modified = derive.encode_to_vec();
    // The duplicate child retains protobuf merge semantics but the unknown
    // modifier must fail admission before any operation uses the message.
    buffa::encoding::encode_varint((1u64 << 3) | 2, &mut modified);
    buffa::encoding::encode_varint(
        u64::try_from(modified_child.len()).unwrap_or(u64::MAX),
        &mut modified,
    );
    modified.extend_from_slice(&modified_child);
    assert!(crypto_proto::wire::decode_protobuf::<CryptoHkdfDeriveInputs>(&modified).is_err());
    let extract = CryptoHkdfExtractSha384Request {
        input_key_material: vec![0x42; 32].into(),
        salt: None,
    };
    assert_unknown_wire(&extract, &[0xa0, 0x06, 0x01]);
    let empty = CryptoHkdfExtractSha384Request::default();
    assert_eq!(
        HkdfExtractSha384Inputs::try_from(&empty).err(),
        Some(CryptoError::PRIMITIVE_INVALID_KEY)
    );
    let mut domain = CryptoHkdfDomainKey32Request {
        input_key_material: vec![0x42; 32].into(),
        salt: None,
        purpose: ProtoPurpose::HKDF_DOMAIN_KEY_PURPOSE_AEAD_CONTENT_KEY.into(),
        domain_tag: MessageField::none(),
    };
    assert_eq!(
        HkdfDomainKey32Inputs::try_from(&domain).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    domain.domain_tag = MessageField::some(CryptoHkdfDomainTag {
        value: b"tenant".to_vec().into(),
    });
    for purpose in [0, -1, i32::MAX] {
        domain.purpose = purpose.into();
        assert_eq!(
            HkdfDomainKey32Inputs::try_from(&domain).err(),
            Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
        );
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn generated_options_owners_clear_retained_storage() {
    fn require_cleanup<T: zeroize::ZeroizeOnDrop>() {}
    require_cleanup::<crypto_proto::generated::proto::reallyme::crypto::v1::CryptoHkdfDomainTag>();
    require_cleanup::<crypto_proto::generated::proto::reallyme::crypto::v1::CryptoHkdfDeriveInputs>(
    );
    require_cleanup::<
        crypto_proto::generated::proto::reallyme::crypto::v1::CryptoHkdfExtractSha384Request,
    >();
    require_cleanup::<
        crypto_proto::generated::proto::reallyme::crypto::v1::CryptoHkdfExtractSha384Result,
    >();
    require_cleanup::<
        crypto_proto::generated::proto::reallyme::crypto::v1::CryptoHkdfExpandSha384Request,
    >();
    require_cleanup::<
        crypto_proto::generated::proto::reallyme::crypto::v1::CryptoHkdfDomainKey32Request,
    >();
}

fn assert_unknown_wire<M: buffa::Message>(message: &M, modifier: &[u8]) {
    let mut wire = message.encode_to_vec();
    wire.extend_from_slice(modifier);
    assert!(matches!(crypto_proto::wire::decode_protobuf::<M>(&wire),
        Err(error) if error == crypto_proto::wire::CryptoWireError::malformed_protobuf()));
}
