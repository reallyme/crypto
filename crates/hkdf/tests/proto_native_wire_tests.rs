// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::expect_used)]
#![cfg(feature = "proto")]

use buffa::{EnumValue, Message, MessageField};
use crypto_core::CryptoError;
use crypto_hkdf::proto_native::HkdfNativeDeriveInputs;
use crypto_hkdf::HkdfSuite;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoHkdfDeriveInputs, CryptoHkdfNativeDeriveRequest, CryptoHkdfSuiteIdentifier, HashAlgorithm,
};
use hex_literal::hex;
use zeroize::Zeroizing;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn wire_known_answer_preserves_exact_context_and_empty_salt_presence() {
    let mut wire = request(None);
    let encoded = Zeroizing::new(wire.encode_to_vec());
    assert_eq!(*encoded, hex!("0a0c0a020864120200ff220200201011"));
    let mut decoded = CryptoHkdfNativeDeriveRequest::default();
    decoded
        .merge_from_slice(&encoded)
        .expect("known wire answer");
    check_inputs(&decoded, None);
    let json = Zeroizing::new(serde_json::to_string(&wire).expect("ProtoJSON"));
    assert!(!json.contains("\"salt\""));
    assert!(json.contains("\"outputLength\":17"));
    let roundtrip: CryptoHkdfNativeDeriveRequest =
        serde_json::from_str(&json).expect("ProtoJSON roundtrip");
    check_inputs(&roundtrip, None);

    wire = request(Some(&[]));
    let encoded = Zeroizing::new(wire.encode_to_vec());
    assert_eq!(*encoded, hex!("0a0e0a020864120200ff1a00220200201011"));
    let mut decoded = CryptoHkdfNativeDeriveRequest::default();
    decoded
        .merge_from_slice(&encoded)
        .expect("present-empty wire answer");
    check_inputs(&decoded, Some(&[]));
    let json = Zeroizing::new(serde_json::to_string(&wire).expect("ProtoJSON"));
    assert!(json.contains("\"salt\":\"\""));
    let roundtrip: CryptoHkdfNativeDeriveRequest =
        serde_json::from_str(&json).expect("ProtoJSON roundtrip");
    check_inputs(&roundtrip, Some(&[]));

    let binary = request(Some(&[0xff, 0, 0x20]));
    let encoded = Zeroizing::new(binary.encode_to_vec());
    let mut decoded = CryptoHkdfNativeDeriveRequest::default();
    decoded
        .merge_from_slice(&encoded)
        .expect("binary wire roundtrip");
    check_inputs(&decoded, Some(&[0xff, 0, 0x20]));
    let json = Zeroizing::new(serde_json::to_string(&binary).expect("binary ProtoJSON"));
    let roundtrip: CryptoHkdfNativeDeriveRequest =
        serde_json::from_str(&json).expect("binary JSON roundtrip");
    check_inputs(&roundtrip, Some(&[0xff, 0, 0x20]));
}

fn check_inputs(wire: &CryptoHkdfNativeDeriveRequest, salt: Option<&[u8]>) {
    let native = HkdfNativeDeriveInputs::<17>::try_from(wire).expect("native inputs");
    assert_eq!(native.as_request().suite, HkdfSuite::Sha2_256);
    assert_eq!(native.as_request().ikm.as_bytes(), &[0, 0xff]);
    assert_eq!(native.as_request().salt.map(|salt| salt.as_bytes()), salt);
    assert_eq!(native.as_request().info.as_bytes(), &[0, 0x20]);
    let returned =
        CryptoHkdfDeriveInputs::try_from(&native.as_request()).expect("native input roundtrip");
    assert_eq!(returned.salt.as_deref(), salt);
    assert_eq!(returned.info, [0, 0x20]);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn zero_unknown_and_modified_schema_values_fail_closed() {
    let outer = request(None);
    assert_unknown_wire(&outer, &[0xa0, 0x06, 0x01]);

    let inner = inputs(None);
    assert_unknown_wire(&inner, &[0xa0, 0x06, 0x01]);
    let mut absent = inputs(None);
    absent.suite = MessageField::none();
    assert_eq!(
        adapt(absent),
        Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );

    for hash in [0, -1, 1, i32::MAX] {
        let mut inner = inputs(None);
        inner.suite = MessageField::some(CryptoHkdfSuiteIdentifier {
            hash: EnumValue::from(hash),
        });
        assert_eq!(
            adapt(inner),
            Some(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
        );
    }
    let mut wrong_suite = inputs(None);
    wrong_suite.suite = MessageField::some(CryptoHkdfSuiteIdentifier {
        hash: HashAlgorithm::HASH_ALGORITHM_SHA2_512.into(),
    });
    assert_eq!(
        adapt(wrong_suite),
        Some(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    );
    let suite = CryptoHkdfSuiteIdentifier::from(HkdfSuite::Sha2_256);
    let mut modified_child = suite.encode_to_vec();
    modified_child.extend_from_slice(&[0xa0, 0x06, 0x01]);
    let mut modified_suite = inputs(None);
    modified_suite.suite = MessageField::some(suite);
    let mut modified = modified_suite.encode_to_vec();
    // The duplicate child retains protobuf merge semantics but the unknown
    // modifier must fail admission before any operation uses the message.
    buffa::encoding::encode_varint((1u64 << 3) | 2, &mut modified);
    buffa::encoding::encode_varint(
        u64::try_from(modified_child.len()).unwrap_or(u64::MAX),
        &mut modified,
    );
    modified.extend_from_slice(&modified_child);
    assert!(crypto_proto::wire::decode_protobuf::<CryptoHkdfDeriveInputs>(&modified).is_err());
}

fn adapt(inputs: CryptoHkdfDeriveInputs) -> Option<CryptoError> {
    let wire = CryptoHkdfNativeDeriveRequest {
        inputs: MessageField::some(inputs),
        output_length: 17,
    };
    HkdfNativeDeriveInputs::<17>::try_from(&wire).err()
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn protojson_preserves_u32_length_domain_and_null_salt() {
    let wire: CryptoHkdfNativeDeriveRequest = serde_json::from_str(
        r#"{"inputs":{"suite":{"hash":"HASH_ALGORITHM_SHA2_256"},"inputKeyMaterial":"AP8=","salt":null,"info":"ACA="},"outputLength":17}"#
    ).expect("exact binary ProtoJSON");
    check_inputs(&wire, None);
    let max: CryptoHkdfNativeDeriveRequest =
        serde_json::from_str(r#"{"outputLength":4294967295}"#).expect("u32 maximum");
    assert_eq!(max.output_length, u32::MAX);
    let default: CryptoHkdfNativeDeriveRequest =
        serde_json::from_str(r#"{"outputLength":null}"#).expect("null scalar default");
    assert_eq!(default.output_length, 0);
    for invalid in [
        r#"{"outputLength":-1}"#,
        r#"{"outputLength":4294967296}"#,
        r#"{"outputLength":1.5}"#,
        r#"{"inputs":{"inputKeyMaterial":"AP8=","unexpected":true},"outputLength":17}"#,
        r#"{"outputLength":17,"unexpected":true}"#,
    ] {
        let error = serde_json::from_str::<CryptoHkdfNativeDeriveRequest>(invalid)
            .expect_err("invalid ProtoJSON");
        assert_eq!(error.classify(), serde_json::error::Category::Data);
        assert!(!error.to_string().contains("AP8="));
    }
}

fn request(salt: Option<&[u8]>) -> CryptoHkdfNativeDeriveRequest {
    CryptoHkdfNativeDeriveRequest {
        inputs: MessageField::some(inputs(salt)),
        output_length: 17,
    }
}

fn inputs(salt: Option<&[u8]>) -> CryptoHkdfDeriveInputs {
    CryptoHkdfDeriveInputs {
        suite: MessageField::some(CryptoHkdfSuiteIdentifier::from(HkdfSuite::Sha2_256)),
        input_key_material: vec![0, 0xff].into(),
        salt: salt.map(|value| value.to_vec().into()),
        info: vec![0, 0x20].into(),
    }
}

fn assert_unknown_wire<M: buffa::Message>(message: &M, modifier: &[u8]) {
    let mut wire = message.encode_to_vec();
    wire.extend_from_slice(modifier);
    assert!(matches!(crypto_proto::wire::decode_protobuf::<M>(&wire),
        Err(error) if error == crypto_proto::wire::CryptoWireError::malformed_protobuf()));
}
