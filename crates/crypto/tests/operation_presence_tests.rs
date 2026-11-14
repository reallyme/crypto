// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Semantic coverage for published protobuf field-presence conventions.

#![cfg(all(
    feature = "operation-response",
    feature = "sha2",
    feature = "hkdf",
    any(feature = "native", feature = "wasm")
))]
#![allow(clippy::expect_used, clippy::panic)]
#![allow(missing_docs)]

use buffa::{EnumValue, Message, MessageField};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm, __buffa::oneof::crypto_error::Error,
    __buffa::oneof::crypto_operation_response::Outcome,
    __buffa::oneof::crypto_operation_result::Result as OperationResult, CryptoAlgorithmIdentifier,
    CryptoErrorReason, CryptoHkdfDeriveRequest, CryptoOperationResponse, KdfAlgorithm,
};
use reallyme_crypto::operation_contract::{
    process_operation_response_json_output, process_operation_response_output,
};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn absent_and_empty_hash_inputs_produce_the_same_sha256_known_answer() {
    // Hash is operation 1; its algorithm message selects hash field 6 with
    // SHA2-256 = 100. The second wire form explicitly encodes empty input.
    let expected = hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        .expect("fixed SHA-256 empty-input answer");
    for binary in [
        [0x0a, 4, 0x0a, 2, 0x30, 100].as_slice(),
        [0x0a, 6, 0x0a, 2, 0x30, 100, 0x12, 0].as_slice(),
    ] {
        let response = process_operation_response_output(binary);
        assert_hash(&response, &expected);
    }
    for json in [
        br#"{"hash":{"algorithm":{"hash":"HASH_ALGORITHM_SHA2_256"}}}"#.as_slice(),
        br#"{"hash":{"algorithm":{"hash":"HASH_ALGORITHM_SHA2_256"},"input":""}}"#.as_slice(),
        br#"{"hash":{"algorithm":{"hash":"HASH_ALGORITHM_SHA2_256"},"input":null}}"#.as_slice(),
    ] {
        let response = process_operation_response_json_output(json);
        assert_hash(&response, &expected);
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn missing_empty_and_unspecified_choices_fail_closed_in_binary_and_json() {
    for (binary, json, reason) in [
        (
            [].as_slice(),
            br#"{}"#.as_slice(),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MISSING_OPERATION,
        ),
        (
            [0x0a, 0].as_slice(),
            br#"{"hash":{}}"#.as_slice(),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER,
        ),
        (
            [0x0a, 2, 0x0a, 0].as_slice(),
            br#"{"hash":{"algorithm":{}}}"#.as_slice(),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER,
        ),
        (
            [0x0a, 4, 0x0a, 2, 0x30, 0].as_slice(),
            br#"{"hash":{"algorithm":{"hash":"HASH_ALGORITHM_UNSPECIFIED"}}}"#.as_slice(),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM,
        ),
    ] {
        assert_error(&process_operation_response_output(binary), reason);
        assert_error(&process_operation_response_json_output(json), reason);
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn hkdf_omitted_and_empty_salt_info_match_rfc5869_case_3() {
    let request = hkdf_request(Vec::new());
    let mut body = request.encode_to_vec();
    let omitted = process_operation_response_output(&hkdf_operation_wire(&body));
    // Salt is field 3; info is field 4. Exercise the explicit empty wire form
    // directly, because re-encoding the generated message omits both fields.
    body.extend_from_slice(&[0x1a, 0, 0x22, 0]);
    let explicit = process_operation_response_output(&hkdf_operation_wire(&body));
    let expected = hex::decode("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d")
        .expect("first 32 bytes of RFC 5869 A.3");
    assert_hkdf(&omitted, &expected);
    assert_hkdf(&explicit, &expected);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn hkdf_present_binary_context_keeps_trailing_zero_and_non_utf8_bytes() {
    let info = [0xff, 0x00, 0x80, 0x00];
    let request = hkdf_request(info.to_vec());
    let response =
        process_operation_response_output(&hkdf_operation_wire(&request.encode_to_vec()));
    let ikm = reallyme_crypto::hkdf::HkdfInputKeyMaterial::from_slice(&[0x0b; 22]);
    let context = reallyme_crypto::hkdf::HkdfInfo::from_slice(&info);
    let expected = reallyme_crypto::hkdf::derive::<32>(&reallyme_crypto::hkdf::DeriveRequest {
        suite: reallyme_crypto::hkdf::HkdfSuite::Sha2_256,
        ikm: &ikm,
        salt: None,
        info: &context,
    })
    .expect("direct HKDF accepts exact binary context");
    assert_hkdf(&response, expected.as_bytes());
    for changed in [Vec::new(), info[..3].to_vec()] {
        let changed = hkdf_request(changed);
        let changed_response =
            process_operation_response_output(&hkdf_operation_wire(&changed.encode_to_vec()));
        assert_ne!(response, changed_response);
    }
}

fn hkdf_request(info: Vec<u8>) -> CryptoHkdfDeriveRequest {
    CryptoHkdfDeriveRequest {
        algorithm: MessageField::some(CryptoAlgorithmIdentifier {
            algorithm: Some(Algorithm::Kdf(EnumValue::from(
                KdfAlgorithm::KDF_ALGORITHM_HKDF_SHA256,
            ))),
        }),
        input_key_material: vec![0x0b; 22].into(),
        salt: Vec::new().into(),
        info: info.into(),
        output_length: 32,
    }
}

fn hkdf_operation_wire(body: &[u8]) -> Vec<u8> {
    // Operation field 40 has a two-byte tag. These bounded test requests fit
    // a single-byte payload length, preserving any explicit empty fields.
    let mut wire = vec![
        0xc2,
        0x02,
        u8::try_from(body.len()).expect("bounded fixture length"),
    ];
    wire.extend_from_slice(body);
    wire
}

fn assert_hash(response: &CryptoOperationResponse, expected: &[u8]) {
    let Some(Outcome::Result(result)) = &response.outcome else {
        panic!("hash response must contain a result");
    };
    let Some(OperationResult::Hash(hash)) = &result.result else {
        panic!("hash response must select the hash result");
    };
    assert_eq!(hash.digest, expected);
}

fn assert_hkdf(response: &CryptoOperationResponse, expected: &[u8]) {
    let Some(Outcome::Result(result)) = &response.outcome else {
        panic!("HKDF response must contain a result");
    };
    let Some(OperationResult::HkdfDerive(hkdf)) = &result.result else {
        panic!("HKDF response must select the HKDF result");
    };
    assert_eq!(hkdf.output_key_material, expected);
}

fn assert_error(response: &CryptoOperationResponse, reason: CryptoErrorReason) {
    let Some(Outcome::Error(error)) = &response.outcome else {
        panic!("incomplete request must fail closed");
    };
    let actual = match &error.error {
        Some(Error::Primitive(error)) => error.reason.as_known(),
        Some(Error::Provider(error)) => error.reason.as_known(),
        _ => panic!("presence validation must retain its typed error branch"),
    };
    assert_eq!(actual, Some(reason));
    assert_eq!(
        matches!(&error.error, Some(Error::Provider(_))),
        reason == CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM,
    );
}
