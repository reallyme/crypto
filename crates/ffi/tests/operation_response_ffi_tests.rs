// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! FFI tests for the generated operation response boundary.

#![allow(unsafe_code)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

use buffa::{EnumValue, Message, MessageField};
use crypto_ffi::operation_response;
use crypto_ffi::status;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as ProtoAlgorithmBranch,
    __buffa::oneof::crypto_operation_request::Operation as CryptoOperation,
    __buffa::oneof::crypto_operation_response::Outcome as CryptoOperationOutcome,
    __buffa::oneof::crypto_operation_result::Result as CryptoOperationResultBranch,
    CryptoAlgorithmIdentifier, CryptoHashRequest, CryptoOperationRequest, HashAlgorithm,
};
use crypto_proto::operation_response_wire::decode_operation_response;
use crypto_proto::operation_response_wire::MAX_CRYPTO_OPERATION_RESPONSE_BYTES;

#[test]
fn ffi_header_exposes_generated_operation_response_boundary() {
    let header = include_str!("../abi/reallyme_crypto_ffi.h");

    assert!(header.contains("#define RM_CRYPTO_OPERATION_RESPONSE_MAX_LEN       1048608"));
    assert!(header.contains("rm_crypto_process_operation_response"));
    assert!(header.contains("rm_crypto_process_operation_response_json"));
}

#[test]
fn ffi_header_operation_response_cap_matches_canonical_rust_constant() {
    assert_eq!(MAX_CRYPTO_OPERATION_RESPONSE_BYTES, 1_048_608);
    let header = include_str!("../abi/reallyme_crypto_ffi.h");

    assert!(header.contains("#define RM_CRYPTO_OPERATION_RESPONSE_MAX_LEN       1048608"));
}

#[test]
fn ffi_process_operation_response_reports_required_length_for_short_output() {
    let request_bytes = hash_operation_request().encode_to_vec();
    let mut short_output = [0_u8; 1];
    let mut output_len = 0_usize;

    let result_status = unsafe {
        operation_response::rm_crypto_process_operation_response(
            request_bytes.as_ptr(),
            request_bytes.len(),
            short_output.as_mut_ptr(),
            short_output.len(),
            &mut output_len,
        )
    };

    assert_eq!(result_status, status::CRYPTO_BUFFER_TOO_SMALL);
    assert!(output_len > short_output.len());
}

#[test]
fn ffi_process_operation_response_json_reports_required_length_for_short_output() {
    let request_json =
        serde_json::to_vec(&hash_operation_request()).expect("generated ProtoJSON serializes");
    let mut short_output = [0_u8; 1];
    let mut output_len = 0_usize;

    let result_status = unsafe {
        operation_response::rm_crypto_process_operation_response_json(
            request_json.as_ptr(),
            request_json.len(),
            short_output.as_mut_ptr(),
            short_output.len(),
            &mut output_len,
        )
    };

    assert_eq!(result_status, status::CRYPTO_BUFFER_TOO_SMALL);
    assert!(output_len > short_output.len());
}

#[test]
fn ffi_process_operation_response_returns_generated_result() {
    let request_bytes = hash_operation_request().encode_to_vec();
    let mut output = [0_u8; 128];
    let mut output_len = 0_usize;

    // SAFETY: The input and output pointers reference live, non-overlapping
    // test-owned buffers, and `output_len` points to aligned writable storage.
    let result_status = unsafe {
        operation_response::rm_crypto_process_operation_response(
            request_bytes.as_ptr(),
            request_bytes.len(),
            output.as_mut_ptr(),
            output.len(),
            &mut output_len,
        )
    };

    assert_eq!(result_status, status::CRYPTO_OK);
    let response = decode_operation_response(&output[..output_len]).expect("response decodes");
    let Some(CryptoOperationOutcome::Result(result)) = response.outcome else {
        panic!("operation response did not contain a generated result");
    };
    let Some(CryptoOperationResultBranch::Hash(hash)) = result.result else {
        panic!("operation result did not contain the hash branch");
    };
    assert_eq!(hash.digest.len(), 32);
}

fn hash_operation_request() -> CryptoOperationRequest {
    CryptoOperationRequest {
        operation: Some(CryptoOperation::Hash(Box::new(CryptoHashRequest {
            algorithm: MessageField::some(CryptoAlgorithmIdentifier {
                algorithm: Some(ProtoAlgorithmBranch::Hash(EnumValue::from(
                    HashAlgorithm::HASH_ALGORITHM_SHA2_256,
                ))),
                __buffa_unknown_fields: Default::default(),
            }),
            input: b"abc".to_vec(),
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    }
}
