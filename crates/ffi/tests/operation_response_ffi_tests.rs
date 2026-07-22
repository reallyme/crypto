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
    __buffa::oneof::crypto_error::Error as CryptoErrorBranch,
    __buffa::oneof::crypto_operation_request::Operation as CryptoOperation,
    __buffa::oneof::crypto_operation_response::Outcome as CryptoOperationOutcome,
    __buffa::oneof::crypto_operation_result::Result as CryptoOperationResultBranch,
    CryptoAlgorithmIdentifier, CryptoErrorReason, CryptoHashRequest,
    CryptoHpkeDeriveKeyPairRequest, CryptoHpkeOpenRequest, CryptoHpkeReceiverExportRequest,
    CryptoHpkeSealRequest, CryptoHpkeSenderExportRequest, CryptoOperationRequest,
    CryptoOperationResponse, HashAlgorithm, HpkeAeadId, HpkeKdfId, HpkeKemId, HpkeSuiteIdentifier,
};
use crypto_proto::operation_response_wire::decode_operation_response;
use crypto_proto::operation_response_wire::MAX_CRYPTO_OPERATION_RESPONSE_BYTES;
use zeroize::Zeroizing;

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

#[test]
fn ffi_operation_contract_executes_post_quantum_hpke_suite_matrix() {
    for case in hpke_suite_cases() {
        let algorithm = hpke_identifier(case);
        assert_ffi_error_reason(
            CryptoOperation::HpkeDeriveKeyPair(Box::new(CryptoHpkeDeriveKeyPairRequest {
                algorithm: MessageField::some(algorithm.clone()),
                input_key_material: vec![0x31; 31],
                __buffa_unknown_fields: Default::default(),
            })),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH,
        );
        let CryptoOperationResultBranch::HpkeDeriveKeyPair(key_pair) = ffi_result(
            CryptoOperation::HpkeDeriveKeyPair(Box::new(CryptoHpkeDeriveKeyPairRequest {
                algorithm: MessageField::some(algorithm.clone()),
                input_key_material: b"arbitrary-length FFI OpenMLS secret".to_vec(),
                __buffa_unknown_fields: Default::default(),
            })),
        ) else {
            panic!("FFI HPKE derive-keypair returned the wrong result branch");
        };

        let CryptoOperationResultBranch::HpkeSeal(sealed) =
            ffi_result(CryptoOperation::HpkeSeal(Box::new(CryptoHpkeSealRequest {
                algorithm: MessageField::some(algorithm.clone()),
                recipient_public_key: key_pair.public_key.clone(),
                info: b"FFI HPKE suite matrix".to_vec(),
                aad: b"FFI HPKE AAD".to_vec(),
                plaintext: b"FFI HPKE plaintext".to_vec(),
                __buffa_unknown_fields: Default::default(),
            })))
        else {
            panic!("FFI HPKE seal returned the wrong result branch");
        };
        let CryptoOperationResultBranch::HpkeOpen(opened) =
            ffi_result(CryptoOperation::HpkeOpen(Box::new(CryptoHpkeOpenRequest {
                algorithm: MessageField::some(algorithm.clone()),
                recipient_secret_key: key_pair.secret_key.clone(),
                encapsulated_key: sealed.encapsulated_key.clone(),
                info: b"FFI HPKE suite matrix".to_vec(),
                aad: b"FFI HPKE AAD".to_vec(),
                ciphertext: sealed.ciphertext.clone(),
                __buffa_unknown_fields: Default::default(),
            })))
        else {
            panic!("FFI HPKE open returned the wrong result branch");
        };
        assert_eq!(opened.plaintext, b"FFI HPKE plaintext");

        let CryptoOperationResultBranch::HpkeSenderExport(sender) = ffi_result(
            CryptoOperation::HpkeSenderExport(Box::new(CryptoHpkeSenderExportRequest {
                algorithm: MessageField::some(algorithm.clone()),
                recipient_public_key: key_pair.public_key.clone(),
                info: b"FFI HPKE suite matrix".to_vec(),
                exporter_context: b"FFI exporter context".to_vec(),
                output_length: 48,
                __buffa_unknown_fields: Default::default(),
            })),
        ) else {
            panic!("FFI HPKE sender export returned the wrong result branch");
        };
        let CryptoOperationResultBranch::HpkeReceiverExport(receiver) = ffi_result(
            CryptoOperation::HpkeReceiverExport(Box::new(CryptoHpkeReceiverExportRequest {
                algorithm: MessageField::some(algorithm.clone()),
                recipient_secret_key: key_pair.secret_key.clone(),
                encapsulated_key: sender.encapsulated_key.clone(),
                info: b"FFI HPKE suite matrix".to_vec(),
                exporter_context: b"FFI exporter context".to_vec(),
                output_length: 48,
                __buffa_unknown_fields: Default::default(),
            })),
        ) else {
            panic!("FFI HPKE receiver export returned the wrong result branch");
        };
        assert_eq!(sender.exporter_secret, receiver.exporter_secret);

        assert_ffi_error_reason(
            CryptoOperation::HpkeSeal(Box::new(CryptoHpkeSealRequest {
                algorithm: MessageField::some(algorithm.clone()),
                recipient_public_key: vec![0_u8; 1],
                info: Vec::new(),
                aad: Vec::new(),
                plaintext: b"payload".to_vec(),
                __buffa_unknown_fields: Default::default(),
            })),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PUBLIC_KEY,
        );
        let mut tampered = sealed.ciphertext.clone();
        if let Some(first) = tampered.first_mut() {
            *first ^= 0x40;
        }
        assert_ffi_error_reason(
            CryptoOperation::HpkeOpen(Box::new(CryptoHpkeOpenRequest {
                algorithm: MessageField::some(algorithm.clone()),
                recipient_secret_key: key_pair.secret_key.clone(),
                encapsulated_key: sealed.encapsulated_key.clone(),
                info: b"FFI HPKE suite matrix".to_vec(),
                aad: b"FFI HPKE AAD".to_vec(),
                ciphertext: tampered,
                __buffa_unknown_fields: Default::default(),
            })),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED,
        );
        assert_ffi_error_reason(
            CryptoOperation::HpkeSenderExport(Box::new(CryptoHpkeSenderExportRequest {
                algorithm: MessageField::some(algorithm),
                recipient_public_key: key_pair.public_key.clone(),
                info: Vec::new(),
                exporter_context: Vec::new(),
                output_length: u32::MAX,
                __buffa_unknown_fields: Default::default(),
            })),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH,
        );
    }
}

fn ffi_result(operation: CryptoOperation) -> CryptoOperationResultBranch {
    let response = ffi_response(operation);
    let Some(CryptoOperationOutcome::Result(result)) = response.outcome else {
        panic!("FFI operation response returned an error");
    };
    let Some(result) = result.result else {
        panic!("FFI operation response returned an empty result");
    };
    result
}

fn assert_ffi_error_reason(operation: CryptoOperation, expected: CryptoErrorReason) {
    let reason = match ffi_response(operation).outcome {
        Some(CryptoOperationOutcome::Error(error)) => match error.error {
            Some(CryptoErrorBranch::Primitive(error)) => error.reason.as_known(),
            Some(CryptoErrorBranch::Provider(error)) => error.reason.as_known(),
            Some(CryptoErrorBranch::Backend(error)) => error.reason.as_known(),
            None => None,
        },
        _ => None,
    };
    assert_eq!(reason, Some(expected));
}

fn ffi_response(operation: CryptoOperation) -> CryptoOperationResponse {
    let request = CryptoOperationRequest {
        operation: Some(operation),
        __buffa_unknown_fields: Default::default(),
    };
    let request_bytes = Zeroizing::new(request.encode_to_vec());
    let mut output = Zeroizing::new(vec![0_u8; MAX_CRYPTO_OPERATION_RESPONSE_BYTES]);
    let mut output_len = 0_usize;

    // SAFETY: The input and output allocations are live, non-overlapping, and
    // sized by their exact Rust slice lengths. `output_len` is aligned writable
    // storage for the duration of the call.
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
    let Ok(response) = decode_operation_response(&output[..output_len]) else {
        panic!("FFI operation response did not decode");
    };
    response
}

#[derive(Clone, Copy)]
struct HpkeSuiteCase {
    kem: HpkeKemId,
    kdf: HpkeKdfId,
    aead: HpkeAeadId,
}

fn hpke_suite_cases() -> [HpkeSuiteCase; 5] {
    [
        HpkeSuiteCase {
            kem: HpkeKemId::HPKE_KEM_ID_ML_KEM_1024,
            kdf: HpkeKdfId::HPKE_KDF_ID_HKDF_SHA384,
            aead: HpkeAeadId::HPKE_AEAD_ID_AES_256_GCM,
        },
        HpkeSuiteCase {
            kem: HpkeKemId::HPKE_KEM_ID_ML_KEM_1024_P384,
            kdf: HpkeKdfId::HPKE_KDF_ID_HKDF_SHA384,
            aead: HpkeAeadId::HPKE_AEAD_ID_AES_256_GCM,
        },
        HpkeSuiteCase {
            kem: HpkeKemId::HPKE_KEM_ID_ML_KEM_1024,
            kdf: HpkeKdfId::HPKE_KDF_ID_SHAKE256,
            aead: HpkeAeadId::HPKE_AEAD_ID_AES_256_GCM,
        },
        HpkeSuiteCase {
            kem: HpkeKemId::HPKE_KEM_ID_ML_KEM_1024_P384,
            kdf: HpkeKdfId::HPKE_KDF_ID_SHAKE256,
            aead: HpkeAeadId::HPKE_AEAD_ID_AES_256_GCM,
        },
        HpkeSuiteCase {
            kem: HpkeKemId::HPKE_KEM_ID_X_WING,
            kdf: HpkeKdfId::HPKE_KDF_ID_HKDF_SHA256,
            aead: HpkeAeadId::HPKE_AEAD_ID_CHACHA20_POLY1305,
        },
    ]
}

fn hpke_identifier(case: HpkeSuiteCase) -> CryptoAlgorithmIdentifier {
    CryptoAlgorithmIdentifier {
        algorithm: Some(ProtoAlgorithmBranch::HpkeSuite(Box::new(
            HpkeSuiteIdentifier {
                kem: EnumValue::from(case.kem),
                kdf: EnumValue::from(case.kdf),
                aead: EnumValue::from(case.aead),
                __buffa_unknown_fields: Default::default(),
            },
        ))),
        __buffa_unknown_fields: Default::default(),
    }
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
