// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Generated operation-contract branch coverage for every HPKE route.

#![cfg(feature = "operation-response")]
#![allow(clippy::panic)]

use buffa::{EnumValue, Message, MessageField};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as ProtoAlgorithmBranch,
    __buffa::oneof::crypto_error::Error as CryptoErrorBranch,
    __buffa::oneof::crypto_operation_request::Operation as CryptoOperation,
    __buffa::oneof::crypto_operation_response::Outcome as CryptoOperationOutcome,
    __buffa::oneof::crypto_operation_result::Result as CryptoOperationResultBranch,
    CryptoAlgorithmIdentifier, CryptoErrorReason, CryptoHpkeDeriveKeyPairRequest,
    CryptoHpkeGenerateKeyPairRequest, CryptoHpkeOpenRequest, CryptoHpkePskOpenRequest,
    CryptoHpkePskSealRequest, CryptoHpkeReceiverExportRequest, CryptoHpkeSealRequest,
    CryptoHpkeSenderExportRequest, CryptoOperationRequest, CryptoOperationResponse, HpkeAeadId,
    HpkeKdfId, HpkeKemId, HpkeSuiteIdentifier,
};
use crypto_proto::operation_response_wire::decode_operation_response;

const INFO: &[u8] = b"operation-contract-hpke-v0.3";
const AAD: &[u8] = b"operation-contract-aad";
const PLAINTEXT: &[u8] = b"operation-contract plaintext";
const EXPORTER_CONTEXT: &[u8] = b"operation-contract exporter";
const PSK: &[u8] = &[0xa3; 32];
const PSK_ID: &[u8] = b"operation-contract-psk";

#[test]
fn primary_operation_contract_executes_all_hpke_branches() {
    let algorithm = suite_identifier();

    let CryptoOperationResultBranch::HpkeGenerateKeyPair(generated) = execute(
        CryptoOperation::HpkeGenerateKeyPair(Box::new(CryptoHpkeGenerateKeyPairRequest {
            algorithm: MessageField::some(algorithm.clone()),
            __buffa_unknown_fields: Default::default(),
        })),
    ) else {
        panic!("HPKE keygen returned the wrong operation-result branch");
    };
    assert_eq!(generated.public_key.len(), 65);
    assert_eq!(generated.secret_key.len(), 32);

    let CryptoOperationResultBranch::HpkeDeriveKeyPair(key_pair) = execute(
        CryptoOperation::HpkeDeriveKeyPair(Box::new(CryptoHpkeDeriveKeyPairRequest {
            algorithm: MessageField::some(algorithm.clone()),
            input_key_material: vec![0x4c; 32],
            __buffa_unknown_fields: Default::default(),
        })),
    ) else {
        panic!("HPKE derive-keypair returned the wrong operation-result branch");
    };

    let CryptoOperationResultBranch::HpkeSeal(sealed) =
        execute(CryptoOperation::HpkeSeal(Box::new(CryptoHpkeSealRequest {
            algorithm: MessageField::some(algorithm.clone()),
            recipient_public_key: key_pair.public_key.clone(),
            info: INFO.to_vec(),
            aad: AAD.to_vec(),
            plaintext: PLAINTEXT.to_vec(),
            __buffa_unknown_fields: Default::default(),
        })))
    else {
        panic!("HPKE seal returned the wrong operation-result branch");
    };
    let CryptoOperationResultBranch::HpkeOpen(opened) =
        execute(CryptoOperation::HpkeOpen(Box::new(CryptoHpkeOpenRequest {
            algorithm: MessageField::some(algorithm.clone()),
            recipient_secret_key: key_pair.secret_key.clone(),
            encapsulated_key: sealed.encapsulated_key.clone(),
            info: INFO.to_vec(),
            aad: AAD.to_vec(),
            ciphertext: sealed.ciphertext.clone(),
            __buffa_unknown_fields: Default::default(),
        })))
    else {
        panic!("HPKE open returned the wrong operation-result branch");
    };
    assert_eq!(opened.plaintext, PLAINTEXT);

    let CryptoOperationResultBranch::HpkeSenderExport(sender) = execute(
        CryptoOperation::HpkeSenderExport(Box::new(CryptoHpkeSenderExportRequest {
            algorithm: MessageField::some(algorithm.clone()),
            recipient_public_key: key_pair.public_key.clone(),
            info: INFO.to_vec(),
            exporter_context: EXPORTER_CONTEXT.to_vec(),
            output_length: 48,
            __buffa_unknown_fields: Default::default(),
        })),
    ) else {
        panic!("HPKE sender-export returned the wrong operation-result branch");
    };
    let CryptoOperationResultBranch::HpkeReceiverExport(receiver) = execute(
        CryptoOperation::HpkeReceiverExport(Box::new(CryptoHpkeReceiverExportRequest {
            algorithm: MessageField::some(algorithm.clone()),
            recipient_secret_key: key_pair.secret_key.clone(),
            encapsulated_key: sender.encapsulated_key.clone(),
            info: INFO.to_vec(),
            exporter_context: EXPORTER_CONTEXT.to_vec(),
            output_length: 48,
            __buffa_unknown_fields: Default::default(),
        })),
    ) else {
        panic!("HPKE receiver-export returned the wrong operation-result branch");
    };
    assert_eq!(sender.exporter_secret, receiver.exporter_secret);

    let CryptoOperationResultBranch::HpkePskSeal(psk_sealed) = execute(
        CryptoOperation::HpkePskSeal(Box::new(CryptoHpkePskSealRequest {
            algorithm: MessageField::some(algorithm.clone()),
            recipient_public_key: key_pair.public_key.clone(),
            info: INFO.to_vec(),
            aad: AAD.to_vec(),
            plaintext: PLAINTEXT.to_vec(),
            psk: PSK.to_vec(),
            psk_id: PSK_ID.to_vec(),
            __buffa_unknown_fields: Default::default(),
        })),
    ) else {
        panic!("HPKE PSK seal returned the wrong operation-result branch");
    };
    let CryptoOperationResultBranch::HpkePskOpen(psk_opened) = execute(
        CryptoOperation::HpkePskOpen(Box::new(CryptoHpkePskOpenRequest {
            algorithm: MessageField::some(algorithm),
            recipient_secret_key: key_pair.secret_key.clone(),
            encapsulated_key: psk_sealed.encapsulated_key.clone(),
            info: INFO.to_vec(),
            aad: AAD.to_vec(),
            ciphertext: psk_sealed.ciphertext.clone(),
            psk: PSK.to_vec(),
            psk_id: PSK_ID.to_vec(),
            __buffa_unknown_fields: Default::default(),
        })),
    ) else {
        panic!("HPKE PSK open returned the wrong operation-result branch");
    };
    assert_eq!(psk_opened.plaintext, PLAINTEXT);
}

#[test]
fn post_quantum_hpke_suites_execute_through_the_serialized_contract() {
    for case in post_quantum_suite_cases() {
        let algorithm = suite_identifier_for(case);
        assert_error_reason(
            CryptoOperation::HpkeDeriveKeyPair(Box::new(CryptoHpkeDeriveKeyPairRequest {
                algorithm: MessageField::some(algorithm.clone()),
                input_key_material: vec![0x31; 31],
                __buffa_unknown_fields: Default::default(),
            })),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH,
        );
        let CryptoOperationResultBranch::HpkeDeriveKeyPair(key_pair) = execute(
            CryptoOperation::HpkeDeriveKeyPair(Box::new(CryptoHpkeDeriveKeyPairRequest {
                algorithm: MessageField::some(algorithm.clone()),
                input_key_material: b"arbitrary-length protobuf OpenMLS secret".to_vec(),
                __buffa_unknown_fields: Default::default(),
            })),
        ) else {
            panic!("HPKE derive-keypair returned the wrong operation-result branch");
        };

        let CryptoOperationResultBranch::HpkeSeal(sealed) =
            execute(CryptoOperation::HpkeSeal(Box::new(CryptoHpkeSealRequest {
                algorithm: MessageField::some(algorithm.clone()),
                recipient_public_key: key_pair.public_key.clone(),
                info: INFO.to_vec(),
                aad: AAD.to_vec(),
                plaintext: PLAINTEXT.to_vec(),
                __buffa_unknown_fields: Default::default(),
            })))
        else {
            panic!("HPKE seal returned the wrong operation-result branch");
        };
        let CryptoOperationResultBranch::HpkeOpen(opened) =
            execute(CryptoOperation::HpkeOpen(Box::new(CryptoHpkeOpenRequest {
                algorithm: MessageField::some(algorithm.clone()),
                recipient_secret_key: key_pair.secret_key.clone(),
                encapsulated_key: sealed.encapsulated_key.clone(),
                info: INFO.to_vec(),
                aad: AAD.to_vec(),
                ciphertext: sealed.ciphertext.clone(),
                __buffa_unknown_fields: Default::default(),
            })))
        else {
            panic!("HPKE open returned the wrong operation-result branch");
        };
        assert_eq!(opened.plaintext, PLAINTEXT);

        let CryptoOperationResultBranch::HpkeSenderExport(sender) = execute(
            CryptoOperation::HpkeSenderExport(Box::new(CryptoHpkeSenderExportRequest {
                algorithm: MessageField::some(algorithm.clone()),
                recipient_public_key: key_pair.public_key.clone(),
                info: INFO.to_vec(),
                exporter_context: EXPORTER_CONTEXT.to_vec(),
                output_length: 48,
                __buffa_unknown_fields: Default::default(),
            })),
        ) else {
            panic!("HPKE sender export returned the wrong operation-result branch");
        };
        let CryptoOperationResultBranch::HpkeReceiverExport(receiver) = execute(
            CryptoOperation::HpkeReceiverExport(Box::new(CryptoHpkeReceiverExportRequest {
                algorithm: MessageField::some(algorithm.clone()),
                recipient_secret_key: key_pair.secret_key.clone(),
                encapsulated_key: sender.encapsulated_key.clone(),
                info: INFO.to_vec(),
                exporter_context: EXPORTER_CONTEXT.to_vec(),
                output_length: 48,
                __buffa_unknown_fields: Default::default(),
            })),
        ) else {
            panic!("HPKE receiver export returned the wrong operation-result branch");
        };
        assert_eq!(sender.exporter_secret, receiver.exporter_secret);

        assert_error_reason(
            CryptoOperation::HpkeSeal(Box::new(CryptoHpkeSealRequest {
                algorithm: MessageField::some(algorithm.clone()),
                recipient_public_key: vec![0_u8; 1],
                info: INFO.to_vec(),
                aad: AAD.to_vec(),
                plaintext: PLAINTEXT.to_vec(),
                __buffa_unknown_fields: Default::default(),
            })),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PUBLIC_KEY,
        );

        let mut tampered_ciphertext = sealed.ciphertext.clone();
        if let Some(first) = tampered_ciphertext.first_mut() {
            *first ^= 0x80;
        }
        assert_error_reason(
            CryptoOperation::HpkeOpen(Box::new(CryptoHpkeOpenRequest {
                algorithm: MessageField::some(algorithm.clone()),
                recipient_secret_key: key_pair.secret_key.clone(),
                encapsulated_key: sealed.encapsulated_key.clone(),
                info: INFO.to_vec(),
                aad: AAD.to_vec(),
                ciphertext: tampered_ciphertext,
                __buffa_unknown_fields: Default::default(),
            })),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED,
        );
        assert_error_reason(
            CryptoOperation::HpkeSenderExport(Box::new(CryptoHpkeSenderExportRequest {
                algorithm: MessageField::some(algorithm),
                recipient_public_key: key_pair.public_key.clone(),
                info: INFO.to_vec(),
                exporter_context: EXPORTER_CONTEXT.to_vec(),
                output_length: u32::MAX,
                __buffa_unknown_fields: Default::default(),
            })),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH,
        );
    }
}

fn execute(operation: CryptoOperation) -> CryptoOperationResultBranch {
    let response = process_response(operation);
    let Some(CryptoOperationOutcome::Result(result)) = response.outcome else {
        panic!("HPKE operation contract returned an error");
    };
    let Some(result) = result.result else {
        panic!("HPKE operation contract returned an empty result");
    };
    result
}

fn process_response(operation: CryptoOperation) -> CryptoOperationResponse {
    let request = CryptoOperationRequest {
        operation: Some(operation),
        __buffa_unknown_fields: Default::default(),
    };
    let response_bytes = reallyme_crypto::operation_contract::process_operation_response(
        request.encode_to_vec().as_slice(),
    );
    let Ok(response) = decode_operation_response(response_bytes.as_slice()) else {
        panic!("HPKE operation response did not decode");
    };
    response
}

fn assert_error_reason(operation: CryptoOperation, expected: CryptoErrorReason) {
    let reason = match process_response(operation).outcome {
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

fn suite_identifier() -> CryptoAlgorithmIdentifier {
    CryptoAlgorithmIdentifier {
        algorithm: Some(ProtoAlgorithmBranch::HpkeSuite(Box::new(
            HpkeSuiteIdentifier {
                kem: EnumValue::from(HpkeKemId::HPKE_KEM_ID_DHKEM_P256_HKDF_SHA256),
                kdf: EnumValue::from(HpkeKdfId::HPKE_KDF_ID_HKDF_SHA256),
                aead: EnumValue::from(HpkeAeadId::HPKE_AEAD_ID_AES_256_GCM),
                __buffa_unknown_fields: Default::default(),
            },
        ))),
        __buffa_unknown_fields: Default::default(),
    }
}

#[derive(Clone, Copy)]
struct HpkeSuiteCase {
    kem: HpkeKemId,
    kdf: HpkeKdfId,
    aead: HpkeAeadId,
}

fn post_quantum_suite_cases() -> [HpkeSuiteCase; 3] {
    [
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

fn suite_identifier_for(case: HpkeSuiteCase) -> CryptoAlgorithmIdentifier {
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
