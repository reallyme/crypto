// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Generated operation-contract branch coverage for every HPKE route.

#![cfg(feature = "operation-response")]
#![allow(clippy::panic)]

use buffa::{EnumValue, Message, MessageField};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as ProtoAlgorithmBranch,
    __buffa::oneof::crypto_operation_request::Operation as CryptoOperation,
    __buffa::oneof::crypto_operation_response::Outcome as CryptoOperationOutcome,
    __buffa::oneof::crypto_operation_result::Result as CryptoOperationResultBranch,
    CryptoAlgorithmIdentifier, CryptoHpkeDeriveKeyPairRequest, CryptoHpkeGenerateKeyPairRequest,
    CryptoHpkeOpenRequest, CryptoHpkePskOpenRequest, CryptoHpkePskSealRequest,
    CryptoHpkeReceiverExportRequest, CryptoHpkeSealRequest, CryptoHpkeSenderExportRequest,
    CryptoOperationRequest, HpkeAeadId, HpkeKdfId, HpkeKemId, HpkeSuiteIdentifier,
};

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

fn execute(operation: CryptoOperation) -> CryptoOperationResultBranch {
    let request = CryptoOperationRequest {
        operation: Some(operation),
        __buffa_unknown_fields: Default::default(),
    };
    let response = reallyme_crypto::operation_contract::process_operation_response_output(
        request.encode_to_vec().as_slice(),
    );
    let Some(CryptoOperationOutcome::Result(result)) = response.outcome else {
        panic!("HPKE operation contract returned an error");
    };
    let Some(result) = result.result else {
        panic!("HPKE operation contract returned an empty result");
    };
    result
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
