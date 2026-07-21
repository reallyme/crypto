// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Generated operation-response coverage for every BIP-340 public operation shape.

#![cfg(all(feature = "operation-response", feature = "secp256k1"))]
#![allow(clippy::expect_used)]

use buffa::{EnumValue, Message, MessageField};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as ProtoAlgorithmBranch,
    __buffa::oneof::crypto_error::Error as CryptoErrorBranch,
    __buffa::oneof::crypto_operation_request::Operation as CryptoOperation,
    __buffa::oneof::crypto_operation_response::Outcome as CryptoOperationOutcome,
    __buffa::oneof::crypto_operation_result::Result as CryptoOperationResultBranch,
    CryptoAlgorithmIdentifier, CryptoBip340SchnorrSignRequest, CryptoErrorReason,
    CryptoOperationRequest, CryptoOperationResponse, CryptoSignatureDeriveKeyPairRequest,
    CryptoSignatureGenerateKeyPairRequest, CryptoSignatureSignRequest,
    CryptoSignatureVerifyRequest, CryptoVerificationStatus, SignatureAlgorithm,
};
use crypto_proto::operation_response_wire::decode_operation_response;

const SECRET_KEY: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3,
];
const MESSAGE32: [u8; 32] = [0; 32];
const AUX_RAND32: [u8; 32] = [0; 32];
const PUBLIC_KEY: [u8; 32] = [
    0xf9, 0x30, 0x8a, 0x01, 0x92, 0x58, 0xc3, 0x10, 0x49, 0x34, 0x4f, 0x85, 0xf8, 0x9d, 0x52, 0x29,
    0xb5, 0x31, 0xc8, 0x45, 0x83, 0x6f, 0x99, 0xb0, 0x86, 0x01, 0xf1, 0x13, 0xbc, 0xe0, 0x36, 0xf9,
];
const SIGNATURE: [u8; 64] = [
    0xe9, 0x07, 0x83, 0x1f, 0x80, 0x84, 0x8d, 0x10, 0x69, 0xa5, 0x37, 0x1b, 0x40, 0x24, 0x10, 0x36,
    0x4b, 0xdf, 0x1c, 0x5f, 0x83, 0x07, 0xb0, 0x08, 0x4c, 0x55, 0xf1, 0xce, 0x2d, 0xca, 0x82, 0x15,
    0x25, 0xf6, 0x6a, 0x4a, 0x85, 0xea, 0x8b, 0x71, 0xe4, 0x82, 0xa7, 0x4f, 0x38, 0x2d, 0x2c, 0xe5,
    0xeb, 0xee, 0xe8, 0xfd, 0xb2, 0x17, 0x2f, 0x47, 0x7d, 0xf4, 0x90, 0x0d, 0x31, 0x05, 0x36, 0xc0,
];

#[test]
fn operation_response_exposes_bip340_keygen_derive_sign_and_verify_results() {
    let generated = result_branch(CryptoOperation::SignatureGenerateKeyPair(Box::new(
        CryptoSignatureGenerateKeyPairRequest {
            algorithm: MessageField::some(bip340_identifier()),
            __buffa_unknown_fields: Default::default(),
        },
    )))
    .expect("key generation returns a result branch");
    assert!(matches!(
        generated,
        CryptoOperationResultBranch::SignatureGenerateKeyPair(ref key_pair)
            if key_pair.public_key.len() == 32 && key_pair.secret_key.len() == 32
    ));

    let derived = result_branch(CryptoOperation::SignatureDeriveKeyPair(Box::new(
        CryptoSignatureDeriveKeyPairRequest {
            algorithm: MessageField::some(bip340_identifier()),
            secret_key: SECRET_KEY.to_vec(),
            __buffa_unknown_fields: Default::default(),
        },
    )))
    .expect("key derivation returns a result branch");
    assert!(matches!(
        derived,
        CryptoOperationResultBranch::SignatureDeriveKeyPair(ref key_pair)
            if key_pair.public_key == PUBLIC_KEY && key_pair.secret_key == SECRET_KEY
    ));

    let signed = result_branch(CryptoOperation::Bip340SchnorrSign(Box::new(
        CryptoBip340SchnorrSignRequest {
            message32: MESSAGE32.to_vec(),
            secret_key: SECRET_KEY.to_vec(),
            aux_rand32: AUX_RAND32.to_vec(),
            __buffa_unknown_fields: Default::default(),
        },
    )))
    .expect("signing returns a result branch");
    assert!(matches!(
        signed,
        CryptoOperationResultBranch::Bip340SchnorrSign(ref result)
            if result.signature == SIGNATURE
    ));

    let verified = result_branch(CryptoOperation::SignatureVerify(Box::new(
        CryptoSignatureVerifyRequest {
            algorithm: MessageField::some(bip340_identifier()),
            signature: SIGNATURE.to_vec(),
            message: MESSAGE32.to_vec(),
            public_key: PUBLIC_KEY.to_vec(),
            __buffa_unknown_fields: Default::default(),
        },
    )))
    .expect("verification returns a result branch");
    assert!(matches!(
        verified,
        CryptoOperationResultBranch::SignatureVerify(ref result)
            if result.status.as_known()
                == Some(CryptoVerificationStatus::CRYPTO_VERIFICATION_STATUS_VALID)
    ));
}

#[test]
fn operation_response_reports_bip340_mismatch_and_malformed_inputs_without_error_text() {
    let mut tampered = SIGNATURE;
    tampered[0] ^= 1;
    let mismatch = result_branch(CryptoOperation::SignatureVerify(Box::new(
        CryptoSignatureVerifyRequest {
            algorithm: MessageField::some(bip340_identifier()),
            signature: tampered.to_vec(),
            message: MESSAGE32.to_vec(),
            public_key: PUBLIC_KEY.to_vec(),
            __buffa_unknown_fields: Default::default(),
        },
    )))
    .expect("verification mismatch returns a result branch");
    assert!(matches!(
        mismatch,
        CryptoOperationResultBranch::SignatureVerify(ref result)
            if result.status.as_known()
                == Some(CryptoVerificationStatus::CRYPTO_VERIFICATION_STATUS_INVALID)
                && result.error.as_option().is_none()
    ));

    assert_error_reason(
        CryptoOperation::Bip340SchnorrSign(Box::new(CryptoBip340SchnorrSignRequest {
            message32: MESSAGE32[1..].to_vec(),
            secret_key: SECRET_KEY.to_vec(),
            aux_rand32: AUX_RAND32.to_vec(),
            __buffa_unknown_fields: Default::default(),
        })),
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH,
    );
    assert_error_reason(
        CryptoOperation::SignatureDeriveKeyPair(Box::new(CryptoSignatureDeriveKeyPairRequest {
            algorithm: MessageField::some(bip340_identifier()),
            secret_key: vec![0; 32],
            __buffa_unknown_fields: Default::default(),
        })),
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
    );
    assert_error_reason(
        CryptoOperation::SignatureSign(Box::new(CryptoSignatureSignRequest {
            algorithm: MessageField::some(bip340_identifier()),
            message: MESSAGE32.to_vec(),
            secret_key: SECRET_KEY.to_vec(),
            __buffa_unknown_fields: Default::default(),
        })),
        CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM,
    );
}

fn result_branch(operation: CryptoOperation) -> Option<CryptoOperationResultBranch> {
    let response = process_response(operation);
    match response.outcome {
        Some(CryptoOperationOutcome::Result(result)) => result.result,
        _ => None,
    }
}

fn assert_error_reason(operation: CryptoOperation, expected: CryptoErrorReason) {
    assert_eq!(error_reason(operation), Some(expected));
}

fn error_reason(operation: CryptoOperation) -> Option<CryptoErrorReason> {
    let response = process_response(operation);
    match response.outcome {
        Some(CryptoOperationOutcome::Error(error)) => match error.error {
            Some(CryptoErrorBranch::Primitive(error)) => error.reason.as_known(),
            Some(CryptoErrorBranch::Provider(error)) => error.reason.as_known(),
            Some(CryptoErrorBranch::Backend(error)) => error.reason.as_known(),
            None => None,
        },
        _ => None,
    }
}

fn process_response(operation: CryptoOperation) -> CryptoOperationResponse {
    let request = CryptoOperationRequest {
        operation: Some(operation),
        __buffa_unknown_fields: Default::default(),
    };
    let output = reallyme_crypto::operation_contract::process_operation_response(
        request.encode_to_vec().as_slice(),
    );
    decode_operation_response(output.as_slice()).expect("operation response decodes")
}

fn bip340_identifier() -> CryptoAlgorithmIdentifier {
    CryptoAlgorithmIdentifier {
        algorithm: Some(ProtoAlgorithmBranch::Signature(EnumValue::from(
            SignatureAlgorithm::SIGNATURE_ALGORITHM_BIP340_SCHNORR_SECP256K1_SHA256,
        ))),
        __buffa_unknown_fields: Default::default(),
    }
}
