// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Generated operation-response coverage for raw and platform signatures.

#![cfg(all(feature = "ed25519", feature = "operation-response"))]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

use buffa::{EnumValue, Message, MessageField};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as ProtoAlgorithmBranch,
    __buffa::oneof::crypto_error::Error as CryptoErrorBranch,
    __buffa::oneof::crypto_operation_request::Operation as CryptoOperation,
    __buffa::oneof::crypto_operation_response::Outcome as CryptoOperationOutcome,
    __buffa::oneof::crypto_operation_result::Result as CryptoOperationResultBranch,
    CryptoAlgorithmIdentifier, CryptoErrorReason, CryptoOperationRequest, CryptoOperationResponse,
    CryptoSignatureDeriveKeyPairRequest, CryptoSignatureGenerateKeyPairRequest,
    CryptoSignatureSignRequest, CryptoSignatureVerifyRequest, CryptoVerificationStatus,
    SignatureAlgorithm,
};
use crypto_proto::operation_response_wire::decode_operation_response;

const MESSAGE: &[u8] = b"signature generated response";
const ED25519_SEED: [u8; 32] = [0x42; 32];

#[test]
fn operation_response_exposes_every_raw_signature_result_branch() {
    let (public_key, _) = crypto_ed25519::generate_ed25519_keypair_from_seed(&ED25519_SEED);
    let signature =
        crypto_ed25519::sign_ed25519(&ED25519_SEED, MESSAGE).expect("test vector signs");

    assert_result_branch(
        CryptoOperation::SignatureGenerateKeyPair(Box::new(
            CryptoSignatureGenerateKeyPairRequest {
                algorithm: MessageField::some(signature_identifier()),
                __buffa_unknown_fields: Default::default(),
            },
        )),
        |branch| {
            matches!(
                branch,
                CryptoOperationResultBranch::SignatureGenerateKeyPair(result)
                    if result.public_key.len() == 32 && result.secret_key.len() == 32
            )
        },
    );

    assert_result_branch(
        CryptoOperation::SignatureDeriveKeyPair(Box::new(CryptoSignatureDeriveKeyPairRequest {
            algorithm: MessageField::some(signature_identifier()),
            secret_key: ED25519_SEED.to_vec(),
            __buffa_unknown_fields: Default::default(),
        })),
        |branch| {
            matches!(
                branch,
                CryptoOperationResultBranch::SignatureDeriveKeyPair(result)
                    if result.public_key == public_key && result.secret_key == ED25519_SEED
            )
        },
    );

    assert_result_branch(
        CryptoOperation::SignatureSign(Box::new(CryptoSignatureSignRequest {
            algorithm: MessageField::some(signature_identifier()),
            secret_key: ED25519_SEED.to_vec(),
            message: MESSAGE.to_vec(),
            __buffa_unknown_fields: Default::default(),
        })),
        |branch| {
            matches!(
                branch,
                CryptoOperationResultBranch::SignatureSign(result)
                    if result.signature == signature
            )
        },
    );

    assert_result_branch(
        CryptoOperation::SignatureVerify(Box::new(CryptoSignatureVerifyRequest {
            algorithm: MessageField::some(signature_identifier()),
            public_key,
            message: MESSAGE.to_vec(),
            signature,
            __buffa_unknown_fields: Default::default(),
        })),
        |branch| {
            matches!(
                branch,
                CryptoOperationResultBranch::SignatureVerify(result)
                    if result.status.as_known()
                        == Some(CryptoVerificationStatus::CRYPTO_VERIFICATION_STATUS_VALID)
            )
        },
    );
}

#[test]
fn operation_response_preserves_seed_only_signature_rejection() {
    let (public_key, _) = crypto_ed25519::generate_ed25519_keypair_from_seed(&ED25519_SEED);
    let mut expanded = ED25519_SEED.to_vec();
    expanded.extend_from_slice(&public_key);
    assert_error_reason(
        CryptoOperation::SignatureSign(Box::new(CryptoSignatureSignRequest {
            algorithm: MessageField::some(signature_identifier()),
            secret_key: expanded,
            message: MESSAGE.to_vec(),
            __buffa_unknown_fields: Default::default(),
        })),
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
    );
}

fn assert_result_branch(
    operation: CryptoOperation,
    assertion: impl FnOnce(&CryptoOperationResultBranch) -> bool,
) {
    let response = process_response(operation);
    let Some(CryptoOperationOutcome::Result(result)) = response.outcome else {
        panic!("operation response did not contain a result");
    };
    let Some(branch) = result.result.as_ref() else {
        panic!("operation result did not contain a branch");
    };
    assert!(assertion(branch));
}

fn assert_error_reason(operation: CryptoOperation, expected: CryptoErrorReason) {
    let response = process_response(operation);
    let Some(CryptoOperationOutcome::Error(error)) = response.outcome else {
        panic!("operation response did not contain an error");
    };
    let reason = match error.error {
        Some(CryptoErrorBranch::Primitive(error)) => error.reason.as_known(),
        Some(CryptoErrorBranch::Provider(error)) => error.reason.as_known(),
        Some(CryptoErrorBranch::Backend(error)) => error.reason.as_known(),
        None => None,
    };
    assert_eq!(reason, Some(expected));
}

fn process_response(operation: CryptoOperation) -> CryptoOperationResponse {
    let request = CryptoOperationRequest {
        operation: Some(operation),
        __buffa_unknown_fields: Default::default(),
    };
    let output = reallyme_crypto::operation_contract::process_operation_response(
        request.encode_to_vec().as_slice(),
    );
    decode_operation_response(output.as_slice()).expect("response decodes")
}

fn signature_identifier() -> CryptoAlgorithmIdentifier {
    CryptoAlgorithmIdentifier {
        algorithm: Some(ProtoAlgorithmBranch::Signature(EnumValue::from(
            SignatureAlgorithm::SIGNATURE_ALGORITHM_ED25519,
        ))),
        __buffa_unknown_fields: Default::default(),
    }
}
