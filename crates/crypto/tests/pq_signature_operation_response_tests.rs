// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Post-quantum signature vectors, semantic/facade parity, and generated responses.

#![cfg(all(
    feature = "operation-response",
    feature = "ml-dsa-44",
    feature = "ml-dsa-65",
    feature = "ml-dsa-87",
    feature = "slh-dsa"
))]
#![allow(clippy::expect_used, clippy::panic)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use buffa::{EnumValue, Message, MessageField};
use crypto_core::{Algorithm, CryptoError};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as ProtoAlgorithmBranch,
    __buffa::oneof::crypto_error::Error as CryptoErrorBranch,
    __buffa::oneof::crypto_operation_request::Operation as CryptoOperation,
    __buffa::oneof::crypto_operation_response::Outcome as CryptoOperationOutcome,
    __buffa::oneof::crypto_operation_result::Result as CryptoOperationResultBranch,
    CryptoAlgorithmIdentifier, CryptoErrorReason, CryptoOperationRequest, CryptoOperationResponse,
    CryptoSignatureDeriveKeyPairRequest, CryptoSignatureGenerateKeyPairRequest,
    CryptoSignatureSignRequest, CryptoSignatureVerifyRequest, CryptoVerificationResult,
    CryptoVerificationStatus, SignatureAlgorithm,
};
use crypto_proto::operation_response_wire::decode_operation_response;
use reallyme_crypto::operations::signature::SignatureKeyPair;
use reallyme_crypto::operations::{OperationError, PrimitiveErrorReason, ProviderErrorReason};
use serde::Deserialize;
use zeroize::Zeroizing;

#[derive(Deserialize)]
struct MlDsaVector {
    secret_key: String,
    public_key: String,
    message: String,
    signature: String,
}

#[derive(Deserialize)]
struct SlhDsaVector {
    keygen_sk_seed: String,
    keygen_sk_prf: String,
    keygen_pk_seed: String,
    secret_key: String,
    public_key: String,
    message: String,
    signature: String,
}

struct SignatureCase {
    algorithm: Algorithm,
    proto_algorithm: SignatureAlgorithm,
    derive_input: Vec<u8>,
    secret_key: Vec<u8>,
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
}

#[test]
fn semantic_owner_and_root_facades_match_every_committed_pq_signature_vector() {
    for case in signature_cases() {
        let owner = reallyme_crypto::operations::signature::derive_key_pair(
            case.algorithm,
            &case.derive_input,
        )
        .expect("committed seed material derives through the semantic owner");
        assert_key_pair(&owner, &case);

        let facade = facade_derive_key_pair(case.algorithm, &case.derive_input)
            .expect("root facade derives the committed keypair");
        assert_eq!(facade.0, case.public_key);
        assert_eq!(facade.1.as_slice(), case.secret_key);

        let owner_signature = reallyme_crypto::operations::signature::sign(
            case.algorithm,
            &case.secret_key,
            &case.message,
        )
        .expect("semantic owner signs committed vector input");
        assert_eq!(owner_signature, case.signature);
        assert_eq!(
            facade_sign(case.algorithm, &case.secret_key, &case.message)
                .expect("root facade signs committed vector input"),
            case.signature
        );
        reallyme_crypto::operations::signature::verify(
            case.algorithm,
            &case.public_key,
            &case.message,
            &case.signature,
        )
        .expect("semantic owner verifies committed signature");

        let mut tampered = case.signature.clone();
        tampered[0] ^= 0x01;
        assert_eq!(
            reallyme_crypto::operations::signature::verify(
                case.algorithm,
                &case.public_key,
                &case.message,
                &tampered,
            )
            .expect_err("tampered signature fails closed"),
            OperationError::Primitive {
                reason: PrimitiveErrorReason::VerificationFailed,
            }
        );
    }
}

#[test]
fn generated_response_exposes_all_signature_branches_for_every_pq_algorithm() {
    for case in signature_cases() {
        let generated = result_branch(CryptoOperation::SignatureGenerateKeyPair(Box::new(
            CryptoSignatureGenerateKeyPairRequest {
                algorithm: MessageField::some(signature_identifier(case.proto_algorithm)),
                __buffa_unknown_fields: Default::default(),
            },
        )))
        .expect("PQ signature key generation returns a generated result branch");
        let generated_key_pair = match generated {
            CryptoOperationResultBranch::SignatureGenerateKeyPair(key_pair) => Some(key_pair),
            _ => None,
        }
        .expect("signature generation returned the expected result branch");
        assert_eq!(generated_key_pair.public_key.len(), case.public_key.len());
        assert_eq!(generated_key_pair.secret_key.len(), case.secret_key.len());
        assert_eq!(
            result_algorithm(&generated_key_pair.algorithm),
            Some(case.proto_algorithm)
        );

        let derived = result_branch(CryptoOperation::SignatureDeriveKeyPair(Box::new(
            CryptoSignatureDeriveKeyPairRequest {
                algorithm: MessageField::some(signature_identifier(case.proto_algorithm)),
                secret_key: case.derive_input.clone(),
                __buffa_unknown_fields: Default::default(),
            },
        )))
        .expect("PQ signature derivation returns a generated result branch");
        assert!(matches!(
            derived,
            CryptoOperationResultBranch::SignatureDeriveKeyPair(ref key_pair)
                if key_pair.public_key == case.public_key
                    && key_pair.secret_key == case.secret_key
                    && result_algorithm(&key_pair.algorithm) == Some(case.proto_algorithm)
        ));

        let signed = result_branch(CryptoOperation::SignatureSign(Box::new(
            CryptoSignatureSignRequest {
                algorithm: MessageField::some(signature_identifier(case.proto_algorithm)),
                secret_key: case.secret_key.clone(),
                message: case.message.clone(),
                __buffa_unknown_fields: Default::default(),
            },
        )))
        .expect("PQ signature signing returns a generated result branch");
        assert!(matches!(
            signed,
            CryptoOperationResultBranch::SignatureSign(ref result)
                if result.signature == case.signature
                    && result_algorithm(&result.algorithm) == Some(case.proto_algorithm)
        ));

        let verified = verification_result(&case, case.public_key.clone(), case.signature.clone());
        assert_eq!(
            verified.status.as_known(),
            Some(CryptoVerificationStatus::CRYPTO_VERIFICATION_STATUS_VALID)
        );
        assert!(verified.error.as_option().is_none());
    }
}

#[test]
fn pq_signature_failures_are_typed_and_invalid_signatures_are_not_errors() {
    for case in signature_cases() {
        for invalid_length in [
            case.derive_input
                .len()
                .checked_sub(1)
                .expect("non-empty seed"),
            case.derive_input
                .len()
                .checked_add(1)
                .expect("small test length"),
        ] {
            assert_top_level_error(
                CryptoOperation::SignatureDeriveKeyPair(Box::new(
                    CryptoSignatureDeriveKeyPairRequest {
                        algorithm: MessageField::some(signature_identifier(case.proto_algorithm)),
                        secret_key: vec![0xA5; invalid_length],
                        __buffa_unknown_fields: Default::default(),
                    },
                )),
                CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
            );
        }

        assert_top_level_error(
            CryptoOperation::SignatureSign(Box::new(CryptoSignatureSignRequest {
                algorithm: MessageField::some(signature_identifier(case.proto_algorithm)),
                secret_key: vec![
                    0x5A;
                    case.secret_key
                        .len()
                        .checked_sub(1)
                        .expect("non-empty secret key")
                ],
                message: case.message.clone(),
                __buffa_unknown_fields: Default::default(),
            })),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
        );

        let malformed_key = verification_result(&case, Vec::new(), case.signature.clone());
        assert_eq!(
            malformed_key.status.as_known(),
            Some(CryptoVerificationStatus::CRYPTO_VERIFICATION_STATUS_ERROR)
        );
        assert_eq!(
            embedded_error_reason(&malformed_key),
            Some(CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY)
        );

        let mut tampered = case.signature.clone();
        tampered[0] ^= 0x80;
        let mismatch = verification_result(&case, case.public_key.clone(), tampered);
        assert_invalid_verification(&mismatch);
        assert!(mismatch.error.as_option().is_none());

        let malformed_signature = verification_result(&case, case.public_key.clone(), vec![0x01]);
        assert_invalid_verification(&malformed_signature);
        assert!(malformed_signature.error.as_option().is_none());
    }

    assert_eq!(
        reallyme_crypto::operations::signature::generate_key_pair(Algorithm::MlKem512).err(),
        Some(OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        })
    );
    assert_top_level_error(
        CryptoOperation::SignatureGenerateKeyPair(Box::new(
            CryptoSignatureGenerateKeyPairRequest {
                algorithm: MessageField::some(signature_identifier(
                    SignatureAlgorithm::SIGNATURE_ALGORITHM_UNSPECIFIED,
                )),
                __buffa_unknown_fields: Default::default(),
            },
        )),
        CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM,
    );
}

fn assert_key_pair(key_pair: &SignatureKeyPair, case: &SignatureCase) {
    assert_eq!(key_pair.public_key, case.public_key);
    assert_eq!(key_pair.secret_key.as_slice(), case.secret_key);
    assert_zeroizing(&key_pair.secret_key);
}

fn facade_derive_key_pair(
    algorithm: Algorithm,
    seed: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    match algorithm {
        Algorithm::MlDsa44 => reallyme_crypto::ml_dsa_44::generate_ml_dsa_44_keypair_from_seed(
            <&[u8; 32]>::try_from(seed).map_err(|_| CryptoError::InvalidKey)?,
        ),
        Algorithm::MlDsa65 => reallyme_crypto::ml_dsa_65::generate_ml_dsa_65_keypair_from_seed(
            <&[u8; 32]>::try_from(seed).map_err(|_| CryptoError::InvalidKey)?,
        ),
        Algorithm::MlDsa87 => reallyme_crypto::ml_dsa_87::generate_ml_dsa_87_keypair_from_seed(
            <&[u8; 32]>::try_from(seed).map_err(|_| CryptoError::InvalidKey)?,
        ),
        Algorithm::SlhDsaSha2_128s => reallyme_crypto::slh_dsa::derive_slh_dsa_sha2_128s_keypair(
            seed.get(..16).ok_or(CryptoError::InvalidKey)?,
            seed.get(16..32).ok_or(CryptoError::InvalidKey)?,
            seed.get(32..48).ok_or(CryptoError::InvalidKey)?,
        ),
        _ => Err(CryptoError::Unsupported),
    }
}

fn facade_sign(
    algorithm: Algorithm,
    secret_key: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    match algorithm {
        Algorithm::MlDsa44 => reallyme_crypto::ml_dsa_44::sign_ml_dsa_44(secret_key, message),
        Algorithm::MlDsa65 => reallyme_crypto::ml_dsa_65::sign_ml_dsa_65(secret_key, message),
        Algorithm::MlDsa87 => reallyme_crypto::ml_dsa_87::sign_ml_dsa_87(secret_key, message),
        Algorithm::SlhDsaSha2_128s => {
            reallyme_crypto::slh_dsa::sign_slh_dsa_sha2_128s(secret_key, message)
        }
        _ => Err(CryptoError::Unsupported),
    }
}

fn signature_cases() -> [SignatureCase; 4] {
    let ml44: MlDsaVector = serde_json::from_str(include_str!("../../../vectors/ml_dsa_44.json"))
        .expect("ML-DSA-44 vector parses");
    let ml65: MlDsaVector = serde_json::from_str(include_str!("../../../vectors/ml_dsa_65.json"))
        .expect("ML-DSA-65 vector parses");
    let ml87: MlDsaVector = serde_json::from_str(include_str!("../../../vectors/ml_dsa_87.json"))
        .expect("ML-DSA-87 vector parses");
    let slh: SlhDsaVector =
        serde_json::from_str(include_str!("../../../vectors/slh_dsa_sha2_128s.json"))
            .expect("SLH-DSA vector parses");
    [
        ml_dsa_case(
            Algorithm::MlDsa44,
            SignatureAlgorithm::SIGNATURE_ALGORITHM_ML_DSA_44,
            ml44,
        ),
        ml_dsa_case(
            Algorithm::MlDsa65,
            SignatureAlgorithm::SIGNATURE_ALGORITHM_ML_DSA_65,
            ml65,
        ),
        ml_dsa_case(
            Algorithm::MlDsa87,
            SignatureAlgorithm::SIGNATURE_ALGORITHM_ML_DSA_87,
            ml87,
        ),
        slh_dsa_case(slh),
    ]
}

fn ml_dsa_case(
    algorithm: Algorithm,
    proto_algorithm: SignatureAlgorithm,
    vector: MlDsaVector,
) -> SignatureCase {
    let secret_key = decode(&vector.secret_key);
    SignatureCase {
        algorithm,
        proto_algorithm,
        derive_input: secret_key.clone(),
        secret_key,
        public_key: decode(&vector.public_key),
        message: decode(&vector.message),
        signature: decode(&vector.signature),
    }
}

fn slh_dsa_case(vector: SlhDsaVector) -> SignatureCase {
    let mut derive_input = Vec::with_capacity(48);
    derive_input.extend_from_slice(&decode(&vector.keygen_sk_seed));
    derive_input.extend_from_slice(&decode(&vector.keygen_sk_prf));
    derive_input.extend_from_slice(&decode(&vector.keygen_pk_seed));
    SignatureCase {
        algorithm: Algorithm::SlhDsaSha2_128s,
        proto_algorithm: SignatureAlgorithm::SIGNATURE_ALGORITHM_SLH_DSA_SHA2_128S,
        derive_input,
        secret_key: decode(&vector.secret_key),
        public_key: decode(&vector.public_key),
        message: decode(&vector.message),
        signature: decode(&vector.signature),
    }
}

fn decode(value: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(value)
        .expect("committed vector field is valid base64url")
}

fn verification_result(
    case: &SignatureCase,
    public_key: Vec<u8>,
    signature: Vec<u8>,
) -> Box<CryptoVerificationResult> {
    let branch = result_branch(CryptoOperation::SignatureVerify(Box::new(
        CryptoSignatureVerifyRequest {
            algorithm: MessageField::some(signature_identifier(case.proto_algorithm)),
            public_key,
            message: case.message.clone(),
            signature,
            __buffa_unknown_fields: Default::default(),
        },
    )))
    .expect("signature verification returns a generated result branch");
    match branch {
        CryptoOperationResultBranch::SignatureVerify(result) => result,
        _ => panic!("signature verification returned the wrong result branch"),
    }
}

fn assert_invalid_verification(result: &CryptoVerificationResult) {
    assert_eq!(
        result.status.as_known(),
        Some(CryptoVerificationStatus::CRYPTO_VERIFICATION_STATUS_INVALID)
    );
}

fn embedded_error_reason(result: &CryptoVerificationResult) -> Option<CryptoErrorReason> {
    match result.error.as_option()?.error.as_ref()? {
        CryptoErrorBranch::Primitive(error) => error.reason.as_known(),
        CryptoErrorBranch::Provider(error) => error.reason.as_known(),
        CryptoErrorBranch::Backend(error) => error.reason.as_known(),
    }
}

fn result_branch(operation: CryptoOperation) -> Option<CryptoOperationResultBranch> {
    match process_response(operation).outcome {
        Some(CryptoOperationOutcome::Result(result)) => result.result,
        _ => None,
    }
}

fn result_algorithm(
    identifier: &MessageField<
        CryptoAlgorithmIdentifier,
        impl buffa::ProtoBox<CryptoAlgorithmIdentifier>,
    >,
) -> Option<SignatureAlgorithm> {
    match identifier.as_option()?.algorithm.as_ref()? {
        ProtoAlgorithmBranch::Signature(value) => value.as_known(),
        _ => None,
    }
}

fn assert_top_level_error(operation: CryptoOperation, expected: CryptoErrorReason) {
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

fn signature_identifier(algorithm: SignatureAlgorithm) -> CryptoAlgorithmIdentifier {
    CryptoAlgorithmIdentifier {
        algorithm: Some(ProtoAlgorithmBranch::Signature(EnumValue::from(algorithm))),
        __buffa_unknown_fields: Default::default(),
    }
}

fn assert_zeroizing(_: &Zeroizing<Vec<u8>>) {}
