// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! KEM vector, semantic-owner, facade, and generated-response parity.

#![cfg(all(
    feature = "operation-response",
    feature = "ml-kem-512",
    feature = "ml-kem-768",
    feature = "ml-kem-1024",
    feature = "x-wing"
))]
#![allow(clippy::expect_used)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use buffa::{EnumValue, Message, MessageField};
use crypto_core::Algorithm;
#[cfg(feature = "test-vectors")]
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as ProtoAlgorithmBranch,
    __buffa::oneof::crypto_error::Error as CryptoErrorBranch,
    __buffa::oneof::crypto_operation_request::Operation as CryptoOperation,
    __buffa::oneof::crypto_operation_response::Outcome as CryptoOperationOutcome,
    __buffa::oneof::crypto_operation_result::Result as CryptoOperationResultBranch,
    CryptoAlgorithmIdentifier, CryptoErrorReason, CryptoKemDecapsulateRequest,
    CryptoKemDeriveKeyPairRequest, CryptoKemEncapsulateRequest, CryptoKemGenerateKeyPairRequest,
    CryptoOperationRequest, CryptoOperationResponse, KemAlgorithm,
};
use crypto_proto::operation_response_wire::decode_operation_response;
use reallyme_crypto::operations::{OperationError, ProviderErrorReason};
use serde::Deserialize;
#[cfg(feature = "test-vectors")]
use zeroize::Zeroizing;

#[derive(Deserialize)]
struct MlKemVector {
    secret_key: String,
    public_key: String,
    #[cfg(feature = "test-vectors")]
    encaps_randomness: String,
    ciphertext: String,
    shared_secret: String,
    #[cfg(feature = "test-vectors")]
    tampered_ciphertext: String,
    #[cfg(feature = "test-vectors")]
    tampered_shared_secret: String,
}

#[derive(Deserialize)]
struct XWingVectorFile {
    x_wing_768: XWingVector,
}

#[derive(Deserialize)]
struct XWingVector {
    secret_key: String,
    public_key: String,
    #[cfg(feature = "test-vectors")]
    encaps_seed: String,
    ciphertext: String,
    shared_secret: String,
}

struct KemCase {
    #[cfg(feature = "test-vectors")]
    algorithm: Algorithm,
    proto_algorithm: KemAlgorithm,
    seed: Vec<u8>,
    public_key: Vec<u8>,
    #[cfg(feature = "test-vectors")]
    randomness: Vec<u8>,
    ciphertext: Vec<u8>,
    shared_secret: Vec<u8>,
    #[cfg(feature = "test-vectors")]
    tampered: Option<(Vec<u8>, Vec<u8>)>,
}

#[test]
#[cfg(feature = "test-vectors")]
fn semantic_owner_and_root_facades_match_every_committed_kem_vector() {
    for case in kem_cases() {
        let owner_key_pair =
            reallyme_crypto::operations::kem::derive_key_pair(case.algorithm, &case.seed)
                .expect("valid KEM vector seed derives a keypair");
        assert_eq!(owner_key_pair.public_key, case.public_key);
        assert_eq!(owner_key_pair.secret_key.as_slice(), case.seed);
        assert_zeroizing(&owner_key_pair.secret_key);

        let facade_key_pair = facade_derive_key_pair(case.algorithm, &case.seed)
            .expect("root KEM facade derives the vector keypair");
        assert_eq!(facade_key_pair.0, case.public_key);
        assert_eq!(facade_key_pair.1.as_slice(), case.seed);

        let owner_encapsulation = reallyme_crypto::operations::kem::encapsulate_derand(
            case.algorithm,
            &case.public_key,
            &case.randomness,
        )
        .expect("valid deterministic KEM vector encapsulates");
        assert_eq!(owner_encapsulation.ciphertext, case.ciphertext);
        assert_eq!(
            owner_encapsulation.shared_secret.as_slice(),
            case.shared_secret
        );
        assert_zeroizing(&owner_encapsulation.shared_secret);

        let facade_encapsulation =
            facade_encapsulate_derand(case.algorithm, &case.public_key, &case.randomness)
                .expect("root KEM facade reproduces deterministic vector");
        assert_eq!(facade_encapsulation.0, case.ciphertext);
        assert_eq!(facade_encapsulation.1.as_slice(), case.shared_secret);

        let owner_shared_secret = reallyme_crypto::operations::kem::decapsulate(
            case.algorithm,
            &case.ciphertext,
            &case.seed,
        )
        .expect("semantic owner decapsulates committed vector");
        assert_eq!(owner_shared_secret.as_slice(), case.shared_secret);
        assert_zeroizing(&owner_shared_secret);

        let facade_shared_secret = facade_decapsulate(case.algorithm, &case.ciphertext, &case.seed)
            .expect("root KEM facade decapsulates committed vector");
        assert_eq!(facade_shared_secret.as_slice(), case.shared_secret);

        if let Some((tampered_ciphertext, tampered_shared_secret)) = &case.tampered {
            let rejected = reallyme_crypto::operations::kem::decapsulate(
                case.algorithm,
                tampered_ciphertext,
                &case.seed,
            )
            .expect("ML-KEM applies implicit rejection to a full-length ciphertext");
            assert_eq!(rejected.as_slice(), tampered_shared_secret);
            assert_ne!(rejected.as_slice(), case.shared_secret);
        }
    }
}

#[test]
fn generated_response_exposes_all_four_kem_result_branches_for_every_algorithm() {
    for case in kem_cases() {
        let generated = result_branch(CryptoOperation::KemGenerateKeyPair(Box::new(
            CryptoKemGenerateKeyPairRequest {
                algorithm: MessageField::some(kem_identifier(case.proto_algorithm)),
                __buffa_unknown_fields: Default::default(),
            },
        )))
        .expect("KEM key generation returns a generated result branch");
        assert!(matches!(
            generated,
            CryptoOperationResultBranch::KemGenerateKeyPair(ref key_pair)
                if key_pair.public_key.len() == case.public_key.len()
                    && key_pair.secret_key.len() == case.seed.len()
                    && result_algorithm(&key_pair.algorithm) == Some(case.proto_algorithm)
        ));

        let derived = result_branch(CryptoOperation::KemDeriveKeyPair(Box::new(
            CryptoKemDeriveKeyPairRequest {
                algorithm: MessageField::some(kem_identifier(case.proto_algorithm)),
                secret_key: case.seed.clone(),
                __buffa_unknown_fields: Default::default(),
            },
        )))
        .expect("KEM key derivation returns a generated result branch");
        assert!(matches!(
            derived,
            CryptoOperationResultBranch::KemDeriveKeyPair(ref key_pair)
                if key_pair.public_key == case.public_key
                    && key_pair.secret_key == case.seed
                    && result_algorithm(&key_pair.algorithm) == Some(case.proto_algorithm)
        ));

        let encapsulated = result_branch(CryptoOperation::KemEncapsulate(Box::new(
            CryptoKemEncapsulateRequest {
                algorithm: MessageField::some(kem_identifier(case.proto_algorithm)),
                public_key: case.public_key.clone(),
                __buffa_unknown_fields: Default::default(),
            },
        )))
        .expect("KEM encapsulation returns a generated result branch");
        let encapsulation = match encapsulated {
            CryptoOperationResultBranch::KemEncapsulate(encapsulation) => Some(encapsulation),
            _ => None,
        }
        .expect("KEM encapsulation returned the expected result branch");
        assert_eq!(encapsulation.ciphertext.len(), case.ciphertext.len());
        assert_eq!(encapsulation.shared_secret.len(), case.shared_secret.len());
        assert_eq!(
            result_algorithm(&encapsulation.algorithm),
            Some(case.proto_algorithm)
        );

        let decapsulated = result_branch(CryptoOperation::KemDecapsulate(Box::new(
            CryptoKemDecapsulateRequest {
                algorithm: MessageField::some(kem_identifier(case.proto_algorithm)),
                ciphertext: encapsulation.ciphertext.clone(),
                secret_key: case.seed.clone(),
                __buffa_unknown_fields: Default::default(),
            },
        )))
        .expect("KEM decapsulation returns a generated result branch");
        assert!(matches!(
            decapsulated,
            CryptoOperationResultBranch::KemDecapsulate(ref result)
                if result.shared_secret == encapsulation.shared_secret
                    && result_algorithm(&result.algorithm) == Some(case.proto_algorithm)
        ));
    }
}

#[test]
fn generated_response_returns_stable_typed_kem_failures() {
    for case in kem_cases() {
        assert_error_reason(
            CryptoOperation::KemDeriveKeyPair(Box::new(CryptoKemDeriveKeyPairRequest {
                algorithm: MessageField::some(kem_identifier(case.proto_algorithm)),
                secret_key: vec![1, 2],
                __buffa_unknown_fields: Default::default(),
            })),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
        );
        assert_error_reason(
            CryptoOperation::KemEncapsulate(Box::new(CryptoKemEncapsulateRequest {
                algorithm: MessageField::some(kem_identifier(case.proto_algorithm)),
                public_key: vec![3, 4],
                __buffa_unknown_fields: Default::default(),
            })),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
        );
        assert_error_reason(
            CryptoOperation::KemDecapsulate(Box::new(CryptoKemDecapsulateRequest {
                algorithm: MessageField::some(kem_identifier(case.proto_algorithm)),
                ciphertext: vec![5, 6],
                secret_key: case.seed,
                __buffa_unknown_fields: Default::default(),
            })),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH,
        );
    }

    assert_error_reason(
        CryptoOperation::KemGenerateKeyPair(Box::new(CryptoKemGenerateKeyPairRequest {
            algorithm: MessageField::some(kem_identifier(KemAlgorithm::KEM_ALGORITHM_UNSPECIFIED)),
            __buffa_unknown_fields: Default::default(),
        })),
        CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM,
    );

    assert_eq!(
        reallyme_crypto::operations::kem::generate_key_pair(Algorithm::Ed25519).err(),
        Some(OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        })
    );
}

#[cfg(feature = "test-vectors")]
fn facade_derive_key_pair(
    algorithm: Algorithm,
    seed: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    match algorithm {
        Algorithm::MlKem512 => reallyme_crypto::ml_kem_512::generate_ml_kem_512_keypair_from_seed(
            <&[u8; 64]>::try_from(seed).map_err(|_| CryptoError::InvalidKey)?,
        ),
        Algorithm::MlKem768 => reallyme_crypto::ml_kem_768::generate_ml_kem_768_keypair_from_seed(
            <&[u8; 64]>::try_from(seed).map_err(|_| CryptoError::InvalidKey)?,
        ),
        Algorithm::MlKem1024 => {
            reallyme_crypto::ml_kem_1024::generate_ml_kem_1024_keypair_from_seed(
                <&[u8; 64]>::try_from(seed).map_err(|_| CryptoError::InvalidKey)?,
            )
        }
        Algorithm::XWing768 => reallyme_crypto::x_wing::generate_x_wing_768_keypair_derand(seed),
        _ => Err(CryptoError::Unsupported),
    }
}

#[cfg(feature = "test-vectors")]
fn facade_encapsulate_derand(
    algorithm: Algorithm,
    public_key: &[u8],
    randomness: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    match algorithm {
        Algorithm::MlKem512 => {
            reallyme_crypto::ml_kem_512::ml_kem_512_encapsulate_derand(public_key, randomness)
        }
        Algorithm::MlKem768 => {
            reallyme_crypto::ml_kem_768::ml_kem_768_encapsulate_derand(public_key, randomness)
        }
        Algorithm::MlKem1024 => {
            reallyme_crypto::ml_kem_1024::ml_kem_1024_encapsulate_derand(public_key, randomness)
        }
        Algorithm::XWing768 => {
            reallyme_crypto::x_wing::x_wing_768_encapsulate_derand(public_key, randomness)
        }
        _ => Err(CryptoError::Unsupported),
    }
}

#[cfg(feature = "test-vectors")]
fn facade_decapsulate(
    algorithm: Algorithm,
    ciphertext: &[u8],
    seed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    match algorithm {
        Algorithm::MlKem512 => {
            reallyme_crypto::ml_kem_512::ml_kem_512_decapsulate(ciphertext, seed)
        }
        Algorithm::MlKem768 => {
            reallyme_crypto::ml_kem_768::ml_kem_768_decapsulate(ciphertext, seed)
        }
        Algorithm::MlKem1024 => {
            reallyme_crypto::ml_kem_1024::ml_kem_1024_decapsulate(ciphertext, seed)
        }
        Algorithm::XWing768 => reallyme_crypto::x_wing::x_wing_768_decapsulate(ciphertext, seed),
        _ => Err(CryptoError::Unsupported),
    }
}

fn kem_cases() -> [KemCase; 4] {
    let ml_kem_512: MlKemVector =
        serde_json::from_str(include_str!("../../../vectors/mlkem512.json"))
            .expect("ML-KEM-512 vector parses");
    let ml_kem_768: MlKemVector =
        serde_json::from_str(include_str!("../../../vectors/mlkem768.json"))
            .expect("ML-KEM-768 vector parses");
    let ml_kem_1024: MlKemVector =
        serde_json::from_str(include_str!("../../../vectors/mlkem1024.json"))
            .expect("ML-KEM-1024 vector parses");
    let x_wing: XWingVectorFile =
        serde_json::from_str(include_str!("../../../vectors/x_wing.json"))
            .expect("X-Wing vector parses");

    [
        ml_kem_case(
            Algorithm::MlKem512,
            KemAlgorithm::KEM_ALGORITHM_ML_KEM_512,
            ml_kem_512,
        ),
        ml_kem_case(
            Algorithm::MlKem768,
            KemAlgorithm::KEM_ALGORITHM_ML_KEM_768,
            ml_kem_768,
        ),
        ml_kem_case(
            Algorithm::MlKem1024,
            KemAlgorithm::KEM_ALGORITHM_ML_KEM_1024,
            ml_kem_1024,
        ),
        KemCase {
            #[cfg(feature = "test-vectors")]
            algorithm: Algorithm::XWing768,
            proto_algorithm: KemAlgorithm::KEM_ALGORITHM_X_WING_768,
            seed: decode(&x_wing.x_wing_768.secret_key),
            public_key: decode(&x_wing.x_wing_768.public_key),
            #[cfg(feature = "test-vectors")]
            randomness: decode(&x_wing.x_wing_768.encaps_seed),
            ciphertext: decode(&x_wing.x_wing_768.ciphertext),
            shared_secret: decode(&x_wing.x_wing_768.shared_secret),
            #[cfg(feature = "test-vectors")]
            tampered: None,
        },
    ]
}

fn ml_kem_case(
    _algorithm: Algorithm,
    proto_algorithm: KemAlgorithm,
    vector: MlKemVector,
) -> KemCase {
    KemCase {
        #[cfg(feature = "test-vectors")]
        algorithm: _algorithm,
        proto_algorithm,
        seed: decode(&vector.secret_key),
        public_key: decode(&vector.public_key),
        #[cfg(feature = "test-vectors")]
        randomness: decode(&vector.encaps_randomness),
        ciphertext: decode(&vector.ciphertext),
        shared_secret: decode(&vector.shared_secret),
        #[cfg(feature = "test-vectors")]
        tampered: Some((
            decode(&vector.tampered_ciphertext),
            decode(&vector.tampered_shared_secret),
        )),
    }
}

fn decode(value: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(value)
        .expect("committed vector field is valid base64url")
}

#[cfg(feature = "test-vectors")]
fn assert_zeroizing(_: &Zeroizing<Vec<u8>>) {}

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
) -> Option<KemAlgorithm> {
    match identifier.as_option()?.algorithm.as_ref()? {
        ProtoAlgorithmBranch::Kem(value) => value.as_known(),
        _ => None,
    }
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

fn kem_identifier(algorithm: KemAlgorithm) -> CryptoAlgorithmIdentifier {
    CryptoAlgorithmIdentifier {
        algorithm: Some(ProtoAlgorithmBranch::Kem(EnumValue::from(algorithm))),
        __buffa_unknown_fields: Default::default(),
    }
}
