// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! RSA semantic-owner, facade, and generated-response parity.

#![cfg(all(feature = "operation-response", feature = "rsa"))]
#![allow(clippy::expect_used)]

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use buffa::{EnumValue, Message, MessageField};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as ProtoAlgorithmBranch,
    __buffa::oneof::crypto_error::Error as CryptoErrorBranch,
    __buffa::oneof::crypto_operation_request::Operation as CryptoOperation,
    __buffa::oneof::crypto_operation_response::Outcome as CryptoOperationOutcome,
    __buffa::oneof::crypto_operation_result::Result as CryptoOperationResultBranch,
    CryptoAlgorithmIdentifier, CryptoErrorReason, CryptoOperationRequest, CryptoOperationResponse,
    CryptoRsaVerifyRequest, CryptoVerificationStatus, RsaPublicKeyDerEncoding as ProtoKeyEncoding,
    SignatureAlgorithm,
};
use crypto_proto::operation_response_wire::decode_operation_response;
use reallyme_crypto::operations::{OperationError, PrimitiveErrorReason};
use reallyme_crypto::rsa::{RsaHash, RsaPssParams, RsaPublicKeyDerEncoding};
use serde::Deserialize;

const NON_BYTE_ALIGNED_PUBLIC_KEY: &str = "MIGJAoGBAT2xGH3a2TEFZ5QzqDasWUbE3bqGfOSapZHM1/VReRgLDT5mh9qFEYCCC9c9gZdVpT3JH+UXa47WC133wCohGgihZJfSSjd8F59GdXBOlN1SPESfAO+byULl7/pyBYqj3lkiNo2yA73AGMQW279ZrZUHapliQYhTFs1K7DK0w+l/AgMBAAE=";
const NON_BYTE_ALIGNED_SIGNATURE: &str = "AJw/2MC05uvkQewI8UcKYVB6XpaJ2Fu9qwBCMBlIlVVP5I9/gnmBs8QMZavjoRReZnURZkLpACVIF1tRO+eCUheclpKEBqEog9ECpwmXYVR11kWREyTfeNJyXaYAM7jxYLptdfeDVYZ6SmJrtXGoG5rdSBQIMxeqiAP0UJ/7qZd5";

#[derive(Deserialize)]
struct RsaVectors {
    public_key_der: String,
    message: String,
    pkcs1v15_sha1_signature: String,
    pkcs1v15_sha256_signature: String,
    pkcs1v15_sha384_signature: String,
    pkcs1v15_sha512_signature: String,
    pss_sha1_mgf1_sha1_salt_len: usize,
    pss_sha1_mgf1_sha1_signature: String,
    pss_sha256_mgf1_sha256_salt_len: usize,
    pss_sha256_mgf1_sha256_signature: String,
    pss_sha384_mgf1_sha384_salt_len: usize,
    pss_sha384_mgf1_sha384_signature: String,
    pss_sha512_mgf1_sha512_salt_len: usize,
    pss_sha512_mgf1_sha512_signature: String,
}

#[derive(Clone, Copy)]
enum Suite {
    Pkcs1v15(RsaHash),
    Pss(RsaPssParams),
}

struct RsaCase<'a> {
    algorithm: SignatureAlgorithm,
    signature: &'a str,
    suite: Suite,
}

#[test]
fn every_public_rsa_suite_matches_semantic_owner_facade_and_generated_response() {
    let vectors = vectors();
    let public_key = decode_url(&vectors.public_key_der);
    let message = decode_url(&vectors.message);

    for case in cases(&vectors) {
        let signature = decode_url(case.signature);
        verify_with_owner(case.suite, &public_key, &message, &signature)
            .expect("semantic owner verifies repository vector");
        verify_with_facade(case.suite, &public_key, &message, &signature)
            .expect("public facade verifies repository vector");

        let result = rsa_result(
            case.algorithm,
            public_key.clone(),
            message.clone(),
            signature,
        )
        .expect("RSA operation returns its generated result branch");
        assert_eq!(
            result.status.as_known(),
            Some(CryptoVerificationStatus::CRYPTO_VERIFICATION_STATUS_VALID)
        );
        assert_eq!(result_algorithm(&result), Some(case.algorithm));
        assert!(result.error.as_option().is_none());
    }
}

#[test]
fn generated_response_distinguishes_mismatch_malformed_key_and_unsupported_suite() {
    let vectors = vectors();
    let public_key = decode_url(&vectors.public_key_der);
    let message = decode_url(&vectors.message);
    let mut signature = decode_url(&vectors.pkcs1v15_sha256_signature);
    signature[0] ^= 1;

    let mismatch = rsa_result(
        SignatureAlgorithm::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA256,
        public_key,
        message,
        signature,
    )
    .expect("RSA mismatch returns a verification result");
    assert_eq!(
        mismatch.status.as_known(),
        Some(CryptoVerificationStatus::CRYPTO_VERIFICATION_STATUS_INVALID)
    );
    assert!(mismatch.error.as_option().is_none());

    let malformed = rsa_result(
        SignatureAlgorithm::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA256,
        vec![0x30, 0x00],
        decode_url(&vectors.message),
        decode_url(&vectors.pkcs1v15_sha256_signature),
    )
    .expect("malformed RSA key returns a typed verification result");
    assert_eq!(
        malformed.status.as_known(),
        Some(CryptoVerificationStatus::CRYPTO_VERIFICATION_STATUS_ERROR)
    );
    assert_eq!(
        nested_error_reason(&malformed),
        Some(CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY)
    );

    let response = process_response(CryptoOperation::RsaVerify(Box::new(rsa_request(
        SignatureAlgorithm::SIGNATURE_ALGORITHM_ED25519,
        decode_url(&vectors.public_key_der),
        decode_url(&vectors.message),
        decode_url(&vectors.pkcs1v15_sha256_signature),
    ))));
    assert_eq!(
        response_error_reason(&response),
        Some(CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM)
    );
}

#[test]
fn semantic_owner_supports_rfc8017_short_encoded_message_and_typed_rejection() {
    let public_key = STANDARD
        .decode(NON_BYTE_ALIGNED_PUBLIC_KEY)
        .expect("1025-bit public key decodes");
    let signature = STANDARD
        .decode(NON_BYTE_ALIGNED_SIGNATURE)
        .expect("1025-bit signature decodes");
    let suite = Suite::Pss(RsaPssParams {
        message_hash: RsaHash::Sha256,
        mgf1_hash: RsaHash::Sha256,
        salt_len: 32,
    });

    verify_with_owner(suite, &public_key, &[], &signature)
        .expect("RFC 8017 emLen = k - 1 signature verifies through semantic owner");
    verify_with_facade(suite, &public_key, &[], &signature)
        .expect("RFC 8017 emLen = k - 1 signature verifies through public facade");

    let error = verify_with_owner(suite, &public_key, b"wrong message", &signature)
        .expect_err("wrong message is a verification mismatch");
    assert_eq!(
        error,
        OperationError::Primitive {
            reason: PrimitiveErrorReason::VerificationFailed
        }
    );
}

fn cases(vectors: &RsaVectors) -> [RsaCase<'_>; 8] {
    [
        pkcs1_case(
            SignatureAlgorithm::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA1,
            &vectors.pkcs1v15_sha1_signature,
            RsaHash::Sha1,
        ),
        pkcs1_case(
            SignatureAlgorithm::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA256,
            &vectors.pkcs1v15_sha256_signature,
            RsaHash::Sha256,
        ),
        pkcs1_case(
            SignatureAlgorithm::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA384,
            &vectors.pkcs1v15_sha384_signature,
            RsaHash::Sha384,
        ),
        pkcs1_case(
            SignatureAlgorithm::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA512,
            &vectors.pkcs1v15_sha512_signature,
            RsaHash::Sha512,
        ),
        pss_case(
            SignatureAlgorithm::SIGNATURE_ALGORITHM_RSA_PSS_SHA1_MGF1_SHA1,
            &vectors.pss_sha1_mgf1_sha1_signature,
            RsaHash::Sha1,
            vectors.pss_sha1_mgf1_sha1_salt_len,
        ),
        pss_case(
            SignatureAlgorithm::SIGNATURE_ALGORITHM_RSA_PSS_SHA256_MGF1_SHA256,
            &vectors.pss_sha256_mgf1_sha256_signature,
            RsaHash::Sha256,
            vectors.pss_sha256_mgf1_sha256_salt_len,
        ),
        pss_case(
            SignatureAlgorithm::SIGNATURE_ALGORITHM_RSA_PSS_SHA384_MGF1_SHA384,
            &vectors.pss_sha384_mgf1_sha384_signature,
            RsaHash::Sha384,
            vectors.pss_sha384_mgf1_sha384_salt_len,
        ),
        pss_case(
            SignatureAlgorithm::SIGNATURE_ALGORITHM_RSA_PSS_SHA512_MGF1_SHA512,
            &vectors.pss_sha512_mgf1_sha512_signature,
            RsaHash::Sha512,
            vectors.pss_sha512_mgf1_sha512_salt_len,
        ),
    ]
}

fn pkcs1_case(algorithm: SignatureAlgorithm, signature: &str, hash: RsaHash) -> RsaCase<'_> {
    RsaCase {
        algorithm,
        signature,
        suite: Suite::Pkcs1v15(hash),
    }
}

fn pss_case(
    algorithm: SignatureAlgorithm,
    signature: &str,
    hash: RsaHash,
    salt_len: usize,
) -> RsaCase<'_> {
    RsaCase {
        algorithm,
        signature,
        suite: Suite::Pss(RsaPssParams {
            message_hash: hash,
            mgf1_hash: hash,
            salt_len,
        }),
    }
}

fn verify_with_owner(
    suite: Suite,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), OperationError> {
    match suite {
        Suite::Pkcs1v15(hash) => reallyme_crypto::operations::signature::verify_rsa_pkcs1v15(
            public_key,
            RsaPublicKeyDerEncoding::Pkcs1,
            hash,
            message,
            signature,
        ),
        Suite::Pss(params) => reallyme_crypto::operations::signature::verify_rsa_pss(
            public_key,
            RsaPublicKeyDerEncoding::Pkcs1,
            params,
            message,
            signature,
        ),
    }
}

fn verify_with_facade(
    suite: Suite,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), crypto_core::CryptoError> {
    match suite {
        Suite::Pkcs1v15(hash) => reallyme_crypto::rsa::verify_rsa_pkcs1v15(
            public_key,
            RsaPublicKeyDerEncoding::Pkcs1,
            hash,
            message,
            signature,
        ),
        Suite::Pss(params) => reallyme_crypto::rsa::verify_rsa_pss(
            public_key,
            RsaPublicKeyDerEncoding::Pkcs1,
            params,
            message,
            signature,
        ),
    }
}

fn rsa_result(
    algorithm: SignatureAlgorithm,
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
) -> Option<crypto_proto::generated::proto::reallyme::crypto::v1::CryptoVerificationResult> {
    let response = process_response(CryptoOperation::RsaVerify(Box::new(rsa_request(
        algorithm, public_key, message, signature,
    ))));
    match response.outcome {
        Some(CryptoOperationOutcome::Result(result)) => match result.result {
            Some(CryptoOperationResultBranch::RsaVerify(verification)) => Some(*verification),
            _ => None,
        },
        _ => None,
    }
}

fn rsa_request(
    algorithm: SignatureAlgorithm,
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
) -> CryptoRsaVerifyRequest {
    CryptoRsaVerifyRequest {
        algorithm: MessageField::some(signature_identifier(algorithm)),
        signature,
        message,
        public_key_der: public_key,
        public_key_encoding: EnumValue::from(ProtoKeyEncoding::RSA_PUBLIC_KEY_DER_ENCODING_PKCS1),
        __buffa_unknown_fields: Default::default(),
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

fn result_algorithm(
    result: &crypto_proto::generated::proto::reallyme::crypto::v1::CryptoVerificationResult,
) -> Option<SignatureAlgorithm> {
    result
        .algorithm
        .as_option()
        .and_then(|identifier| identifier.algorithm.as_ref())
        .and_then(|algorithm| match algorithm {
            ProtoAlgorithmBranch::Signature(value) => value.as_known(),
            _ => None,
        })
}

fn nested_error_reason(
    result: &crypto_proto::generated::proto::reallyme::crypto::v1::CryptoVerificationResult,
) -> Option<CryptoErrorReason> {
    result
        .error
        .as_option()
        .and_then(|error| error.error.as_ref())
        .and_then(error_reason)
}

fn response_error_reason(response: &CryptoOperationResponse) -> Option<CryptoErrorReason> {
    match response.outcome.as_ref() {
        Some(CryptoOperationOutcome::Error(error)) => error.error.as_ref().and_then(error_reason),
        _ => None,
    }
}

fn error_reason(error: &CryptoErrorBranch) -> Option<CryptoErrorReason> {
    match error {
        CryptoErrorBranch::Primitive(error) => error.reason.as_known(),
        CryptoErrorBranch::Provider(error) => error.reason.as_known(),
        CryptoErrorBranch::Backend(error) => error.reason.as_known(),
    }
}

fn signature_identifier(algorithm: SignatureAlgorithm) -> CryptoAlgorithmIdentifier {
    CryptoAlgorithmIdentifier {
        algorithm: Some(ProtoAlgorithmBranch::Signature(EnumValue::from(algorithm))),
        __buffa_unknown_fields: Default::default(),
    }
}

fn vectors() -> RsaVectors {
    serde_json::from_str(include_str!("../../../vectors/rsa.json"))
        .expect("repository RSA vectors parse")
}

fn decode_url(value: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(value)
        .expect("repository RSA vector base64url decodes")
}
