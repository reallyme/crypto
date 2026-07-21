// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Reduced-feature regression coverage for the complete operation oneof.

#![cfg(all(
    feature = "operation-response",
    not(any(
        feature = "sha2",
        feature = "sha3",
        feature = "aes",
        feature = "aes-gcm-siv",
        feature = "chacha20-poly1305",
        feature = "hmac",
        feature = "aes-kw",
        feature = "kmac",
        feature = "hkdf",
        feature = "pbkdf2",
        feature = "concat-kdf",
        feature = "hpke",
        feature = "ed25519",
        feature = "p256",
        feature = "p384",
        feature = "p521",
        feature = "rsa",
        feature = "secp256k1",
        feature = "x25519",
        feature = "ml-dsa-44",
        feature = "ml-dsa-65",
        feature = "ml-dsa-87",
        feature = "ml-kem-512",
        feature = "ml-kem-768",
        feature = "ml-kem-1024",
        feature = "slh-dsa",
        feature = "x-wing"
    ))
))]
#![allow(clippy::panic)]
#![allow(missing_docs)]

use buffa::Message;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_error::Error as CryptoErrorBranch,
    __buffa::oneof::crypto_operation_request::Operation as CryptoOperation,
    __buffa::oneof::crypto_operation_response::Outcome as CryptoOperationOutcome,
    CryptoErrorReason, CryptoOperationRequest,
};
use crypto_proto::operation_response_wire::decode_operation_response;

#[test]
fn every_declared_branch_fails_closed_without_algorithm_features() {
    let operations = [
        CryptoOperation::Hash(Box::default()),
        CryptoOperation::AeadSeal(Box::default()),
        CryptoOperation::AeadOpen(Box::default()),
        CryptoOperation::MacAuthenticate(Box::default()),
        CryptoOperation::MacVerify(Box::default()),
        CryptoOperation::SignatureGenerateKeyPair(Box::default()),
        CryptoOperation::SignatureDeriveKeyPair(Box::default()),
        CryptoOperation::SignatureSign(Box::default()),
        CryptoOperation::SignatureVerify(Box::default()),
        CryptoOperation::Bip340SchnorrSign(Box::default()),
        CryptoOperation::RsaVerify(Box::default()),
        CryptoOperation::KeyAgreementDeriveSharedSecret(Box::default()),
        CryptoOperation::KeyAgreementDeriveKeyPair(Box::default()),
        CryptoOperation::KemGenerateKeyPair(Box::default()),
        CryptoOperation::KemDeriveKeyPair(Box::default()),
        CryptoOperation::KemEncapsulate(Box::default()),
        CryptoOperation::KemDecapsulate(Box::default()),
        CryptoOperation::Kmac256Derive(Box::default()),
        CryptoOperation::HkdfDerive(Box::default()),
        CryptoOperation::KdfDeriveKey(Box::default()),
        CryptoOperation::JwaConcatKdfSha256Derive(Box::default()),
        CryptoOperation::KeyWrap(Box::default()),
        CryptoOperation::KeyUnwrap(Box::default()),
        CryptoOperation::HpkeSeal(Box::default()),
        CryptoOperation::HpkeOpen(Box::default()),
        CryptoOperation::HpkeGenerateKeyPair(Box::default()),
        CryptoOperation::HpkeDeriveKeyPair(Box::default()),
        CryptoOperation::HpkeSenderExport(Box::default()),
        CryptoOperation::HpkeReceiverExport(Box::default()),
        CryptoOperation::HpkePskSeal(Box::default()),
        CryptoOperation::HpkePskOpen(Box::default()),
    ];

    for operation in operations {
        let request = CryptoOperationRequest {
            operation: Some(operation),
            __buffa_unknown_fields: Default::default(),
        };
        let encoded = request.encode_to_vec();
        let response = reallyme_crypto::operation_contract::process_operation_response(&encoded);
        let decoded = match decode_operation_response(response.as_slice()) {
            Ok(decoded) => decoded,
            Err(_) => panic!("reduced-feature operation response must decode"),
        };
        assert_unsupported_provider(decoded);
    }
}

fn assert_unsupported_provider(
    response: crypto_proto::generated::proto::reallyme::crypto::v1::CryptoOperationResponse,
) {
    let Some(CryptoOperationOutcome::Error(error)) = response.outcome else {
        panic!("unavailable operation family must return an error outcome");
    };
    let Some(CryptoErrorBranch::Provider(provider)) = error.error else {
        panic!("unavailable operation family must return a provider error");
    };
    assert_eq!(
        provider.reason.as_known(),
        Some(CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM)
    );
}
