// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{EnumValue, Enumeration, MessageField};
use core::mem::ManuallyDrop;
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as Identity,
    __buffa::oneof::crypto_error::Error as ErrorBranch,
    __buffa::oneof::crypto_operation_response::Outcome, AeadAlgorithm, CryptoAeadOpenRequest,
    CryptoAlgorithmFamily, CryptoAlgorithmIdentifier, CryptoErrorReason, CryptoOperationRequest,
    CryptoOperationResponse, CryptoSignatureSignRequest, KeyAgreementAlgorithm, SignatureAlgorithm,
};
use crypto_proto::wire::CryptoWireError;

use super::super::request_signature::process_signature_sign_request;
use super::super::request_symmetric::process_aead_open_request;
use super::process_decoded_request;
use crate::operations::OperationFamily;

fn assert_provider_error(response: &CryptoOperationResponse, reason: CryptoErrorReason) {
    let Some(Outcome::Error(error)) = response.outcome.as_ref() else {
        kani::assert(false, "rejected request must return the error outcome");
        return;
    };
    assert!(
        matches!(error.error.as_ref(), Some(ErrorBranch::Provider(error))
        if error.reason.as_known() == Some(reason))
    );
}

fn assert_primitive_error(response: &CryptoOperationResponse, reason: CryptoErrorReason) {
    let Some(Outcome::Error(error)) = response.outcome.as_ref() else {
        kani::assert(false, "rejected request must return the error outcome");
        return;
    };
    assert!(
        matches!(error.error.as_ref(), Some(ErrorBranch::Primitive(error))
        if error.reason.as_known() == Some(reason))
    );
}

fn unexpected_dispatch(_request: CryptoOperationRequest) -> CryptoOperationResponse {
    kani::assert(false, "a rejected operation selector reached dispatch");
    CryptoOperationResponse { outcome: None }
}

#[kani::proof]
#[kani::unwind(14)]
#[kani::stub(super::super::request::process_operation_request, unexpected_dispatch)]
fn malformed_binary_request_does_not_dispatch() {
    let response = ManuallyDrop::new(process_decoded_request(Err(
        CryptoWireError::malformed_protobuf(),
    )));
    assert_primitive_error(
        &response,
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF,
    );
}

#[kani::proof]
#[kani::unwind(14)]
fn disabled_aead_open_operation_rejects_any_aead_id() {
    let request = ManuallyDrop::new(CryptoAeadOpenRequest {
        algorithm: MessageField::some(CryptoAlgorithmIdentifier {
            algorithm: Some(Identity::Aead(EnumValue::<AeadAlgorithm>::from(
                kani::any::<i32>(),
            ))),
        }),
        key: Vec::new().into(),
        nonce: Vec::new().into(),
        aad: Vec::new().into(),
        ciphertext_with_tag: Vec::new().into(),
    });
    let response = ManuallyDrop::new(process_aead_open_request(&request));
    assert_provider_error(
        &response,
        CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM,
    );
}

fn ed25519_sign(_secret: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    assert_eq!(message, [1]);
    kani::cover!(true, "eligible signing identity reaches the provider");
    Err(CryptoError::PROVIDER_ACCESS_DENIED)
}

#[kani::proof]
#[kani::unwind(18)]
#[kani::stub(<crypto_dispatch::algorithms::ed25519::Ed25519Algo as crypto_dispatch::traits::SignatureAlgorithm>::sign, ed25519_sign)]
fn signature_gate_requires_the_enabled_id_in_the_signature_family() {
    let id = kani::any::<i32>();
    let signature_family = kani::any::<bool>();
    let is_ed25519_signature = id == SignatureAlgorithm::Ed25519.to_i32();
    let request = ManuallyDrop::new(CryptoSignatureSignRequest {
        algorithm: MessageField::some(CryptoAlgorithmIdentifier {
            algorithm: Some(if signature_family {
                Identity::Signature(EnumValue::from(id))
            } else {
                Identity::KeyAgreement(EnumValue::<KeyAgreementAlgorithm>::from(id))
            }),
        }),
        // Mark the one accepted selector so the stub can detect an unexpected
        // invocation even if its return value is discarded by the handler.
        message: vec![u8::from(signature_family && is_ed25519_signature)].into(),
        secret_key: Vec::new().into(),
    });
    let response = ManuallyDrop::new(process_signature_sign_request(&request));
    if signature_family {
        // A distinctive error from the stub proves the selected branch really
        // called the provider. An accidental call also changes the rejected result.
        let reason = if is_ed25519_signature {
            CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_ACCESS_DENIED
        } else {
            CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM
        };
        assert_provider_error(&response, reason);
    } else {
        assert_primitive_error(
            &response,
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER,
        );
    }
}

#[kani::proof]
fn operation_family_ids_are_total_and_reject_unspecified() {
    let id = kani::any::<i32>();
    let family = OperationFamily::try_from(EnumValue::<CryptoAlgorithmFamily>::from(id));
    if matches!(CryptoAlgorithmFamily::from_i32(id), Some(value)
        if value != CryptoAlgorithmFamily::CRYPTO_ALGORITHM_FAMILY_UNSPECIFIED)
    {
        assert_eq!(
            family.map(|value| CryptoAlgorithmFamily::from(value).to_i32()),
            Ok(id)
        );
    } else {
        assert_eq!(family, Err(CryptoError::PRIMITIVE_INVALID_PARAMETER));
    }
}
