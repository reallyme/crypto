// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{EnumValue, Message, MessageField, SizeCache};
// These harnesses inspect the response before drop. The generated clearing
// paths for the response oneof are outside the serialization proof.
use core::mem::ManuallyDrop;
use crypto_core::{AeadAlgorithm, CryptoError};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm,
    __buffa::oneof::crypto_error::Error as ErrorBranch,
    __buffa::oneof::crypto_operation_response::Outcome, AeadAlgorithm as ProtoAead,
    CryptoAeadOpenRequest, CryptoAlgorithmIdentifier, CryptoErrorReason, CryptoHpkeOpenRequest,
    CryptoHpkePskOpenRequest, CryptoOperationResponse, HpkeAeadId, HpkeKdfId, HpkeKemId,
    HpkeSuiteIdentifier,
};
use zeroize::Zeroizing;

use super::super::request_hpke::{process_hpke_open_request, process_hpke_psk_open_request};
use super::super::request_symmetric::process_aead_open_request;
use super::super::{error::error_response, operation_error::map_operation_error};
use crate::hpke::{HpkeOpenOutput, HpkeOpenRequest, HpkePskOpenRequest};

const RECORD_LEN: usize = 17;
// outcome.error (2), error.primitive (1), primitive.reason (1), reason 122.
const AUTHENTICATION_FAILURE: [u8; 6] = [0x12, 0x04, 0x0a, 0x02, 0x08, 122];

#[allow(dead_code)]
fn reject_aead_open(
    algorithm: AeadAlgorithm,
    _key: &[u8],
    _nonce: &[u8],
    _aad: &[u8],
    record: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    assert_eq!(algorithm, AeadAlgorithm::Aes128Gcm);
    assert_eq!(record.len(), RECORD_LEN);
    kani::cover!(true, "binary AEAD request reached the operation owner");
    Err(CryptoError::PRIMITIVE_AUTHENTICATION_FAILED)
}

#[allow(dead_code)]
fn reject_hpke_open(request: &HpkeOpenRequest<'_>) -> Result<HpkeOpenOutput, CryptoError> {
    assert_eq!(request.ciphertext.len(), RECORD_LEN);
    kani::cover!(true, "binary HPKE Base request reached the operation owner");
    Err(CryptoError::PRIMITIVE_AUTHENTICATION_FAILED)
}

#[allow(dead_code)]
fn reject_hpke_psk_open(request: &HpkePskOpenRequest<'_>) -> Result<HpkeOpenOutput, CryptoError> {
    assert_eq!(request.ciphertext.len(), RECORD_LEN);
    kani::cover!(true, "binary HPKE PSK request reached the operation owner");
    Err(CryptoError::PRIMITIVE_AUTHENTICATION_FAILED)
}

fn assert_authentication_failure(response: &CryptoOperationResponse) {
    let Some(Outcome::Error(error)) = response.outcome.as_ref() else {
        kani::assert(false, "failed open must construct an error response");
        return;
    };
    let Some(ErrorBranch::Primitive(error)) = error.error.as_ref() else {
        kani::assert(false, "failed open must construct a primitive error");
        return;
    };
    assert_eq!(
        error.reason.as_known(),
        Some(CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED),
    );
}

#[kani::proof]
#[kani::unwind(10)]
fn authentication_error_serializes_as_the_single_error_field() {
    let response = ManuallyDrop::new(error_response(map_operation_error(
        CryptoError::PRIMITIVE_AUTHENTICATION_FAILED,
    )));
    let mut cache = SizeCache::new();
    let size = response.compute_size(&mut cache);
    let mut output = [0_u8; AUTHENTICATION_FAILURE.len()];
    let mut remaining = output.as_mut_slice();
    response.write_to(&mut cache, &mut remaining);
    assert_eq!(usize::try_from(size), Ok(AUTHENTICATION_FAILURE.len()));
    assert!(remaining.is_empty());
    assert_eq!(output, AUTHENTICATION_FAILURE);
}

fn hpke_algorithm() -> CryptoAlgorithmIdentifier {
    CryptoAlgorithmIdentifier {
        algorithm: Some(Algorithm::HpkeSuite(Box::new(HpkeSuiteIdentifier {
            kem: EnumValue::from(HpkeKemId::HPKE_KEM_ID_DHKEM_P256_HKDF_SHA256),
            kdf: EnumValue::from(HpkeKdfId::HPKE_KDF_ID_HKDF_SHA256),
            aead: EnumValue::from(HpkeAeadId::HPKE_AEAD_ID_AES_256_GCM),
        }))),
    }
}

fn ciphertext() -> Vec<u8> {
    let bytes: [u8; RECORD_LEN] = kani::any();
    Vec::from(bytes)
}

#[kani::proof]
#[kani::unwind(18)]
#[kani::stub(crate::operations::aead::open, reject_aead_open)]
fn binary_aead_authentication_failure_constructs_only_error() {
    let response = ManuallyDrop::new(process_aead_open_request(&CryptoAeadOpenRequest {
        algorithm: MessageField::some(CryptoAlgorithmIdentifier {
            algorithm: Some(Algorithm::Aead(EnumValue::from(
                ProtoAead::AEAD_ALGORITHM_AES_128_GCM,
            ))),
        }),
        key: Vec::new().into(),
        nonce: Vec::new().into(),
        aad: Vec::new().into(),
        ciphertext_with_tag: ciphertext().into(),
    }));
    assert_authentication_failure(&response);
}

#[kani::proof]
#[kani::unwind(18)]
#[kani::stub(crate::operations::hpke::open_base, reject_hpke_open)]
fn binary_hpke_base_authentication_failure_constructs_only_error() {
    let response = ManuallyDrop::new(process_hpke_open_request(&CryptoHpkeOpenRequest {
        algorithm: MessageField::some(hpke_algorithm()),
        recipient_secret_key: Vec::new().into(),
        encapsulated_key: Vec::new().into(),
        info: Vec::new().into(),
        aad: Vec::new().into(),
        ciphertext: ciphertext().into(),
    }));
    assert_authentication_failure(&response);
}

#[kani::proof]
#[kani::unwind(18)]
#[kani::stub(crate::operations::hpke::open_psk, reject_hpke_psk_open)]
fn binary_hpke_psk_authentication_failure_constructs_only_error() {
    let response = ManuallyDrop::new(process_hpke_psk_open_request(&CryptoHpkePskOpenRequest {
        algorithm: MessageField::some(hpke_algorithm()),
        recipient_secret_key: Vec::new().into(),
        encapsulated_key: Vec::new().into(),
        info: Vec::new().into(),
        aad: Vec::new().into(),
        ciphertext: ciphertext().into(),
        psk: Vec::new().into(),
        psk_id: Vec::new().into(),
    }));
    assert_authentication_failure(&response);
}
