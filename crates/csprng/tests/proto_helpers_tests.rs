// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(feature = "proto")]
#![allow(missing_docs, clippy::expect_used)]
use buffa::Message;
use crypto_core::{CryptoError, RngOutputKind};
use crypto_csprng::proto_helpers::RandomBytesRequest;
use crypto_csprng::{RandomBytes, SecureRandom};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoRandomBytesRequest, CryptoRandomBytesResult, RngOutputKind as ProtoKind,
};
struct Deterministic;
impl SecureRandom for Deterministic {
    fn fill_secure(&mut self, output: &mut [u8], _kind: RngOutputKind) -> Result<(), CryptoError> {
        let mut next = 0_u8;
        for byte in output {
            *byte = next;
            next = next.wrapping_add(1);
        }
        Ok(())
    }
}
struct PartialFailure;
impl SecureRandom for PartialFailure {
    fn fill_secure(&mut self, output: &mut [u8], _kind: RngOutputKind) -> Result<(), CryptoError> {
        if let Some(byte) = output.first_mut() {
            *byte = 0xa5;
        }
        Err(CryptoError::PROVIDER_RANDOMNESS_UNAVAILABLE)
    }
}
fn request(length: u32) -> CryptoRandomBytesRequest {
    CryptoRandomBytesRequest {
        purpose: ProtoKind::RNG_OUTPUT_KIND_GENERIC.into(),
        output_length: length,
        __buffa_unknown_fields: Default::default(),
    }
}
#[test]
fn injected_generation_preserves_kind_length_and_protected_result() {
    let owner = RandomBytesRequest::try_from(&request(4)).expect("request");
    assert_eq!(owner.purpose(), RngOutputKind::Generic);
    assert_eq!(owner.output_length(), 4);
    let generated = owner
        .generate::<4>(&mut Deterministic)
        .expect("injected entropy");
    let wire = owner.to_result(&generated).expect("protected result");
    assert_eq!(wire.value, [0, 1, 2, 3]);
    assert_eq!(
        wire.purpose.as_known(),
        Some(ProtoKind::RNG_OUTPUT_KIND_GENERIC)
    );
    assert_eq!(
        CryptoRandomBytesRequest::try_from(owner)
            .expect("request round trip")
            .output_length,
        4
    );
    let mut output = [0; 4];
    owner
        .fill(&mut Deterministic, &mut output)
        .expect("borrowed fill");
    assert_eq!(output, [0, 1, 2, 3]);
}
#[test]
fn wrong_lengths_zero_generation_and_provider_failures_keep_exact_errors() {
    let owner = RandomBytesRequest::try_from(&request(4)).expect("request");
    assert_eq!(
        owner.generate::<3>(&mut Deterministic).err(),
        Some(CryptoError::PRIMITIVE_INVALID_LENGTH)
    );
    assert_eq!(
        owner.fill(&mut Deterministic, &mut [0; 3]),
        Err(CryptoError::PRIMITIVE_INVALID_LENGTH)
    );
    assert_eq!(
        owner.generate::<4>(&mut PartialFailure).err(),
        Some(CryptoError::PROVIDER_RANDOMNESS_UNAVAILABLE)
    );
    let zero = RandomBytesRequest::try_from(&request(0)).expect("zero fill is representable");
    zero.fill(&mut Deterministic, &mut [])
        .expect("native zero fill");
    assert_eq!(
        zero.generate::<0>(&mut Deterministic).err(),
        Some(CryptoError::PRIMITIVE_INVALID_LENGTH)
    );
}
#[test]
fn random_requests_reject_unknown_purposes_and_modifiers() -> Result<(), buffa::DecodeError> {
    let mut wire = request(4);
    for purpose in [0, -1, 999_999, i32::MAX] {
        wire.purpose = purpose.into();
        assert_eq!(
            RandomBytesRequest::try_from(&wire).err(),
            Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
        );
    }
    wire = request(4);
    wire.merge_from_slice(&[0xa0, 0x06, 0x01])?;
    assert_eq!(
        RandomBytesRequest::try_from(&wire).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    Ok(())
}
#[test]
fn fixed_named_results_keep_purpose_and_clearing_storage() {
    fn cleanup<T: zeroize::ZeroizeOnDrop>() {}
    cleanup::<RandomBytes<4>>();
    cleanup::<CryptoRandomBytesRequest>();
    cleanup::<CryptoRandomBytesResult>();
    let nonce = crypto_csprng::generate_aead_nonce_12(&mut Deterministic).expect("nonce");
    let output = CryptoRandomBytesResult::try_from(&nonce).expect("nonce result");
    assert_eq!(output.value.len(), 12);
    assert_eq!(
        output.purpose.as_known(),
        Some(ProtoKind::RNG_OUTPUT_KIND_AEAD_NONCE_12)
    );
    let key = crypto_csprng::generate_aes256_gcm_key(&mut Deterministic).expect("key");
    let output = CryptoRandomBytesResult::try_from(&key).expect("key result");
    assert_eq!(output.value.len(), 32);
    assert_eq!(
        output.purpose.as_known(),
        Some(ProtoKind::RNG_OUTPUT_KIND_AES_256_GCM_KEY)
    );
}
