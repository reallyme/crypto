// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(all(feature = "proto", any(feature = "native", feature = "wasm")))]
#![allow(missing_docs, clippy::expect_used)]
use buffa::{Message, MessageField};
use crypto_core::CryptoError;
use crypto_pbkdf2::{
    proto_inputs::StandardsDeriveInputs, Pbkdf2Iterations, Pbkdf2Prf, PBKDF2_MAX_ITERATIONS,
    PBKDF2_MAX_OUTPUT_LENGTH, PBKDF2_MODERN_MIN_ITERATIONS,
};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoPbkdf2PrfIdentifier, CryptoPbkdf2StandardsDeriveRequest, MacAlgorithm,
};
use hex_literal::hex;
use zeroize::Zeroize;
fn request(prf: Pbkdf2Prf) -> CryptoPbkdf2StandardsDeriveRequest {
    CryptoPbkdf2StandardsDeriveRequest {
        prf: MessageField::some(CryptoPbkdf2PrfIdentifier::from(prf)),
        password: b"password".to_vec(),
        salt: b"salt".to_vec(),
        iterations: 1,
        output_length: 32,
        __buffa_unknown_fields: Default::default(),
    }
}
#[test]
fn standards_adapter_preserves_both_existing_known_answers() {
    fn require_cleanup<T: zeroize::ZeroizeOnDrop>() {}
    require_cleanup::<StandardsDeriveInputs>();
    require_cleanup::<CryptoPbkdf2StandardsDeriveRequest>();
    let wire = request(Pbkdf2Prf::HmacSha256);
    let inputs = StandardsDeriveInputs::try_from(&wire).expect("standards inputs");
    assert_eq!(
        inputs.derive().expect("derive").as_bytes(),
        &hex!("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
    );
    assert_eq!(
        inputs
            .derive_result()
            .expect("schema result")
            .derived_key
            .as_slice(),
        inputs.derive().expect("native output").as_bytes()
    );
    let mut wire = request(Pbkdf2Prf::HmacSha512);
    wire.output_length = 64;
    let inputs = StandardsDeriveInputs::try_from(&wire).expect("SHA512 inputs");
    assert_eq!(inputs.derive().expect("derive").as_bytes(),&hex!("867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce"));
}
#[test]
fn standards_domain_and_modern_floor_remain_distinct() {
    let prf = Pbkdf2Prf::HmacSha256;
    for iterations in [
        1,
        PBKDF2_MODERN_MIN_ITERATIONS - 1,
        PBKDF2_MODERN_MIN_ITERATIONS,
        PBKDF2_MAX_ITERATIONS,
    ] {
        let mut wire = request(prf);
        wire.iterations = iterations;
        let inputs =
            StandardsDeriveInputs::try_from(&wire).expect("accepted native standard range");
        assert_eq!(inputs.as_request().iterations.as_u32(), iterations);
    }
    assert_eq!(
        Pbkdf2Iterations::from_u32_modern(1, prf),
        Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    let mut wire = request(prf);
    wire.iterations = PBKDF2_MAX_ITERATIONS;
    wire.output_length = u32::try_from(PBKDF2_MAX_OUTPUT_LENGTH).expect("portable length");
    let inputs = StandardsDeriveInputs::try_from(&wire).expect("valid fields");
    assert_eq!(
        inputs.derive().err(),
        Some(CryptoError::PRIMITIVE_RESOURCE_LIMIT_EXCEEDED)
    );
}
#[test]
fn standards_adapter_preserves_binary_inputs_and_live_owner_cleanup() {
    let mut wire = request(Pbkdf2Prf::HmacSha256);
    wire.password = vec![0, 0xff, 0, 0x80];
    wire.salt = vec![0, 1, 0xff, 0];
    let mut inputs = StandardsDeriveInputs::try_from(&wire).expect("binary inputs");
    assert_eq!(inputs.as_request().password.as_bytes(), wire.password);
    assert_eq!(inputs.as_request().salt.as_bytes(), wire.salt);
    inputs.zeroize();
    assert!(inputs.as_request().password.as_bytes().is_empty());
    assert!(inputs.as_request().salt.as_bytes().is_empty());
}
#[test]
fn standards_adapter_rejects_invalid_fields_and_unknown_modifiers() -> Result<(), buffa::DecodeError>
{
    let prf = Pbkdf2Prf::HmacSha256;
    for iterations in [0, u32::MAX] {
        let mut wire = request(prf);
        wire.iterations = iterations;
        assert_eq!(
            StandardsDeriveInputs::try_from(&wire).err(),
            Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
        );
    }
    for length in [0, u32::MAX] {
        let mut wire = request(prf);
        wire.output_length = length;
        assert_eq!(
            StandardsDeriveInputs::try_from(&wire).err(),
            Some(CryptoError::PRIMITIVE_INVALID_LENGTH)
        );
    }
    let mut wire = request(prf);
    wire.prf = MessageField::none();
    assert_eq!(
        StandardsDeriveInputs::try_from(&wire).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    let mut wire = request(prf);
    wire.prf = MessageField::some(CryptoPbkdf2PrfIdentifier {
        prf: MacAlgorithm::MAC_ALGORITHM_UNSPECIFIED.into(),
        __buffa_unknown_fields: Default::default(),
    });
    assert_eq!(
        StandardsDeriveInputs::try_from(&wire).err(),
        Some(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    );
    let mut wire = request(prf);
    let mut id = CryptoPbkdf2PrfIdentifier::from(prf);
    id.merge_from_slice(&[0xa0, 0x06, 1])?;
    wire.prf = MessageField::some(id);
    assert_eq!(
        StandardsDeriveInputs::try_from(&wire).err(),
        Some(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    );
    let mut wire = request(prf);
    wire.merge_from_slice(&[0xa0, 0x06, 1])?;
    assert_eq!(
        StandardsDeriveInputs::try_from(&wire).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    let mut wire = request(prf);
    wire.password.clear();
    assert_eq!(
        StandardsDeriveInputs::try_from(&wire).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PASSWORD)
    );
    let mut wire = request(prf);
    wire.salt.clear();
    assert_eq!(
        StandardsDeriveInputs::try_from(&wire).err(),
        Some(CryptoError::PRIMITIVE_INVALID_SALT)
    );
    Ok(())
}
