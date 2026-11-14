// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::expect_used)]
#![cfg(all(feature = "proto", any(feature = "native", feature = "wasm")))]
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
        password: b"password".to_vec().into(),
        salt: b"salt".to_vec().into(),
        iterations: 1,
        output_length: 32,
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
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
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
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
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn standards_adapter_preserves_binary_inputs_and_live_owner_cleanup() {
    let mut wire = request(Pbkdf2Prf::HmacSha256);
    wire.password = vec![0, 0xff, 0, 0x80].into();
    wire.salt = vec![0, 1, 0xff, 0].into();
    let mut inputs = StandardsDeriveInputs::try_from(&wire).expect("binary inputs");
    assert_eq!(
        inputs.as_request().password.as_bytes(),
        wire.password.as_slice()
    );
    assert_eq!(inputs.as_request().salt.as_bytes(), wire.salt.as_slice());
    inputs.zeroize();
    assert!(inputs.as_request().password.as_bytes().is_empty());
    assert!(inputs.as_request().salt.as_bytes().is_empty());
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
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
    });
    assert_eq!(
        StandardsDeriveInputs::try_from(&wire).err(),
        Some(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    );
    let mut wire = request(prf);
    let id = CryptoPbkdf2PrfIdentifier::from(prf);
    let mut modified_child = id.encode_to_vec();
    modified_child.extend_from_slice(&[0xa0, 0x06, 1]);
    wire.prf = MessageField::some(id);
    let mut modified = wire.encode_to_vec();
    // The duplicate child retains protobuf merge semantics but the unknown
    // modifier must fail admission before any operation uses the message.
    buffa::encoding::encode_varint((1u64 << 3) | 2, &mut modified);
    buffa::encoding::encode_varint(
        u64::try_from(modified_child.len()).unwrap_or(u64::MAX),
        &mut modified,
    );
    modified.extend_from_slice(&modified_child);
    assert!(
        crypto_proto::wire::decode_protobuf::<CryptoPbkdf2StandardsDeriveRequest>(&modified)
            .is_err()
    );
    let wire = request(prf);
    assert_unknown_wire(&wire, &[0xa0, 0x06, 1]);
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

fn assert_unknown_wire<M: buffa::Message>(message: &M, modifier: &[u8]) {
    let mut wire = message.encode_to_vec();
    wire.extend_from_slice(modifier);
    assert!(matches!(crypto_proto::wire::decode_protobuf::<M>(&wire),
        Err(error) if error == crypto_proto::wire::CryptoWireError::malformed_protobuf()));
}
