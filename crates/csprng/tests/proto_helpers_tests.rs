// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::expect_used)]
#![cfg(feature = "proto")]
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
fn request(length: u64) -> CryptoRandomBytesRequest {
    CryptoRandomBytesRequest {
        purpose: ProtoKind::RNG_OUTPUT_KIND_GENERIC.into(),
        output_length: length,
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
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
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
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
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
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
    assert_unknown_wire(&wire, &[0xa0, 0x06, 0x01]);
    Ok(())
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
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

#[cfg(target_pointer_width = "64")]
struct MustNotBeCalled {
    called: bool,
}
#[cfg(target_pointer_width = "64")]
impl SecureRandom for MustNotBeCalled {
    fn fill_secure(&mut self, _output: &mut [u8], _kind: RngOutputKind) -> Result<(), CryptoError> {
        self.called = true;
        Err(CryptoError::BACKEND_INTERNAL)
    }
}

#[cfg(target_pointer_width = "64")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn native_64bit_lengths_above_uint32_round_trip_without_allocating_outputs() {
    let above_u32 = u64::from(u32::MAX)
        .checked_add(1)
        .expect("uint32 successor");
    for length in [above_u32, u64::MAX] {
        let owner = RandomBytesRequest::try_from(&request(length)).expect("native64-bit metadata");
        assert_eq!(
            owner.output_length(),
            usize::try_from(length).expect("native width")
        );
        let wire = CryptoRandomBytesRequest::try_from(owner).expect("uint64 projection");
        assert_eq!(wire.output_length, length);
        let mut rng = MustNotBeCalled { called: false };
        let mut output = [0xa5];
        assert_eq!(
            owner.fill(&mut rng, &mut output),
            Err(CryptoError::PRIMITIVE_INVALID_LENGTH)
        );
        assert_eq!(
            owner.generate::<1>(&mut rng).err(),
            Some(CryptoError::PRIMITIVE_INVALID_LENGTH)
        );
        assert_eq!(output, [0xa5]);
        assert!(!rng.called);
    }
    assert_eq!(
        request(above_u32).encode_to_vec(),
        [8, 100, 16, 0x80, 0x80, 0x80, 0x80, 0x10]
    );
}

#[cfg(target_pointer_width = "32")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn native_32bit_lengths_reject_uint64_values_outside_usize() {
    let above_u32 = u64::from(u32::MAX)
        .checked_add(1)
        .expect("uint32 successor");
    for length in [above_u32, u64::MAX] {
        assert_eq!(
            RandomBytesRequest::try_from(&request(length)).err(),
            Some(CryptoError::PRIMITIVE_INVALID_LENGTH)
        );
    }
    let admitted = RandomBytesRequest::try_from(&request(u64::from(u32::MAX)))
        .expect("largest32-bit metadata");
    assert_eq!(admitted.output_length(), usize::MAX);
    assert_eq!(
        CryptoRandomBytesRequest::try_from(admitted)
            .expect("uint64 projection")
            .output_length,
        u64::from(u32::MAX)
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn protojson_preserves_exact_uint64_lengths_and_null_default() {
    for length in [4_294_967_296u64, 9_007_199_254_740_993, u64::MAX] {
        for value in [
            serde_json::json!(length.to_string()),
            serde_json::json!(length),
        ] {
            let input =
                serde_json::json!({ "purpose": "RNG_OUTPUT_KIND_GENERIC", "outputLength": value });
            let decoded: CryptoRandomBytesRequest =
                serde_json::from_value(input).expect("exact uint64 metadata");
            assert_eq!(decoded.output_length, length);
            let encoded = serde_json::to_value(&decoded).expect("canonical uint64 JSON");
            assert_eq!(encoded["outputLength"], length.to_string());
        }
    }
    let decoded: CryptoRandomBytesRequest = serde_json::from_value(serde_json::json!({
        "purpose": "RNG_OUTPUT_KIND_GENERIC", "outputLength": null
    }))
    .expect("null to scalar default");
    assert_eq!(decoded.output_length, 0);
    assert_eq!(
        RandomBytesRequest::try_from(&decoded)
            .expect("zero metadata")
            .output_length(),
        0
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn protojson_rejects_negative_and_overflow_lengths() {
    for invalid in [
        "-1",
        "\"-1\"",
        "\"18446744073709551616\"",
        "18446744073709551616",
    ] {
        let document =
            format!(r#"{{"purpose":"RNG_OUTPUT_KIND_GENERIC","outputLength":{invalid}}}"#);
        let error = serde_json::from_str::<CryptoRandomBytesRequest>(&document)
            .expect_err("invalid uint64 metadata");
        assert_eq!(error.classify(), serde_json::error::Category::Data);
    }
}

fn assert_unknown_wire<M: buffa::Message>(message: &M, modifier: &[u8]) {
    let mut wire = message.encode_to_vec();
    wire.extend_from_slice(modifier);
    assert!(matches!(crypto_proto::wire::decode_protobuf::<M>(&wire),
        Err(error) if error == crypto_proto::wire::CryptoWireError::malformed_protobuf()));
}
