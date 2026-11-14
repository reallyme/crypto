// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::expect_used)]
#![cfg(feature = "proto")]
use buffa::{Message, MessageField};
use crypto_concat_kdf::{proto_inputs::ConcatKdfInputs, JwaAlgorithmId};
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm, CryptoAlgorithmIdentifier,
    CryptoJwaConcatKdfSha256DeriveRequest, KdfAlgorithm,
};
use zeroize::Zeroize;
fn request(length: u32) -> CryptoJwaConcatKdfSha256DeriveRequest {
    CryptoJwaConcatKdfSha256DeriveRequest {
        algorithm: MessageField::some(CryptoAlgorithmIdentifier {
            algorithm: Some(Algorithm::Kdf(
                KdfAlgorithm::KDF_ALGORITHM_JWA_CONCAT_KDF_SHA256.into(),
            )),
        }),
        shared_secret: vec![0x42; 32].into(),
        algorithm_id: vec![0, 0xff, b'A'].into(),
        party_u_info: vec![0, 0xff].into(),
        party_v_info: vec![0xff, 0].into(),
        output_length: length,
    }
}
fn parity<const N: usize>() {
    let wire = request(u32::try_from(N).expect("fixture length"));
    let inputs = ConcatKdfInputs::<N>::try_from(&wire).expect("exact native width");
    let expected = crypto_concat_kdf::derive_jwa_concat_kdf_sha256::<N>(&inputs.as_request())
        .expect("native leaf");
    assert_eq!(
        inputs.derive().expect("adapter").as_bytes(),
        expected.as_bytes()
    );
    assert_eq!(
        inputs
            .derive_result()
            .expect("result")
            .derived_key
            .as_slice(),
        expected.as_bytes()
    );
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn standalone_adapter_supports_widths_outside_fixed_root_dispatch() {
    fn require_cleanup<T: zeroize::ZeroizeOnDrop>() {}
    require_cleanup::<ConcatKdfInputs<17>>();
    require_cleanup::<JwaAlgorithmId>();
    parity::<1>();
    parity::<15>();
    parity::<17>();
    parity::<31>();
    parity::<33>();
    parity::<65>();
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rfc7518_vector_and_exact_party_bytes_are_retained() {
    let mut wire = request(16);
    wire.shared_secret = vec![
        158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49, 110,
        163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
    ]
    .into();
    wire.algorithm_id = b"A128GCM".to_vec().into();
    wire.party_u_info = b"Alice".to_vec().into();
    wire.party_v_info = b"Bob".to_vec().into();
    let inputs = ConcatKdfInputs::<16>::try_from(&wire).expect("RFC input");
    assert_eq!(
        inputs.derive().expect("derive").as_bytes(),
        &[86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26]
    );
    let first = ConcatKdfInputs::<17>::try_from(&request(17))
        .expect("binary")
        .derive()
        .expect("derive");
    let mut changed = request(17);
    assert!(changed.party_u_info.push(0).is_ok());
    let second = ConcatKdfInputs::<17>::try_from(&changed)
        .expect("changed binary")
        .derive()
        .expect("derive");
    assert_ne!(first.as_bytes(), second.as_bytes());
    changed.party_u_info.clear();
    changed.party_v_info.clear();
    assert!(ConcatKdfInputs::<17>::try_from(&changed).is_ok());
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn adapter_rejects_width_disagreement_zero_and_invalid_native_fields() {
    assert_eq!(
        ConcatKdfInputs::<17>::try_from(&request(16)).err(),
        Some(CryptoError::PRIMITIVE_INVALID_LENGTH)
    );
    assert_eq!(
        ConcatKdfInputs::<0>::try_from(&request(0)).err(),
        Some(CryptoError::PRIMITIVE_INVALID_LENGTH)
    );
    let mut wire = request(17);
    wire.shared_secret.clear();
    assert_eq!(
        ConcatKdfInputs::<17>::try_from(&wire).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PASSWORD)
    );
    let mut wire = request(17);
    wire.algorithm_id.clear();
    assert_eq!(
        ConcatKdfInputs::<17>::try_from(&wire).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    let mut wire = request(17);
    wire.party_u_info = vec![0; crypto_concat_kdf::JWA_CONCAT_KDF_MAX_INFO_LENGTH + 1].into();
    assert_eq!(
        ConcatKdfInputs::<17>::try_from(&wire).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn adapter_rejects_wrong_unknown_and_modified_algorithm_identity() -> Result<(), buffa::DecodeError>
{
    let mut wire = request(17);
    wire.algorithm = MessageField::none();
    assert_eq!(
        ConcatKdfInputs::<17>::try_from(&wire).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    for identity in [
        KdfAlgorithm::KDF_ALGORITHM_UNSPECIFIED.into(),
        KdfAlgorithm::KDF_ALGORITHM_ARGON2ID.into(),
        buffa::EnumValue::from(i32::MAX),
    ] {
        let mut wire = request(17);
        wire.algorithm = MessageField::some(CryptoAlgorithmIdentifier {
            algorithm: Some(Algorithm::Kdf(identity)),
        });
        assert_eq!(
            ConcatKdfInputs::<17>::try_from(&wire).err(),
            Some(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
        );
    }
    let mut wire = request(17);
    let id = CryptoAlgorithmIdentifier {
        algorithm: Some(Algorithm::Kdf(
            KdfAlgorithm::KDF_ALGORITHM_JWA_CONCAT_KDF_SHA256.into(),
        )),
    };
    let mut modified_child = id.encode_to_vec();
    modified_child.extend_from_slice(&[0xa0, 0x06, 1]);
    wire.algorithm = MessageField::some(id);
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
        crypto_proto::wire::decode_protobuf::<CryptoJwaConcatKdfSha256DeriveRequest>(&modified)
            .is_err()
    );
    let wire = request(17);
    assert_unknown_wire(&wire, &[0xa0, 0x06, 1]);
    Ok(())
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn cloned_public_algorithm_identifiers_keep_independent_clearing_owners() {
    let mut original = JwaAlgorithmId::from_slice(b"A128GCM").expect("algorithm");
    let retained = original.clone();
    original.zeroize();
    assert_ne!(original, retained);
    // Existing public metadata formatting remains available after adding cleanup.
    assert!(format!("{retained:?}").contains("JwaAlgorithmId"));
}

fn assert_unknown_wire<M: buffa::Message>(message: &M, modifier: &[u8]) {
    let mut wire = message.encode_to_vec();
    wire.extend_from_slice(modifier);
    assert!(matches!(crypto_proto::wire::decode_protobuf::<M>(&wire),
        Err(error) if error == crypto_proto::wire::CryptoWireError::malformed_protobuf()));
}
