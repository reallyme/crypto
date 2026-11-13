// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(feature = "proto")]
#![allow(missing_docs, clippy::expect_used)]
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
            __buffa_unknown_fields: Default::default(),
        }),
        shared_secret: vec![0x42; 32],
        algorithm_id: vec![0, 0xff, b'A'],
        party_u_info: vec![0, 0xff],
        party_v_info: vec![0xff, 0],
        output_length: length,
        __buffa_unknown_fields: Default::default(),
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
    ];
    wire.algorithm_id = b"A128GCM".to_vec();
    wire.party_u_info = b"Alice".to_vec();
    wire.party_v_info = b"Bob".to_vec();
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
    changed.party_u_info.push(0);
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
    wire.party_u_info = vec![0; crypto_concat_kdf::JWA_CONCAT_KDF_MAX_INFO_LENGTH + 1];
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
            __buffa_unknown_fields: Default::default(),
        });
        assert_eq!(
            ConcatKdfInputs::<17>::try_from(&wire).err(),
            Some(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
        );
    }
    let mut wire = request(17);
    let mut id = CryptoAlgorithmIdentifier {
        algorithm: Some(Algorithm::Kdf(
            KdfAlgorithm::KDF_ALGORITHM_JWA_CONCAT_KDF_SHA256.into(),
        )),
        __buffa_unknown_fields: Default::default(),
    };
    id.merge_from_slice(&[0xa0, 0x06, 1])?;
    wire.algorithm = MessageField::some(id);
    assert_eq!(
        ConcatKdfInputs::<17>::try_from(&wire).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    let mut wire = request(17);
    wire.merge_from_slice(&[0xa0, 0x06, 1])?;
    assert_eq!(
        ConcatKdfInputs::<17>::try_from(&wire).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
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
