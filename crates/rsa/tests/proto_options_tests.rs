// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::expect_used)]
#![cfg(feature = "proto")]
use buffa::{Enumeration, Message};
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{CryptoRsaPssParams, RsaHashAlgorithm};
use crypto_rsa::RsaPssParams;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn pss_preserves_independent_hashes_and_explicit_zero_salt() {
    for message in RsaHashAlgorithm::values()
        .iter()
        .filter(|value| value.to_i32() != 0)
    {
        for mgf in RsaHashAlgorithm::values()
            .iter()
            .filter(|value| value.to_i32() != 0)
        {
            for salt in [0, 1, 32, u32::MAX] {
                let wire = CryptoRsaPssParams {
                    message_hash: (*message).into(),
                    mgf1_hash: (*mgf).into(),
                    salt_length: Some(salt),
                    __buffa_unknown_fields: Default::default(),
                };
                let native =
                    RsaPssParams::try_from(&wire).expect("existing PSS parameter identities");
                let returned = CryptoRsaPssParams::try_from(&native).expect("representable salt");
                assert_eq!(returned.message_hash, wire.message_hash);
                assert_eq!(returned.mgf1_hash, wire.mgf1_hash);
                assert_eq!(returned.salt_length, Some(salt));
            }
        }
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn pss_rejects_missing_salt_and_unknown_hashes_or_modifiers() -> Result<(), buffa::DecodeError> {
    let mut wire = CryptoRsaPssParams {
        message_hash: RsaHashAlgorithm::RSA_HASH_ALGORITHM_SHA256.into(),
        mgf1_hash: RsaHashAlgorithm::RSA_HASH_ALGORITHM_SHA384.into(),
        salt_length: None,
        __buffa_unknown_fields: Default::default(),
    };
    assert_eq!(
        RsaPssParams::try_from(&wire),
        Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    wire.salt_length = Some(0);
    for unknown in [0, -1, 99, i32::MAX] {
        wire.message_hash = unknown.into();
        assert_eq!(
            RsaPssParams::try_from(&wire),
            Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
        );
    }
    wire.message_hash = RsaHashAlgorithm::RSA_HASH_ALGORITHM_SHA256.into();
    wire.merge_from_slice(&[0xa0, 0x06, 0x01])?;
    assert_eq!(
        RsaPssParams::try_from(&wire),
        Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    Ok(())
}
#[cfg(target_pointer_width = "64")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn pss_rejects_native_salt_length_outside_u32() {
    let native = RsaPssParams {
        message_hash: crypto_rsa::RsaHash::Sha256,
        mgf1_hash: crypto_rsa::RsaHash::Sha384,
        salt_len: usize::MAX,
    };
    assert_eq!(
        CryptoRsaPssParams::try_from(&native).err(),
        Some(CryptoError::PRIMITIVE_INVALID_LENGTH)
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn generated_options_owners_clear_retained_storage() {
    fn require_cleanup<T: zeroize::ZeroizeOnDrop>() {}
    require_cleanup::<crypto_proto::generated::proto::reallyme::crypto::v1::CryptoRsaPssParams>();
}
