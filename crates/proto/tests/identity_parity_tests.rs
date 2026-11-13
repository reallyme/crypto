// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generated/native identity parity without a second list of schema values.

#![cfg(feature = "generated")]
#![allow(missing_docs)]
#![allow(clippy::expect_used)]

use buffa::{EnumValue, Enumeration, Message};
use crypto_core::{
    AeadAlgorithm as CoreAead, Algorithm as CoreKey, HashAlgorithm as CoreHash,
    KeyWrapAlgorithm as CoreKeyWrap, MacAlgorithm as CoreMac,
};
use reallyme_crypto_proto::convert::UnsupportedProtoAlgorithm;
use reallyme_crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as Identity, AeadAlgorithm,
    CryptoAlgorithmIdentifier, CryptoErrorReason, CryptoKeyAlgorithmIdentifier, HashAlgorithm,
    KeyAlgorithm, KeyWrapAlgorithm, MacAlgorithm, SignatureAlgorithm,
};

#[test]
fn every_generated_key_identity_has_exact_native_parity() {
    for value in KeyAlgorithm::values() {
        let identifier = key_identifier((*value).into());
        let converted = CoreKey::try_from(&identifier);
        if value.to_i32() == 0 {
            assert_eq!(converted, Err(UnsupportedProtoAlgorithm));
        } else {
            let native = converted.expect("every generated key identity has a native key type");
            assert_eq!(KeyAlgorithm::from(native), *value);
        }
    }
    for unknown in [i32::MIN, -1, 999_999, i32::MAX] {
        assert_eq!(
            CoreKey::try_from(&key_identifier(unknown.into())),
            Err(UnsupportedProtoAlgorithm)
        );
    }
}

#[test]
fn every_generated_aead_identity_has_exact_native_parity() {
    assert_parity::<AeadAlgorithm, CoreAead>(Identity::Aead, |value| Ok(value.into()));
}

#[test]
fn every_generated_hash_identity_has_exact_native_parity() {
    assert_parity::<HashAlgorithm, CoreHash>(Identity::Hash, |value| Ok(value.into()));
}

#[test]
fn every_generated_mac_identity_has_exact_native_parity() {
    assert_parity::<MacAlgorithm, CoreMac>(Identity::Mac, |value| Ok(value.into()));
}

#[test]
fn every_generated_key_wrap_identity_has_exact_native_parity() {
    assert_parity::<KeyWrapAlgorithm, CoreKeyWrap>(Identity::KeyWrap, KeyWrapAlgorithm::try_from);
}

#[test]
fn missing_and_wrong_family_identities_are_rejected() {
    let missing = CryptoAlgorithmIdentifier::default();
    assert_eq!(CoreKey::try_from(&missing), Err(UnsupportedProtoAlgorithm));
    assert_eq!(CoreAead::try_from(&missing), Err(UnsupportedProtoAlgorithm));
    assert_eq!(CoreHash::try_from(&missing), Err(UnsupportedProtoAlgorithm));
    assert_eq!(CoreMac::try_from(&missing), Err(UnsupportedProtoAlgorithm));
    assert_eq!(
        CoreKeyWrap::try_from(&missing),
        Err(UnsupportedProtoAlgorithm)
    );

    let key = identifier(Identity::Signature(
        SignatureAlgorithm::SIGNATURE_ALGORITHM_ECDSA_P256_SHA256.into(),
    ));
    assert_eq!(CoreAead::try_from(&key), Err(UnsupportedProtoAlgorithm));
    assert_eq!(CoreHash::try_from(&key), Err(UnsupportedProtoAlgorithm));
    assert_eq!(CoreMac::try_from(&key), Err(UnsupportedProtoAlgorithm));
    assert_eq!(CoreKeyWrap::try_from(&key), Err(UnsupportedProtoAlgorithm));
}

#[test]
fn unknown_fields_do_not_bypass_identity_validation() -> Result<(), buffa::DecodeError> {
    let mut value = key_identifier(KeyAlgorithm::KEY_ALGORITHM_P256.into());
    // Unknown field 100 must not become an ignored policy or suite modifier.
    value.merge_from_slice(&[0xa0, 0x06, 0x01])?;
    assert_eq!(CoreKey::try_from(&value), Err(UnsupportedProtoAlgorithm));
    Ok(())
}

#[test]
fn fixed_signature_suites_do_not_become_generic_key_identities() {
    for suite in [
        SignatureAlgorithm::SIGNATURE_ALGORITHM_BIP340_SCHNORR_SECP256K1_SHA256,
        SignatureAlgorithm::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA256,
        SignatureAlgorithm::SIGNATURE_ALGORITHM_RSA_PSS_SHA256_MGF1_SHA256,
    ] {
        let value = identifier(Identity::Signature(suite.into()));
        assert_eq!(CoreKey::try_from(&value), Err(UnsupportedProtoAlgorithm));
        // The published convenience conversion has identical rejection.
        assert_eq!(CoreKey::try_from(suite), Err(UnsupportedProtoAlgorithm));
    }
}

#[test]
fn separate_key_metadata_does_not_change_old_suite_tags() {
    let key = key_identifier(KeyAlgorithm::KEY_ALGORITHM_P256.into());
    assert_eq!(key.encode_to_vec(), [0x08, 0xc8, 0x01]);
    let signature = identifier(Identity::Signature(
        SignatureAlgorithm::SIGNATURE_ALGORITHM_ECDSA_P256_SHA256.into(),
    ));
    assert_eq!(signature.encode_to_vec(), [0x08, 0xc8, 0x01]);
}

#[test]
fn all_identity_rejections_keep_the_canonical_schema_reason() {
    assert_eq!(
        UnsupportedProtoAlgorithm.reason(),
        CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM,
    );
}

#[test]
fn key_metadata_clears_retained_unknown_storage_on_drop() {
    fn require_cleanup<T: zeroize::ZeroizeOnDrop>() {}
    require_cleanup::<CryptoKeyAlgorithmIdentifier>();
}

fn assert_parity<P, N>(
    branch: fn(EnumValue<P>) -> Identity,
    reverse: impl Fn(N) -> Result<P, UnsupportedProtoAlgorithm>,
) where
    P: Enumeration + PartialEq + core::fmt::Debug + 'static,
    for<'a> N: TryFrom<&'a CryptoAlgorithmIdentifier, Error = UnsupportedProtoAlgorithm>,
    N: PartialEq + core::fmt::Debug,
{
    for value in P::values() {
        let request = identifier(branch(EnumValue::from(*value)));
        let result = N::try_from(&request);
        if value.to_i32() == 0 {
            assert_eq!(result, Err(UnsupportedProtoAlgorithm));
        } else {
            let native = result.expect("every nonzero generated identity has a native value");
            assert_eq!(reverse(native), Ok(*value));
        }
    }
    for unknown in [i32::MIN, -1, 999_999, i32::MAX] {
        let value = EnumValue::<P>::from(unknown);
        assert!(value.as_known().is_none());
        let request = identifier(branch(value));
        assert_eq!(N::try_from(&request), Err(UnsupportedProtoAlgorithm));
    }
}

fn identifier(algorithm: Identity) -> CryptoAlgorithmIdentifier {
    CryptoAlgorithmIdentifier {
        algorithm: Some(algorithm),
        __buffa_unknown_fields: Default::default(),
    }
}

fn key_identifier(algorithm: EnumValue<KeyAlgorithm>) -> CryptoKeyAlgorithmIdentifier {
    CryptoKeyAlgorithmIdentifier {
        algorithm,
        __buffa_unknown_fields: Default::default(),
    }
}

#[test]
fn legacy_operation_identities_reject_unspecified_and_unknown_values() {
    use reallyme_crypto_proto::generated::proto::reallyme::crypto::v1::{
        KemAlgorithm, KeyAgreementAlgorithm,
    };
    for invalid in [0, -1, 999_999, i32::MAX] {
        for value in [
            Identity::Signature(EnumValue::<SignatureAlgorithm>::from(invalid)),
            Identity::KeyAgreement(EnumValue::<KeyAgreementAlgorithm>::from(invalid)),
            Identity::Kem(EnumValue::<KemAlgorithm>::from(invalid)),
        ] {
            assert_eq!(
                CoreKey::try_from(&identifier(value)),
                Err(UnsupportedProtoAlgorithm)
            );
        }
    }
}
