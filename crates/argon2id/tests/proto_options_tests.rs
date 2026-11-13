// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(feature = "proto")]
#![allow(missing_docs, clippy::expect_used)]
use buffa::{EnumValue, Enumeration, Message, MessageField};
use crypto_argon2id::proto_options::Argon2DeriveInputs;
use crypto_argon2id::{resolve_profile_params_for_platform, Argon2Caps, Argon2PlatformClass};
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    Argon2Caps as ProtoCaps, Argon2ParamsProfile as ProtoParams,
    Argon2PlatformClass as ProtoPlatform, Argon2idKdfVersion, CryptoArgon2FixedDeriveRequest,
    CryptoArgon2idProfileIdentifier,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[test]
fn platform_enum_has_total_parity_and_cost_records_preserve_every_field() {
    for value in ProtoPlatform::values() {
        let native = Argon2PlatformClass::try_from(EnumValue::from(*value));
        if value.to_i32() == 0 {
            assert_eq!(native, Err(CryptoError::PRIMITIVE_INVALID_PARAMETER));
            continue;
        }
        let native = native.expect("known class");
        assert_eq!(ProtoPlatform::from(native), *value);
        let caps = Argon2Caps::for_platform(native);
        let wire = ProtoCaps::from(caps);
        assert_eq!(
            (wire.mem_cap_kib, wire.time_cost_cap, wire.lanes_cap),
            (caps.mem_cap_kib, caps.time_cost_cap, caps.lanes_cap)
        );
        for version in [1, 2] {
            let params = resolve_profile_params_for_platform(version, native)
                .expect("fixed profile fits reviewed caps");
            let wire = ProtoParams::from(params);
            assert_eq!(
                (wire.mem_kib, wire.time_cost, wire.lanes),
                (params.mem_kib, params.time_cost, params.lanes)
            );
        }
    }
    for unknown in [-1, 1, 99, i32::MAX] {
        assert_eq!(
            Argon2PlatformClass::try_from(EnumValue::<ProtoPlatform>::from(unknown)),
            Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
        );
    }
}
#[test]
fn fixed_request_preserves_exact_inputs_and_clearing_owners() {
    fn require_cleanup<T: ZeroizeOnDrop>() {}
    require_cleanup::<Argon2DeriveInputs>();
    let wire = request();
    let mut native = Argon2DeriveInputs::try_from(&wire).expect("fixed request");
    let returned = CryptoArgon2FixedDeriveRequest::from(&native.as_request());
    assert_eq!(returned.secret, wire.secret);
    assert_eq!(returned.salt, wire.salt);
    assert_eq!(
        returned.profile.as_option().expect("profile").kdf_version,
        wire.profile.as_option().expect("profile").kdf_version
    );
    native.zeroize();
    assert!(native.as_request().secret.as_bytes().is_empty());
    assert!(native.as_request().salt.as_bytes().is_empty());
}
#[test]
fn fixed_request_rejects_presence_invalid_inputs_and_unknown_modifiers(
) -> Result<(), buffa::DecodeError> {
    let mut wire = request();
    wire.profile = MessageField::none();
    assert_eq!(
        Argon2DeriveInputs::try_from(&wire).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    wire = request();
    wire.secret.clear();
    assert_eq!(
        Argon2DeriveInputs::try_from(&wire).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PASSWORD)
    );
    wire = request();
    wire.salt.clear();
    assert_eq!(
        Argon2DeriveInputs::try_from(&wire).err(),
        Some(CryptoError::PRIMITIVE_INVALID_SALT)
    );
    wire = request();
    wire.merge_from_slice(&[0xa0, 0x06, 0x01])?;
    assert_eq!(
        Argon2DeriveInputs::try_from(&wire).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    let mut profile = CryptoArgon2idProfileIdentifier {
        kdf_version: Argon2idKdfVersion::ARGON2ID_KDF_VERSION_V1.into(),
        __buffa_unknown_fields: Default::default(),
    };
    profile.merge_from_slice(&[0xa0, 0x06, 0x01])?;
    wire = request();
    wire.profile = MessageField::some(profile);
    assert_eq!(
        Argon2DeriveInputs::try_from(&wire).err(),
        Some(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    );
    Ok(())
}
fn request() -> CryptoArgon2FixedDeriveRequest {
    CryptoArgon2FixedDeriveRequest {
        profile: MessageField::some(CryptoArgon2idProfileIdentifier {
            kdf_version: Argon2idKdfVersion::ARGON2ID_KDF_VERSION_V1.into(),
            __buffa_unknown_fields: Default::default(),
        }),
        secret: vec![0, 0xff, 1],
        salt: vec![0x11; 16],
        __buffa_unknown_fields: Default::default(),
    }
}

#[test]
fn generated_options_owners_clear_retained_storage() {
    fn require_cleanup<T: zeroize::ZeroizeOnDrop>() {}
    require_cleanup::<
        crypto_proto::generated::proto::reallyme::crypto::v1::CryptoArgon2FixedDeriveRequest,
    >();
}
