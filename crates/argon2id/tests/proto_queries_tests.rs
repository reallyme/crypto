// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::expect_used)]
#![cfg(feature = "proto")]

use buffa::{EnumValue, Message, MessageField};
use crypto_argon2id::proto_queries::{resolve_budget, resolve_platform, select_mobile_unlock};
use crypto_argon2id::{
    resolve_mobile_profile_for_unlock, resolve_profile_params_for_platform,
    resolve_profile_params_with_caps, Argon2Caps, Argon2KdfVersion, Argon2PlatformClass,
};
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    Argon2ParamsProfile, Argon2PlatformClass as ProtoPlatform, Argon2idKdfVersion,
    CryptoArgon2BudgetFitRequest, CryptoArgon2MobileUnlockRequest,
    CryptoArgon2PlatformResolveRequest, CryptoArgon2idProfileIdentifier,
};

fn profile(version: Argon2idKdfVersion) -> CryptoArgon2idProfileIdentifier {
    CryptoArgon2idProfileIdentifier {
        kdf_version: version.into(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn budget(version: Argon2idKdfVersion, caps: Argon2Caps) -> CryptoArgon2BudgetFitRequest {
    CryptoArgon2BudgetFitRequest {
        profile: MessageField::some(profile(version)),
        memory_limit_kib: Some(caps.mem_cap_kib),
        time_cost_limit: Some(caps.time_cost_cap),
        lanes_limit: Some(caps.lanes_cap),
        __buffa_unknown_fields: Default::default(),
    }
}

fn known_versions() -> [(Argon2idKdfVersion, u32); 2] {
    [
        (Argon2idKdfVersion::ARGON2ID_KDF_VERSION_V1, 1),
        (Argon2idKdfVersion::ARGON2ID_KDF_VERSION_V2, 2),
    ]
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn platform_query_matches_both_existing_profiles_and_platforms() {
    for (version, number) in known_versions() {
        for native_platform in [
            Argon2PlatformClass::MobileModern,
            Argon2PlatformClass::DesktopModern,
        ] {
            let request = CryptoArgon2PlatformResolveRequest {
                profile: MessageField::some(profile(version)),
                platform: ProtoPlatform::from(native_platform).into(),
                __buffa_unknown_fields: Default::default(),
            };
            let expected = resolve_profile_params_for_platform(number, native_platform)
                .map(Argon2ParamsProfile::from);
            assert_eq!(resolve_platform(&request), expected);
        }
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn budget_query_preserves_arbitrary_u32_admission_without_cost_overrides() {
    for (version, number) in known_versions() {
        let fixed = resolve_profile_params_for_platform(number, Argon2PlatformClass::DesktopModern)
            .expect("reviewed profile fits");
        // The query domain includes zero and values beyond all platform caps.
        // These values cannot become caller-chosen Argon2 execution costs.
        for memory in [
            0,
            fixed.mem_kib - 1,
            fixed.mem_kib,
            fixed.mem_kib + 1,
            u32::MAX,
        ] {
            for time in [
                0,
                fixed.time_cost - 1,
                fixed.time_cost,
                fixed.time_cost + 1,
                u32::MAX,
            ] {
                for lanes in [0, fixed.lanes - 1, fixed.lanes, fixed.lanes + 1, u32::MAX] {
                    let caps = Argon2Caps {
                        mem_cap_kib: memory,
                        time_cost_cap: time,
                        lanes_cap: lanes,
                    };
                    let expected = resolve_profile_params_with_caps(number, caps)
                        .map(Argon2ParamsProfile::from);
                    let actual = resolve_budget(&budget(version, caps));
                    assert_eq!(actual, expected);
                    if let Ok(params) = actual {
                        assert_eq!(
                            (params.mem_kib, params.time_cost, params.lanes),
                            (fixed.mem_kib, fixed.time_cost, fixed.lanes)
                        );
                    }
                }
            }
        }
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn explicit_zero_budget_is_present_on_wire_and_absence_is_rejected() {
    let caps = Argon2Caps {
        mem_cap_kib: 0,
        time_cost_cap: 0,
        lanes_cap: 0,
    };
    let request = budget(Argon2idKdfVersion::ARGON2ID_KDF_VERSION_V1, caps);
    let decoded = CryptoArgon2BudgetFitRequest::decode_from_slice(&request.encode_to_vec())
        .expect("query wire roundtrip");
    assert_eq!(
        (
            decoded.memory_limit_kib,
            decoded.time_cost_limit,
            decoded.lanes_limit
        ),
        (Some(0), Some(0), Some(0))
    );
    assert_eq!(
        resolve_budget(&decoded),
        Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    for missing in 0..3 {
        let mut request = budget(
            Argon2idKdfVersion::ARGON2ID_KDF_VERSION_V1,
            Argon2Caps {
                mem_cap_kib: u32::MAX,
                time_cost_cap: u32::MAX,
                lanes_cap: u32::MAX,
            },
        );
        match missing {
            0 => request.memory_limit_kib = None,
            1 => request.time_cost_limit = None,
            _ => request.lanes_limit = None,
        }
        assert_eq!(
            resolve_budget(&request),
            Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn mobile_unlock_query_reuses_existing_selection_and_owner_contracts() {
    fn require_cleanup<T: zeroize::ZeroizeOnDrop>() {}
    require_cleanup::<CryptoArgon2PlatformResolveRequest>();
    require_cleanup::<CryptoArgon2BudgetFitRequest>();
    require_cleanup::<CryptoArgon2MobileUnlockRequest>();
    let actual = select_mobile_unlock(&CryptoArgon2MobileUnlockRequest::default())
        .expect("fixed mobile selection");
    assert_eq!(
        Argon2KdfVersion::try_from(&actual).expect("known profile"),
        resolve_mobile_profile_for_unlock().expect("native mobile selection")
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn queries_reject_missing_unknown_identities_platforms_and_modifiers(
) -> Result<(), buffa::DecodeError> {
    let mut request = CryptoArgon2PlatformResolveRequest {
        profile: MessageField::none(),
        platform: ProtoPlatform::ARGON2_PLATFORM_CLASS_MOBILE_MODERN.into(),
        __buffa_unknown_fields: Default::default(),
    };
    assert_eq!(
        resolve_platform(&request),
        Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    for unknown in [0, -1, 1, 99, i32::MAX] {
        request.profile = MessageField::some(profile(Argon2idKdfVersion::ARGON2ID_KDF_VERSION_V1));
        request.platform = EnumValue::from(unknown);
        assert_eq!(
            resolve_platform(&request),
            Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
        );
    }
    for unknown in [0, -1, 3, i32::MAX] {
        let identity = CryptoArgon2idProfileIdentifier {
            kdf_version: EnumValue::from(unknown),
            __buffa_unknown_fields: Default::default(),
        };
        request.profile = MessageField::some(identity);
        request.platform = ProtoPlatform::ARGON2_PLATFORM_CLASS_MOBILE_MODERN.into();
        assert_eq!(
            resolve_platform(&request),
            Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
        );
    }
    let mut identity = CryptoArgon2idProfileIdentifier::from(Argon2KdfVersion::V1);
    identity.merge_from_slice(&[0xa0, 0x06, 1])?;
    request.profile = MessageField::some(identity);
    assert_eq!(
        resolve_platform(&request),
        Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    );
    request.profile = MessageField::some(profile(Argon2idKdfVersion::ARGON2ID_KDF_VERSION_V1));
    request.merge_from_slice(&[0xa0, 0x06, 1])?;
    assert_eq!(
        resolve_platform(&request),
        Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );

    let mut request = budget(
        Argon2idKdfVersion::ARGON2ID_KDF_VERSION_V1,
        Argon2Caps {
            mem_cap_kib: u32::MAX,
            time_cost_cap: u32::MAX,
            lanes_cap: u32::MAX,
        },
    );
    request.profile = MessageField::none();
    assert_eq!(
        resolve_budget(&request),
        Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    let mut identity = CryptoArgon2idProfileIdentifier::from(Argon2KdfVersion::V1);
    identity.merge_from_slice(&[0xa0, 0x06, 1])?;
    request.profile = MessageField::some(identity);
    assert_eq!(
        resolve_budget(&request),
        Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    );
    request.profile = MessageField::some(profile(Argon2idKdfVersion::ARGON2ID_KDF_VERSION_V1));
    request.merge_from_slice(&[0xa0, 0x06, 1])?;
    assert_eq!(
        resolve_budget(&request),
        Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    let mut mobile = CryptoArgon2MobileUnlockRequest::default();
    mobile.merge_from_slice(&[0xa0, 0x06, 1])?;
    assert_eq!(
        select_mobile_unlock(&mobile),
        Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    Ok(())
}
