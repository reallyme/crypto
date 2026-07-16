// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
use crypto_argon2id::{
    derive_key, derive_key_for_version, resolve_mobile_profile_for_unlock,
    resolve_profile_params_for_platform, resolve_profile_params_with_caps, Argon2Caps,
    Argon2KdfVersion, Argon2PlatformClass, Argon2Profile, Argon2Salt, Argon2Secret,
    DeriveKeyRequest, ARGON2ID_DERIVED_KEY_LENGTH, ARGON2ID_V1_LANES, ARGON2ID_V1_MEMORY_COST_KIB,
    ARGON2ID_V1_TIME_COST, ARGON2ID_V2_LANES, ARGON2ID_V2_MEMORY_COST_KIB, ARGON2ID_V2_TIME_COST,
};
use crypto_core::{CryptoError, KdfAlgorithm, KdfFailureKind, KdfProfile};

#[test]
fn derive_key_is_deterministic_for_same_inputs() {
    let profile = Argon2Profile::V1;
    let secret_result = Argon2Secret::from_slice(b"passphrase", profile);
    assert!(secret_result.is_ok());
    let salt_result = Argon2Salt::from_slice(&[7u8; 16], profile);
    assert!(salt_result.is_ok());

    let secret = match secret_result {
        Ok(value) => value,
        Err(_) => return,
    };
    let salt = match salt_result {
        Ok(value) => value,
        Err(_) => return,
    };

    let request = DeriveKeyRequest {
        profile,
        secret: &secret,
        salt: &salt,
    };

    let first_result = derive_key(&request);
    assert!(first_result.is_ok());
    let second_result = derive_key(&request);
    assert!(second_result.is_ok());

    let first = match first_result {
        Ok(value) => value,
        Err(_) => return,
    };
    let second = match second_result {
        Ok(value) => value,
        Err(_) => return,
    };

    assert_eq!(first.as_bytes(), second.as_bytes());
    assert_eq!(first.as_bytes().len(), ARGON2ID_DERIVED_KEY_LENGTH);
}

#[test]
fn v1_parameter_constants_are_pinned() {
    assert_eq!(ARGON2ID_V1_MEMORY_COST_KIB, 262_144);
    assert_eq!(ARGON2ID_V1_TIME_COST, 3);
    assert_eq!(ARGON2ID_V1_LANES, 1);
}

#[test]
fn derive_key_changes_when_salt_changes() {
    let profile = Argon2Profile::V1;

    let secret_result = Argon2Secret::from_slice(b"passphrase", profile);
    assert!(secret_result.is_ok());
    let secret = match secret_result {
        Ok(value) => value,
        Err(_) => return,
    };

    let salt_a_result = Argon2Salt::from_slice(&[1u8; 16], profile);
    assert!(salt_a_result.is_ok());
    let salt_b_result = Argon2Salt::from_slice(&[2u8; 16], profile);
    assert!(salt_b_result.is_ok());

    let salt_a = match salt_a_result {
        Ok(value) => value,
        Err(_) => return,
    };
    let salt_b = match salt_b_result {
        Ok(value) => value,
        Err(_) => return,
    };

    let key_a_result = derive_key(&DeriveKeyRequest {
        profile,
        secret: &secret,
        salt: &salt_a,
    });
    assert!(key_a_result.is_ok());

    let key_b_result = derive_key(&DeriveKeyRequest {
        profile,
        secret: &secret,
        salt: &salt_b,
    });
    assert!(key_b_result.is_ok());

    let key_a = match key_a_result {
        Ok(value) => value,
        Err(_) => return,
    };
    let key_b = match key_b_result {
        Ok(value) => value,
        Err(_) => return,
    };

    assert_ne!(key_a.as_bytes(), key_b.as_bytes());
}

#[test]
fn rejects_empty_secret() {
    let profile = Argon2Profile::V1;
    let result = Argon2Secret::from_slice(&[], profile);

    assert!(matches!(
        result,
        Err(CryptoError::Kdf {
            algorithm: KdfAlgorithm::Argon2id,
            profile: KdfProfile::Argon2idV1,
            kind: KdfFailureKind::InvalidSecretLength,
        })
    ));
}

#[test]
fn rejects_invalid_salt_lengths() {
    let profile = Argon2Profile::V1;

    for len in [0usize, 1, 15, 33, 64] {
        let result = Argon2Salt::from_slice(&vec![9u8; len], profile);
        assert!(matches!(
            result,
            Err(CryptoError::Kdf {
                algorithm: KdfAlgorithm::Argon2id,
                profile: KdfProfile::Argon2idV1,
                kind: KdfFailureKind::InvalidSaltLength,
            })
        ));
    }
}

#[test]
fn accepts_boundary_salt_lengths() {
    let profile = Argon2Profile::V1;

    let min = Argon2Salt::from_slice(&[1u8; 16], profile);
    assert!(min.is_ok());

    let max = Argon2Salt::from_slice(&[2u8; 32], profile);
    assert!(max.is_ok());
}

#[test]
fn derive_key_changes_when_secret_changes() {
    let profile = Argon2Profile::V1;
    let salt_result = Argon2Salt::from_slice(&[3u8; 16], profile);
    assert!(salt_result.is_ok());
    let salt = match salt_result {
        Ok(value) => value,
        Err(_) => return,
    };

    let secret_a_result = Argon2Secret::from_slice(b"passphrase-a", profile);
    let secret_b_result = Argon2Secret::from_slice(b"passphrase-b", profile);
    assert!(secret_a_result.is_ok());
    assert!(secret_b_result.is_ok());

    let secret_a = match secret_a_result {
        Ok(value) => value,
        Err(_) => return,
    };
    let secret_b = match secret_b_result {
        Ok(value) => value,
        Err(_) => return,
    };

    let key_a_result = derive_key(&DeriveKeyRequest {
        profile,
        secret: &secret_a,
        salt: &salt,
    });
    let key_b_result = derive_key(&DeriveKeyRequest {
        profile,
        secret: &secret_b,
        salt: &salt,
    });

    assert!(key_a_result.is_ok());
    assert!(key_b_result.is_ok());

    let key_a = match key_a_result {
        Ok(value) => value,
        Err(_) => return,
    };
    let key_b = match key_b_result {
        Ok(value) => value,
        Err(_) => return,
    };

    assert_ne!(key_a.as_bytes(), key_b.as_bytes());
}

#[test]
fn accepts_large_secret_input() {
    let profile = Argon2Profile::V1;
    let large_secret = vec![0x5au8; 1024 * 1024];
    let secret_result = Argon2Secret::from_slice(&large_secret, profile);
    assert!(secret_result.is_ok());
    let secret = match secret_result {
        Ok(value) => value,
        Err(_) => return,
    };

    let salt_result = Argon2Salt::from_slice(&[0x33u8; 32], profile);
    assert!(salt_result.is_ok());
    let salt = match salt_result {
        Ok(value) => value,
        Err(_) => return,
    };

    let derived_result = derive_key(&DeriveKeyRequest {
        profile,
        secret: &secret,
        salt: &salt,
    });
    assert!(derived_result.is_ok());

    let derived = match derived_result {
        Ok(value) => value,
        Err(_) => return,
    };

    assert_eq!(derived.as_bytes().len(), ARGON2ID_DERIVED_KEY_LENGTH);
    assert!(derived.as_bytes().iter().any(|byte| *byte != 0));
}

#[test]
fn kdf_version_mapping_is_strict() {
    let valid = Argon2KdfVersion::try_from(1);
    assert!(matches!(valid, Ok(Argon2KdfVersion::V1)));
    let valid_v2 = Argon2KdfVersion::try_from(2);
    assert!(matches!(valid_v2, Ok(Argon2KdfVersion::V2)));

    for invalid in [0u32, 99u32, u32::MAX] {
        let result = Argon2KdfVersion::try_from(invalid);
        assert!(matches!(
            result,
            Err(CryptoError::Kdf {
                algorithm: KdfAlgorithm::Argon2id,
                profile: KdfProfile::Argon2idV1,
                kind: KdfFailureKind::InvalidParams,
            })
        ));
    }
}

#[test]
fn derive_for_kdf_version_enforces_version_and_lengths() {
    let valid = derive_key_for_version(1, b"passphrase", &[7u8; 16]);
    assert!(valid.is_ok());
    let valid_v2 = derive_key_for_version(2, b"passphrase", &[7u8; 16]);
    assert!(valid_v2.is_ok());

    let invalid_version = derive_key_for_version(99, b"passphrase", &[7u8; 16]);
    assert!(matches!(
        invalid_version,
        Err(CryptoError::Kdf {
            algorithm: KdfAlgorithm::Argon2id,
            profile: KdfProfile::Argon2idV1,
            kind: KdfFailureKind::InvalidParams,
        })
    ));

    let invalid_salt = derive_key_for_version(1, b"passphrase", &[7u8; 8]);
    assert!(matches!(
        invalid_salt,
        Err(CryptoError::Kdf {
            algorithm: KdfAlgorithm::Argon2id,
            profile: KdfProfile::Argon2idV1,
            kind: KdfFailureKind::InvalidSaltLength,
        })
    ));
}

#[test]
fn v2_parameter_constants_are_pinned() {
    assert_eq!(ARGON2ID_V2_MEMORY_COST_KIB, 524_288);
    assert_eq!(ARGON2ID_V2_TIME_COST, 3);
    assert_eq!(ARGON2ID_V2_LANES, 1);
}

#[test]
fn profile_resolution_respects_platform_caps() {
    let mobile_v1 = resolve_profile_params_for_platform(1, Argon2PlatformClass::MobileModern);
    let mobile_v2 = resolve_profile_params_for_platform(2, Argon2PlatformClass::MobileModern);
    let desktop_v2 = resolve_profile_params_for_platform(2, Argon2PlatformClass::DesktopModern);

    assert!(mobile_v1.is_ok());
    assert!(mobile_v2.is_ok());
    assert!(desktop_v2.is_ok());

    let restricted_caps = Argon2Caps {
        mem_cap_kib: 32_768,
        time_cost_cap: 3,
        lanes_cap: 1,
    };

    let capped = resolve_profile_params_with_caps(1, restricted_caps);
    assert!(matches!(
        capped,
        Err(CryptoError::Kdf {
            algorithm: KdfAlgorithm::Argon2id,
            profile: KdfProfile::Argon2idV1,
            kind: KdfFailureKind::InvalidParams,
        })
    ));
}

#[test]
fn mobile_unlock_prefers_v2_with_fallback_policy() {
    let selected = resolve_mobile_profile_for_unlock();
    assert!(selected.is_ok());
    assert!(matches!(
        selected,
        Ok(Argon2KdfVersion::V2) | Ok(Argon2KdfVersion::V1)
    ));
}

#[test]
fn derive_for_version_matches_profile_path() {
    let profile_result = {
        let secret_result = Argon2Secret::from_slice(b"passphrase", Argon2Profile::V1);
        let salt_result = Argon2Salt::from_slice(&[7u8; 16], Argon2Profile::V1);
        assert!(secret_result.is_ok());
        assert!(salt_result.is_ok());

        let secret = match secret_result {
            Ok(value) => value,
            Err(_) => return,
        };
        let salt = match salt_result {
            Ok(value) => value,
            Err(_) => return,
        };

        derive_key(&DeriveKeyRequest {
            profile: Argon2Profile::V1,
            secret: &secret,
            salt: &salt,
        })
    };

    let version_result = derive_key_for_version(1, b"passphrase", &[7u8; 16]);

    assert!(profile_result.is_ok());
    assert!(version_result.is_ok());

    let profile_result = match profile_result {
        Ok(value) => value,
        Err(_) => return,
    };
    let version_result = match version_result {
        Ok(value) => value,
        Err(_) => return,
    };

    assert_eq!(profile_result.as_bytes(), version_result.as_bytes());
}

#[test]
fn snapshot_vector_password_and_salt_16() {
    let result = derive_key_for_version(1, b"password", b"somesaltvalue1234");
    assert!(result.is_ok());
    let result = match result {
        Ok(value) => value,
        Err(_) => return,
    };

    assert_eq!(
        hex::encode(result.as_bytes()),
        "53334265f014b5a46f2b3fce4de2c965669b6cd3a4879366385dfc301c234757"
    );
}

#[test]
fn snapshot_vector_client_secret_and_salt_32() {
    let result = derive_key_for_version(
        1,
        b"client-controlled-root-secret-material",
        b"domain-separation-salt-000000001",
    );
    assert!(result.is_ok());
    let result = match result {
        Ok(value) => value,
        Err(_) => return,
    };

    assert_eq!(
        hex::encode(result.as_bytes()),
        "7e4c6ef85993a6829ad0ec14e60a05e7273abfbe60d73a5a6bed513fd1612df7"
    );
}
