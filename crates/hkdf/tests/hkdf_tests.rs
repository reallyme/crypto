// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
use crypto_core::{CryptoError, HkdfFailureKind, HkdfHash};
use crypto_hkdf::{
    derive, DeriveRequest, DomainTag, HkdfInfo, HkdfInputKeyMaterial, HkdfSalt, HkdfSuite,
};
#[cfg(feature = "sha3")]
use crypto_hkdf::{derive_domain_key_32, DomainKeyPurpose};
#[cfg(feature = "sha3")]
use hex_literal::hex;

#[test]
fn derive_is_deterministic_with_same_inputs() {
    let ikm = HkdfInputKeyMaterial::from_slice(b"root key material");
    let salt = HkdfSalt::from_slice(b"domain salt");
    let info = HkdfInfo::from_slice(b"crypto/aad/v1");

    let request = DeriveRequest {
        suite: HkdfSuite::Sha2_256,
        ikm: &ikm,
        salt: Some(&salt),
        info: &info,
    };

    let first = derive::<32>(&request);
    let second = derive::<32>(&request);

    assert!(first.is_ok());
    assert!(second.is_ok());

    let first_bytes = match first {
        Ok(value) => *value.as_bytes(),
        Err(_) => return,
    };
    let second_bytes = match second {
        Ok(value) => *value.as_bytes(),
        Err(_) => return,
    };

    assert_eq!(first_bytes, second_bytes);
}

#[test]
fn derive_changes_when_info_changes() {
    let ikm = HkdfInputKeyMaterial::from_slice(b"root key material");
    let salt = HkdfSalt::from_slice(b"domain salt");
    let info_a = HkdfInfo::from_slice(b"crypto/key");
    let info_b = HkdfInfo::from_slice(b"crypto/context");

    let key_a = derive::<32>(&DeriveRequest {
        suite: HkdfSuite::Sha2_256,
        ikm: &ikm,
        salt: Some(&salt),
        info: &info_a,
    });
    let key_b = derive::<32>(&DeriveRequest {
        suite: HkdfSuite::Sha2_256,
        ikm: &ikm,
        salt: Some(&salt),
        info: &info_b,
    });

    assert!(key_a.is_ok());
    assert!(key_b.is_ok());

    let key_a_bytes = match key_a {
        Ok(value) => *value.as_bytes(),
        Err(_) => return,
    };
    let key_b_bytes = match key_b {
        Ok(value) => *value.as_bytes(),
        Err(_) => return,
    };

    assert_ne!(key_a_bytes, key_b_bytes);
}

#[cfg(feature = "sha3")]
#[test]
fn sha2_and_sha3_suites_produce_distinct_outputs() {
    let ikm = HkdfInputKeyMaterial::from_slice(b"root key material");
    let salt = HkdfSalt::from_slice(b"domain salt");
    let info = HkdfInfo::from_slice(b"context");

    let sha2 = derive::<32>(&DeriveRequest {
        suite: HkdfSuite::Sha2_256,
        ikm: &ikm,
        salt: Some(&salt),
        info: &info,
    });
    let sha3 = derive::<32>(&DeriveRequest {
        suite: HkdfSuite::Sha3_256,
        ikm: &ikm,
        salt: Some(&salt),
        info: &info,
    });

    assert!(sha2.is_ok());
    assert!(sha3.is_ok());

    let sha2_bytes = match sha2 {
        Ok(value) => *value.as_bytes(),
        Err(_) => return,
    };
    let sha3_bytes = match sha3 {
        Ok(value) => *value.as_bytes(),
        Err(_) => return,
    };

    assert_ne!(sha2_bytes, sha3_bytes);
}

#[cfg(feature = "sha3")]
#[test]
fn sha3_handles_long_ikm_and_multi_block_output() {
    let ikm = HkdfInputKeyMaterial::from_slice(&[0x0b; 200]);
    let salt = HkdfSalt::from_slice(&[0x0c; 20]);
    let info_bytes = [0x0d; 80];
    let info = HkdfInfo::from_slice(&info_bytes);

    let output = derive::<96>(&DeriveRequest {
        suite: HkdfSuite::Sha3_256,
        ikm: &ikm,
        salt: Some(&salt),
        info: &info,
    });
    assert!(output.is_ok());
    let output = match output {
        Ok(value) => value,
        Err(_) => return,
    };

    assert_eq!(
        output.as_bytes(),
        &hex!(
            "2f8ac9951b4f0124ff412ca234f8bae921e9bb0dc78d9b56ede2a3b83916b113"
            "28f124c9be81d6bdb5182d59cb1446966b5d620100946481ac2b72561b5f3371"
            "6f5d31d84ec55dddc8b977b61d202dcf6ea1720df79d81b5ab9dbde165802539"
        )
    );
}

#[cfg(not(feature = "sha3"))]
#[test]
fn sha3_suite_is_explicitly_unsupported_without_sha3_feature() {
    let ikm = HkdfInputKeyMaterial::from_slice(b"root key material");
    let salt = HkdfSalt::from_slice(b"domain salt");
    let info = HkdfInfo::from_slice(b"context");

    let result = derive::<32>(&DeriveRequest {
        suite: HkdfSuite::Sha3_256,
        ikm: &ikm,
        salt: Some(&salt),
        info: &info,
    });

    assert!(matches!(result, Err(CryptoError::Unsupported)));
}

#[test]
fn reject_zero_output_length() {
    let ikm = HkdfInputKeyMaterial::from_slice(b"root key material");
    let info = HkdfInfo::from_slice(b"context");

    let result = derive::<0>(&DeriveRequest {
        suite: HkdfSuite::Sha2_256,
        ikm: &ikm,
        salt: None,
        info: &info,
    });

    assert!(matches!(
        result,
        Err(CryptoError::Hkdf {
            hash: HkdfHash::Sha2_256,
            kind: HkdfFailureKind::InvalidOutputLength,
        })
    ));
}

#[test]
fn reject_empty_ikm() {
    let ikm = HkdfInputKeyMaterial::from_slice(b"");
    let info = HkdfInfo::from_slice(b"context");

    let result = derive::<32>(&DeriveRequest {
        suite: HkdfSuite::Sha2_256,
        ikm: &ikm,
        salt: None,
        info: &info,
    });

    assert!(matches!(
        result,
        Err(CryptoError::Hkdf {
            hash: HkdfHash::Sha2_256,
            kind: HkdfFailureKind::InvalidIkmLength,
        })
    ));
}

#[test]
fn reject_output_length_above_hkdf_limit() {
    let ikm = HkdfInputKeyMaterial::from_slice(b"root key material");
    let info = HkdfInfo::from_slice(b"context");

    let result = derive::<8161>(&DeriveRequest {
        suite: HkdfSuite::Sha2_256,
        ikm: &ikm,
        salt: None,
        info: &info,
    });

    assert!(matches!(
        result,
        Err(CryptoError::Hkdf {
            hash: HkdfHash::Sha2_256,
            kind: HkdfFailureKind::ExpandFailed,
        })
    ));
}

#[test]
fn domain_tag_validation_rejects_invalid_tags() {
    let too_long = DomainTag::from_slice(&[b'a'; 49]);
    assert!(matches!(
        too_long,
        Err(CryptoError::Hkdf {
            hash: HkdfHash::Sha3_256,
            kind: HkdfFailureKind::InvalidDomainTagLength,
        })
    ));

    let invalid_char = DomainTag::from_slice(b"crypto/Key");
    assert!(matches!(
        invalid_char,
        Err(CryptoError::Hkdf {
            hash: HkdfHash::Sha3_256,
            kind: HkdfFailureKind::InvalidDomainTagByte,
        })
    ));
}

#[test]
fn sensitive_context_debug_output_is_redacted() {
    let info = HkdfInfo::from_slice(b"tenant/account/context");
    let domain_tag = match DomainTag::from_slice(b"tenant/account") {
        Ok(value) => value,
        Err(_) => return,
    };

    assert_eq!(format!("{info:?}"), "HkdfInfo(<redacted>)");
    assert_eq!(format!("{domain_tag:?}"), "DomainTag(<redacted>)");
}

#[cfg(feature = "sha3")]
#[test]
fn strict_domain_derivation_is_domain_and_purpose_separated() {
    let ikm = HkdfInputKeyMaterial::from_slice(b"root key material");
    let salt = HkdfSalt::from_slice(b"domain salt");

    let key_domain_a = derive_domain_key_32(
        &ikm,
        Some(&salt),
        DomainKeyPurpose::AeadContentKey,
        &match DomainTag::from_slice(b"crypto/key") {
            Ok(value) => value,
            Err(_) => return,
        },
    );

    let key_domain_b = derive_domain_key_32(
        &ikm,
        Some(&salt),
        DomainKeyPurpose::AeadContentKey,
        &match DomainTag::from_slice(b"crypto/context") {
            Ok(value) => value,
            Err(_) => return,
        },
    );

    let key_purpose_b = derive_domain_key_32(
        &ikm,
        Some(&salt),
        DomainKeyPurpose::AuthProofKey,
        &match DomainTag::from_slice(b"crypto/key") {
            Ok(value) => value,
            Err(_) => return,
        },
    );

    assert!(key_domain_a.is_ok());
    assert!(key_domain_b.is_ok());
    assert!(key_purpose_b.is_ok());

    let key_domain_a = match key_domain_a {
        Ok(value) => value,
        Err(_) => return,
    };
    let key_domain_b = match key_domain_b {
        Ok(value) => value,
        Err(_) => return,
    };
    let key_purpose_b = match key_purpose_b {
        Ok(value) => value,
        Err(_) => return,
    };

    assert_ne!(key_domain_a.as_bytes(), key_domain_b.as_bytes());
    assert_ne!(key_domain_a.as_bytes(), key_purpose_b.as_bytes());
}
