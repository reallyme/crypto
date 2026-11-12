// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]
use crypto_core::{CryptoError, HkdfFailureKind, HkdfHash};
use crypto_hkdf::{
    derive, DeriveRequest, DomainTag, HkdfInfo, HkdfInputKeyMaterial, HkdfSalt, HkdfSuite,
};
#[cfg(feature = "sha3")]
use crypto_hkdf::{derive_domain_key_32, DomainKeyPurpose};
use hex_literal::hex;

// RFC 5869 appendix A.1-A.3 are direct extract-and-expand answers. Keeping
// them inline lets the same leaf tests execute on devices without filesystem
// access to the conformance corpus.
// Source: https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rfc5869_sha256_case_1_matches_exact_42_byte_output() -> Result<(), CryptoError> {
    let ikm = HkdfInputKeyMaterial::from_slice(&[0x0b; 22]);
    let salt = HkdfSalt::from_slice(&hex!("000102030405060708090a0b0c"));
    let info = HkdfInfo::from_slice(&hex!("f0f1f2f3f4f5f6f7f8f9"));
    let output = derive::<42>(&DeriveRequest {
        suite: HkdfSuite::Sha2_256,
        ikm: &ikm,
        salt: Some(&salt),
        info: &info,
    })?;
    assert_eq!(
        output.as_bytes(),
        &hex!(
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        )
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rfc5869_sha256_case_2_preserves_long_binary_inputs() -> Result<(), CryptoError> {
    let ikm = HkdfInputKeyMaterial::from_slice(&hex!(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f"
        "303132333435363738393a3b3c3d3e3f"
        "404142434445464748494a4b4c4d4e4f"
    ));
    let salt = HkdfSalt::from_slice(&hex!(
        "606162636465666768696a6b6c6d6e6f"
        "707172737475767778797a7b7c7d7e7f"
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    ));
    let info = HkdfInfo::from_slice(&hex!(
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
        "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    ));
    let output = derive::<82>(&DeriveRequest {
        suite: HkdfSuite::Sha2_256,
        ikm: &ikm,
        salt: Some(&salt),
        info: &info,
    })?;
    assert_eq!(
        output.as_bytes(),
        &hex!(
            "b11e398dc80327a1c8e7f78c596a4934"
            "4f012eda2d4efad8a050cc4c19afa97c"
            "59045a99cac7827271cb41c65e590e09"
            "da3275600c2f09b8367793a9aca3db71"
            "cc30c58179ec3e87c14c01d5c1f3434f"
            "1d87"
        )
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rfc5869_sha256_case_3_accepts_empty_salt_and_info() -> Result<(), CryptoError> {
    let ikm = HkdfInputKeyMaterial::from_slice(&[0x0b; 22]);
    let salt = HkdfSalt::from_slice(&[]);
    let info = HkdfInfo::from_slice(&[]);
    let expected = hex!(
        "8da4e775a563c18f715f802a063c5a31"
        "b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8"
    );
    // An omitted salt has the specified all-zero HMAC-key semantics. Neither
    // representation adds a protocol label or normalizes the supplied info.
    for salt in [Some(&salt), None] {
        let output = derive::<42>(&DeriveRequest {
            suite: HkdfSuite::Sha2_256,
            ikm: &ikm,
            salt,
            info: &info,
        })?;
        assert_eq!(output.as_bytes(), &expected);
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
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

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
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
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
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
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
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
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
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

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
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

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
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

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
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

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
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

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
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
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
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
