// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! ACVP AEAD and key-wrap audit adapters.

use crypto_aes256_gcm::{
    decrypt, decrypt_aes128_gcm, decrypt_aes192_gcm, encrypt, encrypt_aes128_gcm,
    encrypt_aes192_gcm, Aes128GcmDecryptRequest, Aes128GcmEncryptRequest, Aes128GcmKey,
    Aes128GcmNonce, Aes192GcmDecryptRequest, Aes192GcmEncryptRequest, Aes192GcmKey, Aes192GcmNonce,
    Aes256GcmKey, Aes256GcmNonce, CiphertextWithTag, DecryptRequest, EncryptRequest,
};
use crypto_aes_kw::{
    unwrap_key_aes128, unwrap_key_aes192, unwrap_key_aes256, wrap_key_aes128, wrap_key_aes192,
    wrap_key_aes256, Aes128KwKek, Aes192KwKek, Aes256KwKek,
};
use external_vector_audit::support::{assert_bytes_eq, hex_bytes, load_json, AuditError};
use serde::Deserialize;

const PRACTICAL_SUBSET_PER_FAMILY: usize = 64;
const AES_GCM_NONCE_BITS: u32 = 96;
const AES_GCM_TAG_BITS: u32 = 128;
const AES_GCM_SIV_PUBLIC_KEY_BITS: u32 = 256;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AesGcmFile {
    test_groups: Vec<AesGcmGroup>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AesGcmGroup {
    direction: AesDirection,
    key_len: u32,
    iv_len: u32,
    tag_len: u32,
    tests: Vec<AesGcmCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AesGcmCase {
    test_passed: bool,
    key: String,
    aad: String,
    iv: String,
    pt: Option<String>,
    ct: String,
    tag: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum AesDirection {
    Encrypt,
    Decrypt,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AesKwFile {
    test_groups: Vec<AesKwGroup>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AesKwGroup {
    direction: AesDirection,
    key_len: u32,
    tests: Vec<AesKwCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AesKwCase {
    test_passed: bool,
    key: String,
    pt: Option<String>,
    ct: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AesGcmSivFile {
    test_groups: Vec<AesGcmSivGroup>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AesGcmSivGroup {
    key_len: u32,
}

#[test]
fn acvp_aes_gcm_vectors_execute_against_public_api() -> Result<(), AuditError> {
    let file: AesGcmFile = load_json("nist-acvp/aead/aes-gcm/internalProjection.json")?;
    let mut executed = 0usize;

    for group in &file.test_groups {
        if group.iv_len != AES_GCM_NONCE_BITS || group.tag_len != AES_GCM_TAG_BITS {
            continue;
        }
        for case in &group.tests {
            execute_aes_gcm_case(group, case)?;
            executed = executed
                .checked_add(1)
                .ok_or(AuditError::NoExecutableVectors)?;
            if executed >= PRACTICAL_SUBSET_PER_FAMILY {
                assert!(executed > 0);
                return Ok(());
            }
        }
    }

    if executed == 0 {
        Err(AuditError::NoExecutableVectors)
    } else {
        Ok(())
    }
}

#[test]
fn acvp_aes_kw_vectors_execute_against_public_api() -> Result<(), AuditError> {
    let file: AesKwFile = load_json("nist-acvp/key-wrap/aes-kw/internalProjection.json")?;
    let mut executed = 0usize;

    for group in &file.test_groups {
        for case in &group.tests {
            execute_aes_kw_case(group, case)?;
            executed = executed
                .checked_add(1)
                .ok_or(AuditError::NoExecutableVectors)?;
            if executed >= PRACTICAL_SUBSET_PER_FAMILY {
                assert!(executed > 0);
                return Ok(());
            }
        }
    }

    if executed == 0 {
        Err(AuditError::NoExecutableVectors)
    } else {
        Ok(())
    }
}

#[test]
fn acvp_aes_gcm_siv_file_has_no_current_public_key_size_vectors() -> Result<(), AuditError> {
    let file: AesGcmSivFile = load_json("nist-acvp/aead/aes-gcm-siv/internalProjection.json")?;
    let has_aes256_vectors = file
        .test_groups
        .iter()
        .any(|group| group.key_len == AES_GCM_SIV_PUBLIC_KEY_BITS);
    if has_aes256_vectors {
        Err(AuditError::Mismatch)
    } else {
        Ok(())
    }
}

fn execute_aes_gcm_case(group: &AesGcmGroup, case: &AesGcmCase) -> Result<(), AuditError> {
    let key = hex_bytes(&case.key)?;
    let nonce = hex_bytes(&case.iv)?;
    let aad = hex_bytes(&case.aad)?;
    let ct = hex_bytes(&case.ct)?;
    let tag = hex_bytes(&case.tag)?;
    let mut ciphertext = ct;
    ciphertext.extend_from_slice(&tag);

    match (&group.direction, group.key_len) {
        (AesDirection::Encrypt, 128) => {
            let plaintext = hex_bytes(case.pt.as_ref().ok_or(AuditError::Shape)?)?;
            let key = Aes128GcmKey::from_slice(&key).map_err(|_| AuditError::Shape)?;
            let nonce = Aes128GcmNonce::from_slice(&nonce).map_err(|_| AuditError::Shape)?;
            let actual = encrypt_aes128_gcm(&Aes128GcmEncryptRequest {
                key: &key,
                nonce,
                aad: &aad,
                plaintext: &plaintext,
            })
            .map_err(|_| AuditError::Mismatch)?;
            assert_bytes_eq(actual.as_bytes(), &ciphertext)
        }
        (AesDirection::Encrypt, 192) => {
            let plaintext = hex_bytes(case.pt.as_ref().ok_or(AuditError::Shape)?)?;
            let key = Aes192GcmKey::from_slice(&key).map_err(|_| AuditError::Shape)?;
            let nonce = Aes192GcmNonce::from_slice(&nonce).map_err(|_| AuditError::Shape)?;
            let actual = encrypt_aes192_gcm(&Aes192GcmEncryptRequest {
                key: &key,
                nonce,
                aad: &aad,
                plaintext: &plaintext,
            })
            .map_err(|_| AuditError::Mismatch)?;
            assert_bytes_eq(actual.as_bytes(), &ciphertext)
        }
        (AesDirection::Encrypt, 256) => {
            let plaintext = hex_bytes(case.pt.as_ref().ok_or(AuditError::Shape)?)?;
            let key = Aes256GcmKey::from_slice(&key).map_err(|_| AuditError::Shape)?;
            let nonce = Aes256GcmNonce::from_slice(&nonce).map_err(|_| AuditError::Shape)?;
            let actual = encrypt(&EncryptRequest {
                key: &key,
                nonce,
                aad: &aad,
                plaintext: &plaintext,
            })
            .map_err(|_| AuditError::Mismatch)?;
            assert_bytes_eq(actual.as_bytes(), &ciphertext)
        }
        (AesDirection::Decrypt, 128) => {
            let key = Aes128GcmKey::from_slice(&key).map_err(|_| AuditError::Shape)?;
            let nonce = Aes128GcmNonce::from_slice(&nonce).map_err(|_| AuditError::Shape)?;
            let ciphertext =
                CiphertextWithTag::from_vec(ciphertext).map_err(|_| AuditError::Shape)?;
            let actual = decrypt_aes128_gcm(&Aes128GcmDecryptRequest {
                key: &key,
                nonce,
                aad: &aad,
                ciphertext: &ciphertext,
            });
            assert_aes_gcm_decrypt_result(case, actual)
        }
        (AesDirection::Decrypt, 192) => {
            let key = Aes192GcmKey::from_slice(&key).map_err(|_| AuditError::Shape)?;
            let nonce = Aes192GcmNonce::from_slice(&nonce).map_err(|_| AuditError::Shape)?;
            let ciphertext =
                CiphertextWithTag::from_vec(ciphertext).map_err(|_| AuditError::Shape)?;
            let actual = decrypt_aes192_gcm(&Aes192GcmDecryptRequest {
                key: &key,
                nonce,
                aad: &aad,
                ciphertext: &ciphertext,
            });
            assert_aes_gcm_decrypt_result(case, actual)
        }
        (AesDirection::Decrypt, 256) => {
            let key = Aes256GcmKey::from_slice(&key).map_err(|_| AuditError::Shape)?;
            let nonce = Aes256GcmNonce::from_slice(&nonce).map_err(|_| AuditError::Shape)?;
            let ciphertext =
                CiphertextWithTag::from_vec(ciphertext).map_err(|_| AuditError::Shape)?;
            let actual = decrypt(&DecryptRequest {
                key: &key,
                nonce,
                aad: &aad,
                ciphertext: &ciphertext,
            });
            assert_aes_gcm_decrypt_result(case, actual)
        }
        (_, _) => Err(AuditError::UnsupportedBoundary),
    }
}

fn assert_aes_gcm_decrypt_result(
    case: &AesGcmCase,
    actual: Result<Vec<u8>, crypto_core::CryptoError>,
) -> Result<(), AuditError> {
    if case.test_passed {
        let plaintext = hex_bytes(case.pt.as_ref().ok_or(AuditError::Shape)?)?;
        assert_bytes_eq(&actual.map_err(|_| AuditError::Mismatch)?, &plaintext)
    } else if actual.is_err() {
        Ok(())
    } else {
        Err(AuditError::Mismatch)
    }
}

fn execute_aes_kw_case(group: &AesKwGroup, case: &AesKwCase) -> Result<(), AuditError> {
    let key = hex_bytes(&case.key)?;
    let ct = hex_bytes(&case.ct)?;

    match (&group.direction, group.key_len) {
        (AesDirection::Encrypt, 128) => {
            let key = Aes128KwKek::from_slice(&key).map_err(|_| AuditError::Shape)?;
            let pt = hex_bytes(case.pt.as_ref().ok_or(AuditError::Shape)?)?;
            let actual = wrap_key_aes128(&key, &pt).map_err(|_| AuditError::Mismatch)?;
            assert_bytes_eq(actual.as_bytes(), &ct)
        }
        (AesDirection::Encrypt, 192) => {
            let key = Aes192KwKek::from_slice(&key).map_err(|_| AuditError::Shape)?;
            let pt = hex_bytes(case.pt.as_ref().ok_or(AuditError::Shape)?)?;
            let actual = wrap_key_aes192(&key, &pt).map_err(|_| AuditError::Mismatch)?;
            assert_bytes_eq(actual.as_bytes(), &ct)
        }
        (AesDirection::Encrypt, 256) => {
            let key = Aes256KwKek::from_slice(&key).map_err(|_| AuditError::Shape)?;
            let pt = hex_bytes(case.pt.as_ref().ok_or(AuditError::Shape)?)?;
            let actual = wrap_key_aes256(&key, &pt).map_err(|_| AuditError::Mismatch)?;
            assert_bytes_eq(actual.as_bytes(), &ct)
        }
        (AesDirection::Decrypt, 128) => {
            let key = Aes128KwKek::from_slice(&key).map_err(|_| AuditError::Shape)?;
            assert_aes_kw_unwrap_result(case, unwrap_key_aes128(&key, &ct))
        }
        (AesDirection::Decrypt, 192) => {
            let key = Aes192KwKek::from_slice(&key).map_err(|_| AuditError::Shape)?;
            assert_aes_kw_unwrap_result(case, unwrap_key_aes192(&key, &ct))
        }
        (AesDirection::Decrypt, 256) => {
            let key = Aes256KwKek::from_slice(&key).map_err(|_| AuditError::Shape)?;
            assert_aes_kw_unwrap_result(case, unwrap_key_aes256(&key, &ct))
        }
        (_, _) => Err(AuditError::UnsupportedBoundary),
    }
}

fn assert_aes_kw_unwrap_result(
    case: &AesKwCase,
    actual: Result<crypto_aes_kw::AesKwKeyData, crypto_core::CryptoError>,
) -> Result<(), AuditError> {
    if case.test_passed {
        let plaintext = hex_bytes(case.pt.as_ref().ok_or(AuditError::Shape)?)?;
        assert_bytes_eq(
            actual.map_err(|_| AuditError::Mismatch)?.as_bytes(),
            &plaintext,
        )
    } else if actual.is_err() {
        Ok(())
    } else {
        Err(AuditError::Mismatch)
    }
}
