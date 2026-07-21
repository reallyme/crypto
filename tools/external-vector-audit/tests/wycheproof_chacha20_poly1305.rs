// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Wycheproof ChaCha20-Poly1305 AEAD audit adapter.
//!
//! Vendored via `scripts/vendor_external_vectors.mjs`; ignored by default and
//! executed through the external-vectors audit workflow. Fails closed (the file
//! load errors) when the corpus has not been vendored.

use crypto_chacha20_poly1305::{
    decrypt, encrypt, ChaCha20Poly1305Key, ChaCha20Poly1305Nonce, CiphertextWithTag,
    DecryptRequest, EncryptRequest, CHACHA20_POLY1305_KEY_LENGTH, CHACHA20_POLY1305_NONCE_LENGTH,
};
use external_vector_audit::support::{hex_bytes, load_json, AuditError};
use external_vector_audit::wycheproof::{WycheproofFile, WycheproofResult};
use serde::Deserialize;

const KEY_SIZE_BITS: u32 = 256;
const IV_SIZE_BITS: u32 = 96;
const TAG_SIZE_BITS: u32 = 128;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AeadGroup {
    key_size: u32,
    iv_size: u32,
    tag_size: u32,
    tests: Vec<AeadCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AeadCase {
    key: String,
    iv: String,
    aad: String,
    msg: String,
    ct: String,
    tag: String,
    result: WycheproofResult,
}

#[test]
#[ignore = "vendored Wycheproof corpus; run via the external-vectors audit workflow after vendoring"]
fn wycheproof_chacha20_poly1305_vectors_execute_against_public_api() -> Result<(), AuditError> {
    let file: WycheproofFile<AeadGroup> = load_json("wycheproof/chacha20_poly1305_test.json")?;
    let mut executed = 0usize;
    let mut invalid_nonce_cases = 0usize;

    for group in &file.test_groups {
        if group.key_size != KEY_SIZE_BITS || group.tag_size != TAG_SIZE_BITS {
            continue;
        }
        for case in &group.tests {
            if group.iv_size == IV_SIZE_BITS {
                run_case(case)?;
            } else {
                assert_invalid_nonce_rejected(case, group.iv_size)?;
                invalid_nonce_cases = invalid_nonce_cases
                    .checked_add(1)
                    .ok_or(AuditError::NoExecutableVectors)?;
            }
            executed = executed
                .checked_add(1)
                .ok_or(AuditError::NoExecutableVectors)?;
        }
    }

    if executed == 0 || invalid_nonce_cases == 0 {
        return Err(AuditError::NoExecutableVectors);
    }
    Ok(())
}

fn assert_invalid_nonce_rejected(case: &AeadCase, declared_iv_size: u32) -> Result<(), AuditError> {
    if case.result != WycheproofResult::Invalid {
        return Err(AuditError::Shape);
    }

    let iv_bytes = hex_bytes(&case.iv)?;
    let iv_bits = iv_bytes
        .len()
        .checked_mul(u8::BITS.try_into().map_err(|_| AuditError::Shape)?)
        .ok_or(AuditError::Shape)?;
    let iv_bits = u32::try_from(iv_bits).map_err(|_| AuditError::Shape)?;
    if iv_bits != declared_iv_size || iv_bytes.len() == CHACHA20_POLY1305_NONCE_LENGTH {
        return Err(AuditError::Shape);
    }
    if ChaCha20Poly1305Nonce::from_slice(&iv_bytes).is_ok() {
        return Err(AuditError::Mismatch);
    }
    Ok(())
}

fn run_case(case: &AeadCase) -> Result<(), AuditError> {
    // `acceptable` cases are legal-but-discouraged; a hardened AEAD may accept
    // or reject them, so we do not assert a direction.
    if case.result == WycheproofResult::Acceptable {
        return Ok(());
    }

    let key_bytes = hex_bytes(&case.key)?;
    let iv_bytes = hex_bytes(&case.iv)?;
    if key_bytes.len() != CHACHA20_POLY1305_KEY_LENGTH
        || iv_bytes.len() != CHACHA20_POLY1305_NONCE_LENGTH
    {
        return Err(AuditError::Shape);
    }
    let key = ChaCha20Poly1305Key::from_slice(&key_bytes).map_err(|_| AuditError::Shape)?;
    let nonce = ChaCha20Poly1305Nonce::from_slice(&iv_bytes).map_err(|_| AuditError::Shape)?;
    let aad = hex_bytes(&case.aad)?;
    let msg = hex_bytes(&case.msg)?;

    let mut expected = hex_bytes(&case.ct)?;
    expected.extend_from_slice(&hex_bytes(&case.tag)?);
    let ciphertext =
        CiphertextWithTag::from_vec(expected.clone()).map_err(|_| AuditError::Shape)?;

    let decrypt_request = DecryptRequest {
        key: &key,
        nonce,
        aad: &aad,
        ciphertext: &ciphertext,
    };

    match case.result {
        WycheproofResult::Valid => {
            // Encryption must reproduce ciphertext || tag exactly.
            let sealed = encrypt(&EncryptRequest {
                key: &key,
                nonce,
                aad: &aad,
                plaintext: &msg,
            })
            .map_err(|_| AuditError::Mismatch)?;
            if sealed.as_bytes() != expected.as_slice() {
                return Err(AuditError::Mismatch);
            }
            // Decryption must recover the plaintext.
            let opened = decrypt(&decrypt_request).map_err(|_| AuditError::Mismatch)?;
            if opened != msg {
                return Err(AuditError::Mismatch);
            }
            Ok(())
        }
        WycheproofResult::Invalid => {
            // A forged or corrupted ciphertext/tag must be rejected.
            if decrypt(&decrypt_request).is_ok() {
                return Err(AuditError::Mismatch);
            }
            Ok(())
        }
        WycheproofResult::Acceptable => Ok(()),
    }
}
