// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_hpke::{
    open_base, HpkeOpenRequest, HpkeSuite, HPKE_DHKEM_P256_HKDF_SHA256_AES256GCM,
    HPKE_DHKEM_X25519_HKDF_SHA256_CHACHA20POLY1305,
};
use serde_json::Value;

use crate::support::{b64u_to_bytes, field_string, load, object_field, VectorTestError};

#[test]
fn hpke_vector_invariants() -> Result<(), VectorTestError> {
    let vectors = load("hpke.json")?;
    verify_hpke_case(
        object_field(&vectors, "p256_sha256_aes256gcm")?,
        HPKE_DHKEM_P256_HKDF_SHA256_AES256GCM,
        0x0010,
        0x0001,
        0x0002,
        32,
        65,
        65,
    )?;
    verify_hpke_case(
        object_field(&vectors, "x25519_sha256_chacha20poly1305")?,
        HPKE_DHKEM_X25519_HKDF_SHA256_CHACHA20POLY1305,
        0x0020,
        0x0001,
        0x0003,
        32,
        32,
        32,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_hpke_case(
    vector: &Value,
    suite: HpkeSuite,
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
    secret_key_len: usize,
    public_key_len: usize,
    encapsulated_key_len: usize,
) -> Result<(), VectorTestError> {
    if vector.get("kem_id").and_then(Value::as_u64) != Some(u64::from(kem_id))
        || vector.get("kdf_id").and_then(Value::as_u64) != Some(u64::from(kdf_id))
        || vector.get("aead_id").and_then(Value::as_u64) != Some(u64::from(aead_id))
    {
        return Err(VectorTestError::InvalidField);
    }

    let secret_key = b64u_to_bytes(field_string(vector, "recipient_secret_key")?)?;
    let public_key = b64u_to_bytes(field_string(vector, "recipient_public_key")?)?;
    let encapsulated_key = b64u_to_bytes(field_string(vector, "encapsulated_key")?)?;
    let info = b64u_to_bytes(field_string(vector, "info")?)?;
    let aad = b64u_to_bytes(field_string(vector, "aad")?)?;
    let plaintext = b64u_to_bytes(field_string(vector, "plaintext")?)?;
    let ciphertext = b64u_to_bytes(field_string(vector, "ciphertext")?)?;
    let tampered_ciphertext = b64u_to_bytes(field_string(vector, "tampered_ciphertext")?)?;

    assert_eq!(secret_key.len(), secret_key_len);
    assert_eq!(public_key.len(), public_key_len);
    assert_eq!(encapsulated_key.len(), encapsulated_key_len);
    assert_eq!(ciphertext.len(), plaintext.len() + 16);

    let opened = open_base(&HpkeOpenRequest {
        suite,
        encapsulated_key: &encapsulated_key,
        recipient_private_key: &secret_key,
        info: &info,
        aad: &aad,
        ciphertext: &ciphertext,
    })
    .map_err(|_| VectorTestError::HpkeOperation)?;
    if opened.plaintext.as_slice() != plaintext {
        return Err(VectorTestError::HpkeMismatch);
    }

    if open_base(&HpkeOpenRequest {
        suite,
        encapsulated_key: &encapsulated_key,
        recipient_private_key: &secret_key,
        info: &info,
        aad: &aad,
        ciphertext: &tampered_ciphertext,
    })
    .is_ok()
    {
        return Err(VectorTestError::HpkeMismatch);
    }

    Ok(())
}
