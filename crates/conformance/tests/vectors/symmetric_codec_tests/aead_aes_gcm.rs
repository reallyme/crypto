// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#[test]
fn aes256gcm_vector_round_trips() -> Result<(), VectorTestError> {
    let v = load("aes256gcm.json")?;
    let key_bytes = b64u_to_bytes(field_string(&v, "key")?)?;
    let nonce_bytes = b64u_to_bytes(field_string(&v, "nonce")?)?;
    let aad = b64u_to_bytes(field_string(&v, "aad")?)?;
    let plaintext = b64u_to_bytes(field_string(&v, "plaintext")?)?;
    let ciphertext_bytes = b64u_to_bytes(field_string(&v, "ciphertext_with_tag")?)?;

    let key = Aes256GcmKey::from_slice(&key_bytes).map_err(|_| VectorTestError::AesKey)?;
    let nonce = Aes256GcmNonce::from_slice(&nonce_bytes).map_err(|_| VectorTestError::AesNonce)?;
    let ciphertext = CiphertextWithTag::from_vec(ciphertext_bytes.clone())
        .map_err(|_| VectorTestError::AesCiphertext)?;
    let decrypted = decrypt(&DecryptRequest {
        key: &key,
        nonce,
        aad: &aad,
        ciphertext: &ciphertext,
    })
    .map_err(|_| VectorTestError::AesDecrypt)?;

    assert_eq!(decrypted, plaintext);

    // A one-bit flip of the authentication tag must fail authentication.
    let mut tampered_tag = ciphertext_bytes.clone();
    let last = tampered_tag.len() - 1;
    tampered_tag[last] ^= 0x01;
    let tampered_tag =
        CiphertextWithTag::from_vec(tampered_tag).map_err(|_| VectorTestError::AesCiphertext)?;
    if decrypt(&DecryptRequest {
        key: &key,
        nonce,
        aad: &aad,
        ciphertext: &tampered_tag,
    })
    .is_ok()
    {
        return Err(VectorTestError::AesDecrypt);
    }

    // A one-bit flip of the AAD must also break authentication.
    let mut tampered_aad = aad.clone();
    tampered_aad[0] ^= 0x01;
    if decrypt(&DecryptRequest {
        key: &key,
        nonce,
        aad: &tampered_aad,
        ciphertext: &ciphertext,
    })
    .is_ok()
    {
        return Err(VectorTestError::AesDecrypt);
    }

    Ok(())
}

#[test]
fn aes128gcm_vector_round_trips_and_reproduces_ciphertext() -> Result<(), VectorTestError> {
    let v = load("aes128gcm.json")?;
    assert_eq!(field_string(&v, "alg")?, "AES-128-GCM");

    let key_bytes = b64u_to_bytes(field_string(&v, "key")?)?;
    let nonce_bytes = b64u_to_bytes(field_string(&v, "nonce")?)?;
    let aad = b64u_to_bytes(field_string(&v, "aad")?)?;
    let plaintext = b64u_to_bytes(field_string(&v, "plaintext")?)?;
    let ciphertext_bytes = b64u_to_bytes(field_string(&v, "ciphertext_with_tag")?)?;

    let key = Aes128GcmKey::from_slice(&key_bytes).map_err(|_| VectorTestError::AesKey)?;
    let nonce = Aes128GcmNonce::from_slice(&nonce_bytes).map_err(|_| VectorTestError::AesNonce)?;
    let encrypted = encrypt_aes128_gcm(&Aes128GcmEncryptRequest {
        key: &key,
        nonce,
        aad: &aad,
        plaintext: &plaintext,
    })
    .map_err(|_| VectorTestError::AesEncrypt)?;
    assert_eq!(encrypted.as_bytes(), ciphertext_bytes.as_slice());

    let ciphertext = CiphertextWithTag::from_vec(ciphertext_bytes.clone())
        .map_err(|_| VectorTestError::AesCiphertext)?;
    let decrypted = decrypt_aes128_gcm(&Aes128GcmDecryptRequest {
        key: &key,
        nonce,
        aad: &aad,
        ciphertext: &ciphertext,
    })
    .map_err(|_| VectorTestError::AesDecrypt)?;
    assert_eq!(decrypted, plaintext);

    let mut tampered_tag = ciphertext_bytes.clone();
    let last = tampered_tag.len() - 1;
    tampered_tag[last] ^= 0x01;
    let tampered_tag =
        CiphertextWithTag::from_vec(tampered_tag).map_err(|_| VectorTestError::AesCiphertext)?;
    if decrypt_aes128_gcm(&Aes128GcmDecryptRequest {
        key: &key,
        nonce,
        aad: &aad,
        ciphertext: &tampered_tag,
    })
    .is_ok()
    {
        return Err(VectorTestError::AesDecrypt);
    }

    Ok(())
}

#[test]
fn aes192gcm_vector_round_trips_and_reproduces_ciphertext() -> Result<(), VectorTestError> {
    let v = load("aes192gcm.json")?;
    assert_eq!(field_string(&v, "alg")?, "AES-192-GCM");

    let key_bytes = b64u_to_bytes(field_string(&v, "key")?)?;
    let nonce_bytes = b64u_to_bytes(field_string(&v, "nonce")?)?;
    let aad = b64u_to_bytes(field_string(&v, "aad")?)?;
    let plaintext = b64u_to_bytes(field_string(&v, "plaintext")?)?;
    let ciphertext_bytes = b64u_to_bytes(field_string(&v, "ciphertext_with_tag")?)?;

    let key = Aes192GcmKey::from_slice(&key_bytes).map_err(|_| VectorTestError::AesKey)?;
    let nonce = Aes192GcmNonce::from_slice(&nonce_bytes).map_err(|_| VectorTestError::AesNonce)?;
    let encrypted = encrypt_aes192_gcm(&Aes192GcmEncryptRequest {
        key: &key,
        nonce,
        aad: &aad,
        plaintext: &plaintext,
    })
    .map_err(|_| VectorTestError::AesEncrypt)?;
    assert_eq!(encrypted.as_bytes(), ciphertext_bytes.as_slice());

    let ciphertext = CiphertextWithTag::from_vec(ciphertext_bytes.clone())
        .map_err(|_| VectorTestError::AesCiphertext)?;
    let decrypted = decrypt_aes192_gcm(&Aes192GcmDecryptRequest {
        key: &key,
        nonce,
        aad: &aad,
        ciphertext: &ciphertext,
    })
    .map_err(|_| VectorTestError::AesDecrypt)?;
    assert_eq!(decrypted, plaintext);

    let mut tampered_tag = ciphertext_bytes.clone();
    let last = tampered_tag.len() - 1;
    tampered_tag[last] ^= 0x01;
    let tampered_tag =
        CiphertextWithTag::from_vec(tampered_tag).map_err(|_| VectorTestError::AesCiphertext)?;
    if decrypt_aes192_gcm(&Aes192GcmDecryptRequest {
        key: &key,
        nonce,
        aad: &aad,
        ciphertext: &tampered_tag,
    })
    .is_ok()
    {
        return Err(VectorTestError::AesDecrypt);
    }

    Ok(())
}
