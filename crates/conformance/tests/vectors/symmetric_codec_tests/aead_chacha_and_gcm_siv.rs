// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

fn chacha_case<'a>(v: &'a Value, field_name: &str) -> Result<&'a Value, VectorTestError> {
    object_field(v, field_name)
}

fn verify_chacha20_poly1305_case(v: &Value) -> Result<(), VectorTestError> {
    let key_bytes = b64u_to_bytes(field_string(v, "key")?)?;
    let nonce_bytes = b64u_to_bytes(field_string(v, "nonce")?)?;
    let aad = b64u_to_bytes(field_string(v, "aad")?)?;
    let plaintext = b64u_to_bytes(field_string(v, "plaintext")?)?;
    let ciphertext_bytes = b64u_to_bytes(field_string(v, "ciphertext_with_tag")?)?;

    let key =
        ChaCha20Poly1305Key::from_slice(&key_bytes).map_err(|_| VectorTestError::ChaChaKey)?;
    let nonce = ChaCha20Poly1305Nonce::from_slice(&nonce_bytes)
        .map_err(|_| VectorTestError::ChaChaNonce)?;
    let ciphertext = ChaChaCiphertextWithTag::from_vec(ciphertext_bytes)
        .map_err(|_| VectorTestError::ChaChaCiphertext)?;
    let decrypted = chacha_decrypt(&ChaChaDecryptRequest {
        key: &key,
        nonce,
        aad: &aad,
        ciphertext: &ciphertext,
    })
    .map_err(|_| VectorTestError::ChaChaDecrypt)?;

    assert_eq!(decrypted, plaintext);
    Ok(())
}

fn verify_xchacha20_poly1305_case(v: &Value) -> Result<(), VectorTestError> {
    let key_bytes = b64u_to_bytes(field_string(v, "key")?)?;
    let nonce_bytes = b64u_to_bytes(field_string(v, "nonce")?)?;
    let aad = b64u_to_bytes(field_string(v, "aad")?)?;
    let plaintext = b64u_to_bytes(field_string(v, "plaintext")?)?;
    let ciphertext_bytes = b64u_to_bytes(field_string(v, "ciphertext_with_tag")?)?;

    let key =
        ChaCha20Poly1305Key::from_slice(&key_bytes).map_err(|_| VectorTestError::ChaChaKey)?;
    let nonce = XChaCha20Poly1305Nonce::from_slice(&nonce_bytes)
        .map_err(|_| VectorTestError::ChaChaNonce)?;
    let ciphertext = ChaChaCiphertextWithTag::from_vec(ciphertext_bytes)
        .map_err(|_| VectorTestError::ChaChaCiphertext)?;
    let decrypted = decrypt_xchacha20_poly1305(&XChaCha20Poly1305DecryptRequest {
        key: &key,
        nonce,
        aad: &aad,
        ciphertext: &ciphertext,
    })
    .map_err(|_| VectorTestError::ChaChaDecrypt)?;

    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[test]
fn chacha20poly1305_vectors_round_trip() -> Result<(), VectorTestError> {
    let v = load("chacha20poly1305.json")?;
    verify_chacha20_poly1305_case(chacha_case(&v, "chacha20_poly1305")?)?;
    verify_xchacha20_poly1305_case(chacha_case(&v, "xchacha20_poly1305")?)?;
    Ok(())
}

#[test]
fn aes256gcmsiv_vector_round_trips_and_rejects_tampering() -> Result<(), VectorTestError> {
    let v = load("aes256gcmsiv.json")?;
    assert_eq!(field_string(&v, "alg")?, "AES-256-GCM-SIV");
    let key_bytes = b64u_to_bytes(field_string(&v, "key")?)?;
    let nonce_bytes = b64u_to_bytes(field_string(&v, "nonce")?)?;
    let aad = b64u_to_bytes(field_string(&v, "aad")?)?;
    let plaintext = b64u_to_bytes(field_string(&v, "plaintext")?)?;
    let ciphertext_bytes = b64u_to_bytes(field_string(&v, "ciphertext_with_tag")?)?;

    let key = Aes256GcmSivKey::from_slice(&key_bytes).map_err(|_| VectorTestError::AesGcmSiv)?;
    let nonce =
        Aes256GcmSivNonce::from_slice(&nonce_bytes).map_err(|_| VectorTestError::AesGcmSiv)?;

    // Re-encrypt deterministically: GCM-SIV is nonce-misuse resistant and
    // deterministic, so the committed ciphertext must reproduce exactly.
    let reencrypted = gcm_siv_encrypt(&GcmSivEncryptRequest {
        key: &key,
        nonce,
        aad: &aad,
        plaintext: &plaintext,
    })
    .map_err(|_| VectorTestError::AesGcmSiv)?;
    assert_eq!(reencrypted.as_bytes(), ciphertext_bytes.as_slice());

    let ciphertext = GcmSivCiphertextWithTag::from_vec(ciphertext_bytes.clone())
        .map_err(|_| VectorTestError::AesGcmSiv)?;
    let decrypted = gcm_siv_decrypt(&GcmSivDecryptRequest {
        key: &key,
        nonce,
        aad: &aad,
        ciphertext: &ciphertext,
    })
    .map_err(|_| VectorTestError::AesGcmSiv)?;
    assert_eq!(decrypted, plaintext);

    // A one-bit tamper of the tag must fail authentication.
    let mut tampered_bytes = ciphertext_bytes;
    let last = tampered_bytes.len() - 1;
    tampered_bytes[last] ^= 0x01;
    let tampered = GcmSivCiphertextWithTag::from_vec(tampered_bytes)
        .map_err(|_| VectorTestError::AesGcmSiv)?;
    if gcm_siv_decrypt(&GcmSivDecryptRequest {
        key: &key,
        nonce,
        aad: &aad,
        ciphertext: &tampered,
    })
    .is_ok()
    {
        return Err(VectorTestError::AesGcmSiv);
    }

    Ok(())
}

#[test]
fn aes256gcmsiv_matches_rfc8452_known_answers() -> Result<(), VectorTestError> {
    // RFC 8452 Appendix C.2 (AEAD_AES_256_GCM_SIV) — authoritative KATs that do
    // not depend on our own generator.
    let key = [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    let nonce_bytes = [
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let key = Aes256GcmSivKey::from_slice(&key).map_err(|_| VectorTestError::AesGcmSiv)?;
    let nonce =
        Aes256GcmSivNonce::from_slice(&nonce_bytes).map_err(|_| VectorTestError::AesGcmSiv)?;

    // Empty plaintext, empty AAD.
    let empty = gcm_siv_encrypt(&GcmSivEncryptRequest {
        key: &key,
        nonce,
        aad: &[],
        plaintext: &[],
    })
    .map_err(|_| VectorTestError::AesGcmSiv)?;
    assert_eq!(
        empty.as_bytes(),
        [
            0x07, 0xf5, 0xf4, 0x16, 0x9b, 0xbf, 0x55, 0xa8, 0x40, 0x0c, 0xd4, 0x7e, 0xa6, 0xfd,
            0x40, 0x0f,
        ]
    );

    // 8-byte plaintext, empty AAD.
    let plaintext = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let sealed = gcm_siv_encrypt(&GcmSivEncryptRequest {
        key: &key,
        nonce,
        aad: &[],
        plaintext: &plaintext,
    })
    .map_err(|_| VectorTestError::AesGcmSiv)?;
    assert_eq!(
        sealed.as_bytes(),
        [
            0xc2, 0xef, 0x32, 0x8e, 0x5c, 0x71, 0xc8, 0x3b, 0x84, 0x31, 0x22, 0x13, 0x0f, 0x73,
            0x64, 0xb7, 0x61, 0xe0, 0xb9, 0x74, 0x27, 0xe3, 0xdf, 0x28,
        ]
    );

    Ok(())
}
