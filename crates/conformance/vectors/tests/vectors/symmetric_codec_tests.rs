// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_aes256_gcm::{
    decrypt, decrypt_aes128_gcm, decrypt_aes192_gcm, encrypt_aes128_gcm, encrypt_aes192_gcm,
    Aes128GcmDecryptRequest, Aes128GcmEncryptRequest, Aes128GcmKey, Aes128GcmNonce,
    Aes192GcmDecryptRequest, Aes192GcmEncryptRequest, Aes192GcmKey, Aes192GcmNonce, Aes256GcmKey,
    Aes256GcmNonce, CiphertextWithTag, DecryptRequest,
};
use crypto_aes256_gcm_siv::{
    decrypt as gcm_siv_decrypt, encrypt as gcm_siv_encrypt, Aes256GcmSivKey, Aes256GcmSivNonce,
    CiphertextWithTag as GcmSivCiphertextWithTag, DecryptRequest as GcmSivDecryptRequest,
    EncryptRequest as GcmSivEncryptRequest,
};
use crypto_aes_kw::{unwrap_key as aes_kw_unwrap_key, wrap_key as aes_kw_wrap_key, Aes256KwKek};
use crypto_argon2id::{
    derive_key as argon2id_derive_key, Argon2Profile, Argon2Salt, Argon2Secret, DeriveKeyRequest,
};
use crypto_chacha20_poly1305::{
    decrypt as chacha_decrypt, decrypt_xchacha20_poly1305, ChaCha20Poly1305Key,
    ChaCha20Poly1305Nonce, CiphertextWithTag as ChaChaCiphertextWithTag,
    DecryptRequest as ChaChaDecryptRequest, XChaCha20Poly1305DecryptRequest,
    XChaCha20Poly1305Nonce,
};
use crypto_concat_kdf::{
    derive_jwa_concat_kdf_sha256, JwaAlgorithmId, JwaConcatKdfRequest, JwaPartyInfo,
    JwaSharedSecret,
};
use crypto_core::MacAlgorithm;
use crypto_hkdf::{
    derive as hkdf_derive, DeriveRequest, HkdfInfo, HkdfInputKeyMaterial, HkdfSalt, HkdfSuite,
};
use crypto_hmac::{authenticate as hmac_authenticate, verify as hmac_verify, HmacKey};
use crypto_pbkdf2::{
    derive_key as derive_pbkdf2_key, Pbkdf2Iterations, Pbkdf2Password, Pbkdf2Prf, Pbkdf2Request,
    Pbkdf2Salt,
};
use crypto_sha2::{digest_sha2_384, digest_sha2_512};
use crypto_sha2_256::digest as sha2_256_digest;
use crypto_sha3::{digest_sha3_224, digest_sha3_384, digest_sha3_512};
use crypto_sha3_256::digest as sha3_256_digest;
use serde_json::Value;

use crate::support::{b64u_to_bytes, field_string, load, object_field, VectorTestError};

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

#[test]
fn aes256kw_vector_wraps_unwraps_and_rejects_tampering() -> Result<(), VectorTestError> {
    let v = load("aes256kw.json")?;
    let kek_bytes = b64u_to_bytes(field_string(&v, "kek")?)?;
    let key_data = b64u_to_bytes(field_string(&v, "key_data")?)?;
    let wrapped_key = b64u_to_bytes(field_string(&v, "wrapped_key")?)?;

    assert_eq!(field_string(&v, "alg")?, "AES-256-KW");
    assert_eq!(kek_bytes.len(), 32);
    assert_eq!(key_data.len(), 32);
    assert_eq!(wrapped_key.len(), 40);

    let kek = Aes256KwKek::from_slice(&kek_bytes).map_err(|_| VectorTestError::AesKw)?;
    let wrapped = aes_kw_wrap_key(&kek, &key_data).map_err(|_| VectorTestError::AesKw)?;
    assert_eq!(wrapped.as_bytes(), wrapped_key);
    let unwrapped = aes_kw_unwrap_key(&kek, &wrapped_key).map_err(|_| VectorTestError::AesKw)?;
    assert_eq!(unwrapped.as_bytes(), key_data);

    let mut tampered = wrapped_key;
    tampered[0] ^= 0x01;
    if aes_kw_unwrap_key(&kek, &tampered).is_ok() {
        return Err(VectorTestError::AesKwTamperAccepted);
    }

    Ok(())
}

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

fn verify_hmac_case(
    v: &Value,
    field_name: &str,
    algorithm: MacAlgorithm,
) -> Result<(), VectorTestError> {
    let case = object_field(v, field_name)?;
    let key_bytes = b64u_to_bytes(field_string(case, "key")?)?;
    let message = b64u_to_bytes(field_string(case, "message")?)?;
    let tag = b64u_to_bytes(field_string(case, "tag")?)?;
    let key = HmacKey::from_slice(&key_bytes).map_err(|_| VectorTestError::HmacKey)?;
    let recomputed = hmac_authenticate(algorithm, &key, &message)
        .map_err(|_| VectorTestError::HmacAuthenticate)?;

    assert_eq!(tag, recomputed.as_bytes());
    hmac_verify(algorithm, &key, &message, &tag).map_err(|_| VectorTestError::HmacVerify)?;

    let mut tampered = tag;
    tampered[0] ^= 0x01;
    if hmac_verify(algorithm, &key, &message, &tampered).is_ok() {
        return Err(VectorTestError::HmacTamperAccepted);
    }

    Ok(())
}

#[test]
fn hmac_vectors_match_workspace_primitives() -> Result<(), VectorTestError> {
    let v = load("hmac.json")?;
    verify_hmac_case(&v, "hmac_sha256", MacAlgorithm::HmacSha256)?;
    verify_hmac_case(&v, "hmac_sha512", MacAlgorithm::HmacSha512)?;
    Ok(())
}

fn verify_pbkdf2_case(v: &Value, field_name: &str, prf: Pbkdf2Prf) -> Result<(), VectorTestError> {
    let case = object_field(v, field_name)?;
    let password_bytes = b64u_to_bytes(field_string(case, "password")?)?;
    let salt_bytes = b64u_to_bytes(field_string(case, "salt")?)?;
    let derived_key = b64u_to_bytes(field_string(case, "derived_key")?)?;
    let iterations = case
        .get("iterations")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(VectorTestError::InvalidField)?;
    let output_len = case
        .get("output_len")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(VectorTestError::InvalidField)?;

    let password =
        Pbkdf2Password::from_slice(&password_bytes, prf).map_err(|_| VectorTestError::Pbkdf2)?;
    let salt = Pbkdf2Salt::from_slice(&salt_bytes, prf).map_err(|_| VectorTestError::Pbkdf2)?;
    let iterations =
        Pbkdf2Iterations::from_u32(iterations, prf).map_err(|_| VectorTestError::Pbkdf2)?;
    let output = derive_pbkdf2_key(&Pbkdf2Request {
        prf,
        password: &password,
        salt: &salt,
        iterations,
        output_len,
    })
    .map_err(|_| VectorTestError::Pbkdf2)?;

    assert_eq!(output.as_bytes(), derived_key);
    Ok(())
}

#[test]
fn pbkdf2_vectors_match_workspace_primitives() -> Result<(), VectorTestError> {
    let v = load("pbkdf2.json")?;
    assert_eq!(
        field_string(object_field(&v, "pbkdf2_hmac_sha256")?, "alg")?,
        "PBKDF2-HMAC-SHA-256"
    );
    assert_eq!(
        field_string(object_field(&v, "pbkdf2_hmac_sha512")?, "alg")?,
        "PBKDF2-HMAC-SHA-512"
    );
    verify_pbkdf2_case(&v, "pbkdf2_hmac_sha256", Pbkdf2Prf::HmacSha256)?;
    verify_pbkdf2_case(&v, "pbkdf2_hmac_sha512", Pbkdf2Prf::HmacSha512)?;
    Ok(())
}

#[test]
fn hkdf_vector_matches_workspace_primitive() -> Result<(), VectorTestError> {
    // RFC 5869 test case 1 (SHA-256, L=42), cross-checked byte-for-byte against
    // the shared vector every lane consumes.
    let v = load("hkdf.json")?;
    assert_eq!(field_string(&v, "alg")?, "HKDF-SHA256");
    assert_eq!(field_string(&v, "hash")?, "SHA-256");

    let ikm_bytes = b64u_to_bytes(field_string(&v, "ikm")?)?;
    let salt_bytes = b64u_to_bytes(field_string(&v, "salt")?)?;
    let info_bytes = b64u_to_bytes(field_string(&v, "info")?)?;
    let okm = b64u_to_bytes(field_string(&v, "okm")?)?;
    let output_len = v
        .get("output_len")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(VectorTestError::InvalidField)?;

    // The shared HKDF vector is the RFC 5869 L=42 case; the derive API is
    // const-generic on the output length, so pin it and reject drift.
    if output_len != 42 || okm.len() != 42 {
        return Err(VectorTestError::Hkdf);
    }

    let ikm = HkdfInputKeyMaterial::from_slice(&ikm_bytes);
    let salt = HkdfSalt::from_slice(&salt_bytes);
    let info = HkdfInfo::from_slice(&info_bytes);
    let output = hkdf_derive::<42>(&DeriveRequest {
        suite: HkdfSuite::Sha2_256,
        ikm: &ikm,
        salt: Some(&salt),
        info: &info,
    })
    .map_err(|_| VectorTestError::Hkdf)?;

    assert_eq!(output.as_bytes(), okm.as_slice());
    Ok(())
}

#[test]
fn jwa_concat_kdf_vector_matches_rfc7518_appendix_c() -> Result<(), VectorTestError> {
    let v = load("concat_kdf.json")?;
    assert_eq!(field_string(&v, "alg")?, "JWA-CONCAT-KDF-SHA256");
    assert_eq!(field_string(&v, "profile")?, "ECDH-ES+A128GCM");

    let shared_secret_bytes = b64u_to_bytes(field_string(&v, "shared_secret")?)?;
    let algorithm_id_bytes = b64u_to_bytes(field_string(&v, "algorithm_id")?)?;
    let party_u_info_bytes = b64u_to_bytes(field_string(&v, "party_u_info")?)?;
    let party_v_info_bytes = b64u_to_bytes(field_string(&v, "party_v_info")?)?;
    let derived_key = b64u_to_bytes(field_string(&v, "derived_key")?)?;
    let output_len = v
        .get("output_len")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(VectorTestError::InvalidField)?;

    if output_len != 16 || derived_key.len() != 16 {
        return Err(VectorTestError::ConcatKdf);
    }

    let shared_secret = JwaSharedSecret::from_slice(&shared_secret_bytes)
        .map_err(|_| VectorTestError::ConcatKdf)?;
    let algorithm_id =
        JwaAlgorithmId::from_slice(&algorithm_id_bytes).map_err(|_| VectorTestError::ConcatKdf)?;
    let party_u_info =
        JwaPartyInfo::from_slice(&party_u_info_bytes).map_err(|_| VectorTestError::ConcatKdf)?;
    let party_v_info =
        JwaPartyInfo::from_slice(&party_v_info_bytes).map_err(|_| VectorTestError::ConcatKdf)?;
    let output = derive_jwa_concat_kdf_sha256::<16>(&JwaConcatKdfRequest {
        shared_secret: &shared_secret,
        algorithm_id: &algorithm_id,
        party_u_info: &party_u_info,
        party_v_info: &party_v_info,
    })
    .map_err(|_| VectorTestError::ConcatKdf)?;

    assert_eq!(output.as_bytes(), derived_key.as_slice());
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

#[test]
fn argon2id_vector_matches_workspace_primitive() -> Result<(), VectorTestError> {
    let v = load("argon2id.json")?;
    assert_eq!(field_string(&v, "alg")?, "Argon2id");
    // The committed vector pins the Argon2id V1 cost profile.
    assert_eq!(
        v.get("kdf_version").and_then(Value::as_u64),
        Some(1),
        "kdf_version"
    );
    assert_eq!(
        v.get("memory_cost_kib").and_then(Value::as_u64),
        Some(262_144),
        "memory_cost_kib"
    );
    assert_eq!(
        v.get("time_cost").and_then(Value::as_u64),
        Some(3),
        "time_cost"
    );
    assert_eq!(
        v.get("parallelism").and_then(Value::as_u64),
        Some(1),
        "parallelism"
    );

    let secret_bytes = b64u_to_bytes(field_string(&v, "secret")?)?;
    let salt_bytes = b64u_to_bytes(field_string(&v, "salt")?)?;
    let derived_key = b64u_to_bytes(field_string(&v, "derived_key")?)?;

    let profile = Argon2Profile::V1;
    let secret =
        Argon2Secret::from_slice(&secret_bytes, profile).map_err(|_| VectorTestError::Argon2id)?;
    let salt =
        Argon2Salt::from_slice(&salt_bytes, profile).map_err(|_| VectorTestError::Argon2id)?;
    let derived = argon2id_derive_key(&DeriveKeyRequest {
        profile,
        secret: &secret,
        salt: &salt,
    })
    .map_err(|_| VectorTestError::Argon2id)?;

    assert_eq!(derived.as_bytes().as_slice(), derived_key.as_slice());
    Ok(())
}

#[test]
fn hash_vectors_match_workspace_primitives() -> Result<(), VectorTestError> {
    let v = load("hashes.json")?;
    let message = b64u_to_bytes(field_string(&v, "message")?)?;
    let sha2 = b64u_to_bytes(field_string(&v, "sha2_256")?)?;
    let sha2_384 = b64u_to_bytes(field_string(&v, "sha2_384")?)?;
    let sha2_512 = b64u_to_bytes(field_string(&v, "sha2_512")?)?;
    let sha3_224 = b64u_to_bytes(field_string(&v, "sha3_224")?)?;
    let sha3 = b64u_to_bytes(field_string(&v, "sha3_256")?)?;
    let sha3_384 = b64u_to_bytes(field_string(&v, "sha3_384")?)?;
    let sha3_512 = b64u_to_bytes(field_string(&v, "sha3_512")?)?;

    assert_eq!(sha2, sha2_256_digest(&message).as_bytes());
    assert_eq!(sha2_384, digest_sha2_384(&message).as_bytes());
    assert_eq!(sha2_512, digest_sha2_512(&message).as_bytes());
    assert_eq!(sha3_224, digest_sha3_224(&message).as_bytes());
    assert_eq!(sha3, sha3_256_digest(&message).as_bytes());
    assert_eq!(sha3_384, digest_sha3_384(&message).as_bytes());
    assert_eq!(sha3_512, digest_sha3_512(&message).as_bytes());
    Ok(())
}
