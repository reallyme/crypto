// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

type AesGcmEncryptFn = unsafe extern "C" fn(
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *mut u8,
    usize,
    *mut usize,
) -> status::CryptoStatus;

type AesGcmDecryptFn = unsafe extern "C" fn(
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *mut u8,
    usize,
    *mut usize,
) -> status::CryptoStatus;

fn assert_aes_gcm_ffi_roundtrip_and_tamper(
    encrypt: AesGcmEncryptFn,
    decrypt: AesGcmDecryptFn,
    key: &[u8],
    nonce: &[u8],
    tag_len: usize,
) {
    let aad = b"aad";
    let plaintext = b"ffi plaintext";
    let mut ciphertext = [0u8; 64];
    let mut ciphertext_len = 0usize;

    let encrypt_status = unsafe {
        encrypt(
            key.as_ptr(),
            key.len(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
            plaintext.as_ptr(),
            plaintext.len(),
            ciphertext.as_mut_ptr(),
            ciphertext.len(),
            &mut ciphertext_len,
        )
    };

    assert_eq!(encrypt_status, status::CRYPTO_OK);
    assert_eq!(ciphertext_len, plaintext.len() + tag_len);

    let mut decrypted = [0u8; 64];
    let mut decrypted_len = 0usize;
    let decrypt_status = unsafe {
        decrypt(
            key.as_ptr(),
            key.len(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
            ciphertext.as_ptr(),
            ciphertext_len,
            decrypted.as_mut_ptr(),
            decrypted.len(),
            &mut decrypted_len,
        )
    };

    assert_eq!(decrypt_status, status::CRYPTO_OK);
    assert_eq!(decrypted_len, plaintext.len());
    assert_eq!(&decrypted[..decrypted_len], plaintext);

    ciphertext[0] ^= 0x01;
    let tamper_status = unsafe {
        decrypt(
            key.as_ptr(),
            key.len(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
            ciphertext.as_ptr(),
            ciphertext_len,
            decrypted.as_mut_ptr(),
            decrypted.len(),
            &mut decrypted_len,
        )
    };
    assert_eq!(tamper_status, status::CRYPTO_AUTHENTICATION_FAILED);
}

#[test]
fn aes128_gcm_ffi_encrypts_decrypts_and_rejects_tampering() {
    let key = [7u8; aes256_gcm::AES128_GCM_KEY_LEN];
    let nonce = [9u8; aes256_gcm::AES128_GCM_NONCE_LEN];
    assert_aes_gcm_ffi_roundtrip_and_tamper(
        aes256_gcm::rm_crypto_aes128_gcm_encrypt,
        aes256_gcm::rm_crypto_aes128_gcm_decrypt,
        &key,
        &nonce,
        aes256_gcm::AES128_GCM_TAG_LEN,
    );
}

#[test]
fn aes192_gcm_ffi_encrypts_decrypts_and_rejects_tampering() {
    let key = [7u8; aes256_gcm::AES192_GCM_KEY_LEN];
    let nonce = [9u8; aes256_gcm::AES192_GCM_NONCE_LEN];
    assert_aes_gcm_ffi_roundtrip_and_tamper(
        aes256_gcm::rm_crypto_aes192_gcm_encrypt,
        aes256_gcm::rm_crypto_aes192_gcm_decrypt,
        &key,
        &nonce,
        aes256_gcm::AES192_GCM_TAG_LEN,
    );
}

#[test]
fn aes256_gcm_ffi_encrypts_decrypts_and_rejects_tampering() {
    let key = [7u8; aes256_gcm::AES256_GCM_KEY_LEN];
    let nonce = [9u8; aes256_gcm::AES256_GCM_NONCE_LEN];
    assert_aes_gcm_ffi_roundtrip_and_tamper(
        aes256_gcm::rm_crypto_aes256_gcm_encrypt,
        aes256_gcm::rm_crypto_aes256_gcm_decrypt,
        &key,
        &nonce,
        aes256_gcm::AES256_GCM_TAG_LEN,
    );
}

#[test]
fn aes_kw_ffi_vectors_wrap_unwrap_and_reject_tampering() {
    type WrapFn = unsafe extern "C" fn(
        *const u8,
        usize,
        *const u8,
        usize,
        *mut u8,
        usize,
        *mut usize,
    ) -> status::CryptoStatus;
    type UnwrapFn = unsafe extern "C" fn(
        *const u8,
        usize,
        *const u8,
        usize,
        *mut u8,
        usize,
        *mut usize,
    ) -> status::CryptoStatus;

    fn assert_suite(vector_name: &str, expected_algorithm: &str, wrap: WrapFn, unwrap: UnwrapFn) {
        let vector = load_shared_vector(vector_name);
        let kek = vector_bytes(&vector, "kek");
        let key_data = vector_bytes(&vector, "key_data");
        let expected_wrapped = vector_bytes(&vector, "wrapped_key");

        assert_eq!(vector_string(&vector, "alg"), expected_algorithm);
        let mut wrapped = [0u8; 48];
        let mut wrapped_len = 0usize;
        let wrap_status = unsafe {
            wrap(
                kek.as_ptr(),
                kek.len(),
                key_data.as_ptr(),
                key_data.len(),
                wrapped.as_mut_ptr(),
                wrapped.len(),
                &mut wrapped_len,
            )
        };
        assert_eq!(wrap_status, status::CRYPTO_OK);
        assert_eq!(wrapped_len, expected_wrapped.len());
        assert_eq!(&wrapped[..wrapped_len], expected_wrapped);

        let mut unwrapped = [0u8; 40];
        let mut unwrapped_len = 0usize;
        let unwrap_status = unsafe {
            unwrap(
                kek.as_ptr(),
                kek.len(),
                wrapped.as_ptr(),
                wrapped_len,
                unwrapped.as_mut_ptr(),
                unwrapped.len(),
                &mut unwrapped_len,
            )
        };
        assert_eq!(unwrap_status, status::CRYPTO_OK);
        assert_eq!(unwrapped_len, key_data.len());
        assert_eq!(&unwrapped[..unwrapped_len], key_data.as_slice());

        wrapped[0] ^= 0x01;
        let tamper_status = unsafe {
            unwrap(
                kek.as_ptr(),
                kek.len(),
                wrapped.as_ptr(),
                wrapped_len,
                unwrapped.as_mut_ptr(),
                unwrapped.len(),
                &mut unwrapped_len,
            )
        };
        assert_eq!(tamper_status, status::CRYPTO_AUTHENTICATION_FAILED);
    }

    assert_suite(
        "aes128kw.json",
        "AES-128-KW",
        aes_kw::rm_crypto_aes128_kw_wrap_key,
        aes_kw::rm_crypto_aes128_kw_unwrap_key,
    );
    assert_suite(
        "aes192kw.json",
        "AES-192-KW",
        aes_kw::rm_crypto_aes192_kw_wrap_key,
        aes_kw::rm_crypto_aes192_kw_unwrap_key,
    );
    assert_suite(
        "aes256kw.json",
        "AES-256-KW",
        aes_kw::rm_crypto_aes256_kw_wrap_key,
        aes_kw::rm_crypto_aes256_kw_unwrap_key,
    );
}

#[test]
fn aes_kw_ffi_rejects_short_output_and_invalid_plaintext_length() {
    let vector = load_shared_vector("aes256kw.json");
    let kek = vector_bytes(&vector, "kek");
    let key_data = vector_bytes(&vector, "key_data");
    let mut wrapped = [0u8; 48];
    let mut wrapped_len = 17usize;

    let mut short_out = [0u8; 8];
    let small_status = unsafe {
        aes_kw::rm_crypto_aes256_kw_wrap_key(
            kek.as_ptr(),
            kek.len(),
            key_data.as_ptr(),
            key_data.len(),
            short_out.as_mut_ptr(),
            short_out.len(),
            &mut wrapped_len,
        )
    };
    assert_eq!(small_status, status::CRYPTO_BUFFER_TOO_SMALL);
    assert_eq!(wrapped_len, 17, "scalar AES-KW does not define probe sizing");

    let invalid_key_data = [0u8; aes_kw::AES_KW_BLOCK_LEN];
    let invalid_status = unsafe {
        aes_kw::rm_crypto_aes256_kw_wrap_key(
            kek.as_ptr(),
            kek.len(),
            invalid_key_data.as_ptr(),
            invalid_key_data.len(),
            wrapped.as_mut_ptr(),
            wrapped.len(),
            &mut wrapped_len,
        )
    };
    assert_eq!(invalid_status, status::CRYPTO_INVALID_ARGUMENT);
}

#[test]
fn aes256_gcm_siv_ffi_encrypts_decrypts_and_rejects_tampering() {
    let key = [7u8; aes256_gcm_siv::AES256_GCM_SIV_KEY_LEN];
    let nonce = [9u8; aes256_gcm_siv::AES256_GCM_SIV_NONCE_LEN];
    let aad = b"aad";
    let plaintext = b"ffi gcm siv plaintext";
    let mut ciphertext = [0u8; 96];
    let mut ciphertext_len = 0usize;

    let encrypt_status = unsafe {
        aes256_gcm_siv::rm_crypto_aes256_gcm_siv_encrypt(
            key.as_ptr(),
            key.len(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
            plaintext.as_ptr(),
            plaintext.len(),
            ciphertext.as_mut_ptr(),
            ciphertext.len(),
            &mut ciphertext_len,
        )
    };

    assert_eq!(encrypt_status, status::CRYPTO_OK);
    assert_eq!(
        ciphertext_len,
        plaintext.len() + aes256_gcm_siv::AES256_GCM_SIV_TAG_LEN
    );

    let mut decrypted = [0u8; 96];
    let mut decrypted_len = 0usize;
    let decrypt_status = unsafe {
        aes256_gcm_siv::rm_crypto_aes256_gcm_siv_decrypt(
            key.as_ptr(),
            key.len(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
            ciphertext.as_ptr(),
            ciphertext_len,
            decrypted.as_mut_ptr(),
            decrypted.len(),
            &mut decrypted_len,
        )
    };

    assert_eq!(decrypt_status, status::CRYPTO_OK);
    assert_eq!(decrypted_len, plaintext.len());
    assert_eq!(&decrypted[..decrypted_len], plaintext);

    ciphertext[0] ^= 0x01;
    let tamper_status = unsafe {
        aes256_gcm_siv::rm_crypto_aes256_gcm_siv_decrypt(
            key.as_ptr(),
            key.len(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
            ciphertext.as_ptr(),
            ciphertext_len,
            decrypted.as_mut_ptr(),
            decrypted.len(),
            &mut decrypted_len,
        )
    };
    assert_eq!(tamper_status, status::CRYPTO_AUTHENTICATION_FAILED);
}
