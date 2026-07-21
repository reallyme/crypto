// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#[test]
fn ffi_rejects_null_oversized_and_short_output_pointer_pairs() {
    let message = b"pointer boundary vector";
    let mut digest = [0xA5_u8; sha2_256::SHA2_256_DIGEST_LEN];

    let null_message_status = unsafe {
        sha2_256::rm_crypto_sha2_256_digest(core::ptr::null(), 1, digest.as_mut_ptr(), digest.len())
    };
    assert_eq!(null_message_status, status::CRYPTO_INVALID_ARGUMENT);
    assert_eq!(digest, [0xA5_u8; sha2_256::SHA2_256_DIGEST_LEN]);

    let oversized_message_status = unsafe {
        sha2_256::rm_crypto_sha2_256_digest(
            NonNull::<u8>::dangling().as_ptr(),
            usize::MAX,
            digest.as_mut_ptr(),
            digest.len(),
        )
    };
    assert_eq!(oversized_message_status, status::CRYPTO_INVALID_ARGUMENT);
    assert_eq!(digest, [0xA5_u8; sha2_256::SHA2_256_DIGEST_LEN]);

    let null_output_status = unsafe {
        sha2_256::rm_crypto_sha2_256_digest(
            message.as_ptr(),
            message.len(),
            core::ptr::null_mut(),
            digest.len(),
        )
    };
    assert_eq!(null_output_status, status::CRYPTO_INVALID_ARGUMENT);

    let mut short_output = [0xA5_u8; sha2_256::SHA2_256_DIGEST_LEN - 1];
    let short_output_status = unsafe {
        sha2_256::rm_crypto_sha2_256_digest(
            message.as_ptr(),
            message.len(),
            short_output.as_mut_ptr(),
            short_output.len(),
        )
    };
    assert_eq!(short_output_status, status::CRYPTO_BUFFER_TOO_SMALL);
    assert_eq!(short_output, [0xA5_u8; sha2_256::SHA2_256_DIGEST_LEN - 1]);
}

#[test]
fn ffi_rejects_overlapping_input_and_output_buffers() {
    let mut public_key = [7_u8; ml_dsa_44::ML_DSA_44_PUBLIC_KEY_LEN];
    let public_key_ptr = public_key.as_mut_ptr();
    let status = unsafe {
        ml_dsa_44::rm_crypto_ml_dsa_44_encode_public_key(
            public_key_ptr.cast_const(),
            public_key.len(),
            public_key_ptr,
            public_key.len(),
        )
    };

    assert_eq!(status, status::CRYPTO_INVALID_ARGUMENT);
    assert_eq!(public_key, [7_u8; ml_dsa_44::ML_DSA_44_PUBLIC_KEY_LEN]);
}

#[test]
fn ffi_rejects_overlap_even_when_output_is_derived_storage() {
    let mut storage = [0xA5_u8; sha2_256::SHA2_256_DIGEST_LEN + 8];
    let input_ptr = storage.as_ptr();
    let output_ptr = unsafe { storage.as_mut_ptr().add(8) };

    let status = unsafe {
        sha2_256::rm_crypto_sha2_256_digest(
            input_ptr,
            16,
            output_ptr,
            sha2_256::SHA2_256_DIGEST_LEN,
        )
    };

    assert_eq!(status, status::CRYPTO_INVALID_ARGUMENT);
    assert_eq!(storage, [0xA5_u8; sha2_256::SHA2_256_DIGEST_LEN + 8]);
}

#[test]
fn ffi_rejects_overlapping_output_buffers() {
    let mut output = [0xA5_u8; p256::P256_PUBLIC_KEY_UNCOMPRESSED_LEN];
    let output_ptr = output.as_mut_ptr();
    let status = unsafe {
        p256::rm_crypto_p256_generate_keypair(
            output_ptr,
            output.len(),
            output_ptr,
            p256::P256_SECRET_KEY_LEN,
        )
    };

    assert_eq!(status, status::CRYPTO_INVALID_ARGUMENT);
    assert_eq!(output, [0xA5_u8; p256::P256_PUBLIC_KEY_UNCOMPRESSED_LEN]);
}

#[test]
fn hpke_ffi_rejects_cross_output_length_aliases_before_writing() {
    let mut encapsulated_storage = [usize::MAX; 16];
    let encapsulated_ptr = encapsulated_storage.as_mut_ptr().cast::<u8>();
    let encapsulated_len = core::mem::size_of_val(&encapsulated_storage);
    let ciphertext_len_out = unsafe { encapsulated_storage.as_mut_ptr().add(1) };
    let mut encapsulated_key_len = 0_usize;
    let mut ciphertext = [0xA5_u8; 128];

    let status = unsafe {
        hpke::rm_crypto_hpke_seal_base(
            hpke::HPKE_SUITE_P256_SHA256_AES256GCM,
            core::ptr::null(),
            0,
            core::ptr::null(),
            0,
            core::ptr::null(),
            0,
            core::ptr::null(),
            0,
            encapsulated_ptr,
            encapsulated_len,
            &mut encapsulated_key_len,
            ciphertext.as_mut_ptr(),
            ciphertext.len(),
            ciphertext_len_out,
        )
    };

    assert_eq!(status, status::CRYPTO_INVALID_ARGUMENT);
    assert_eq!(encapsulated_storage, [usize::MAX; 16]);
    assert_eq!(ciphertext, [0xA5_u8; 128]);
    assert_eq!(encapsulated_key_len, 0);
}

#[test]
fn variable_length_ffis_reject_missing_length_output_before_writing_bytes() {
    let kek = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let key_data = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let mut wrapped = [0xA5_u8; 32];

    let status = unsafe {
        aes_kw::rm_crypto_aes256_kw_wrap_key(
            kek.as_ptr(),
            kek.len(),
            key_data.as_ptr(),
            key_data.len(),
            wrapped.as_mut_ptr(),
            wrapped.len(),
            core::ptr::null_mut(),
        )
    };

    assert_eq!(status, status::CRYPTO_INVALID_ARGUMENT);
    assert_eq!(wrapped, [0xA5_u8; 32]);
}

#[test]
fn variable_length_ffis_reject_length_output_aliasing_an_input_before_writing_bytes() {
    let kek = [0x42_u8; aes_kw::AES256_KW_KEK_LEN];
    let mut key_data_words = [0x1122_3344_5566_7788_usize; 2];
    let key_data_ptr = key_data_words.as_ptr().cast::<u8>();
    let key_data_len = core::mem::size_of_val(&key_data_words);
    let mut wrapped = [0xA5_u8; 32];

    let status = unsafe {
        aes_kw::rm_crypto_aes256_kw_wrap_key(
            kek.as_ptr(),
            kek.len(),
            key_data_ptr,
            key_data_len,
            wrapped.as_mut_ptr(),
            wrapped.len(),
            key_data_words.as_mut_ptr(),
        )
    };

    assert_eq!(status, status::CRYPTO_INVALID_ARGUMENT);
    assert_eq!(wrapped, [0xA5_u8; 32]);
}

#[test]
fn multi_output_ffis_reject_input_aliasing_any_output_before_partial_writes() {
    let mut seed = [0x21_u8; ed25519::ED25519_SECRET_KEY_LEN];
    let mut public_key = [0xA5_u8; ed25519::ED25519_PUBLIC_KEY_LEN];

    let status = unsafe {
        ed25519::rm_crypto_ed25519_generate_keypair_from_seed(
            seed.as_ptr(),
            seed.len(),
            public_key.as_mut_ptr(),
            public_key.len(),
            seed.as_mut_ptr(),
            seed.len(),
        )
    };

    assert_eq!(status, status::CRYPTO_INVALID_ARGUMENT);
    assert_eq!(public_key, [0xA5_u8; ed25519::ED25519_PUBLIC_KEY_LEN]);
}
