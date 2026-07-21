// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#[test]
fn ml_kem_512_ffi_covers_keygen_encaps_decaps_and_encoding() {
    let mut public = [0u8; ml_kem_512::ML_KEM_512_PUBLIC_KEY_LEN];
    let mut secret = [0u8; ml_kem_512::ML_KEM_512_SECRET_KEY_LEN];
    let key_status = unsafe {
        ml_kem_512::rm_crypto_ml_kem_512_generate_keypair(
            public.as_mut_ptr(),
            public.len(),
            secret.as_mut_ptr(),
            secret.len(),
        )
    };
    assert_eq!(key_status, status::CRYPTO_OK);

    let mut ciphertext = [0u8; ml_kem_512::ML_KEM_512_CIPHERTEXT_LEN];
    let mut shared_from_encap = [0u8; ml_kem_512::ML_KEM_512_SHARED_SECRET_LEN];
    let encap_status = unsafe {
        ml_kem_512::rm_crypto_ml_kem_512_encapsulate(
            public.as_ptr(),
            public.len(),
            ciphertext.as_mut_ptr(),
            ciphertext.len(),
            shared_from_encap.as_mut_ptr(),
            shared_from_encap.len(),
        )
    };
    assert_eq!(encap_status, status::CRYPTO_OK);

    let mut shared_from_decap = [0u8; ml_kem_512::ML_KEM_512_SHARED_SECRET_LEN];
    let decap_status = unsafe {
        ml_kem_512::rm_crypto_ml_kem_512_decapsulate(
            ciphertext.as_ptr(),
            ciphertext.len(),
            secret.as_ptr(),
            secret.len(),
            shared_from_decap.as_mut_ptr(),
            shared_from_decap.len(),
        )
    };
    assert_eq!(decap_status, status::CRYPTO_OK);
    assert_eq!(shared_from_encap, shared_from_decap);

    let mut encoded = [0u8; ml_kem_512::ML_KEM_512_PUBLIC_KEY_LEN];
    let encode_status = unsafe {
        ml_kem_512::rm_crypto_ml_kem_512_encode_public_key(
            public.as_ptr(),
            public.len(),
            encoded.as_mut_ptr(),
            encoded.len(),
        )
    };
    assert_eq!(encode_status, status::CRYPTO_OK);
    let mut decoded = [0u8; ml_kem_512::ML_KEM_512_PUBLIC_KEY_LEN];
    let decode_status = unsafe {
        ml_kem_512::rm_crypto_ml_kem_512_decode_public_key(
            encoded.as_ptr(),
            encoded.len(),
            decoded.as_mut_ptr(),
            decoded.len(),
        )
    };
    assert_eq!(decode_status, status::CRYPTO_OK);
    assert_eq!(decoded, public);
}

#[test]
fn ml_kem_768_ffi_covers_keygen_encaps_decaps_and_encoding() {
    let mut public = [0u8; ml_kem_768::ML_KEM_768_PUBLIC_KEY_LEN];
    let mut secret = [0u8; ml_kem_768::ML_KEM_768_SECRET_KEY_LEN];
    let key_status = unsafe {
        ml_kem_768::rm_crypto_ml_kem_768_generate_keypair(
            public.as_mut_ptr(),
            public.len(),
            secret.as_mut_ptr(),
            secret.len(),
        )
    };
    assert_eq!(key_status, status::CRYPTO_OK);

    let mut ciphertext = [0u8; ml_kem_768::ML_KEM_768_CIPHERTEXT_LEN];
    let mut shared_from_encap = [0u8; ml_kem_768::ML_KEM_768_SHARED_SECRET_LEN];
    let encap_status = unsafe {
        ml_kem_768::rm_crypto_ml_kem_768_encapsulate(
            public.as_ptr(),
            public.len(),
            ciphertext.as_mut_ptr(),
            ciphertext.len(),
            shared_from_encap.as_mut_ptr(),
            shared_from_encap.len(),
        )
    };
    assert_eq!(encap_status, status::CRYPTO_OK);

    let mut shared_from_decap = [0u8; ml_kem_768::ML_KEM_768_SHARED_SECRET_LEN];
    let decap_status = unsafe {
        ml_kem_768::rm_crypto_ml_kem_768_decapsulate(
            ciphertext.as_ptr(),
            ciphertext.len(),
            secret.as_ptr(),
            secret.len(),
            shared_from_decap.as_mut_ptr(),
            shared_from_decap.len(),
        )
    };
    assert_eq!(decap_status, status::CRYPTO_OK);
    assert_eq!(shared_from_encap, shared_from_decap);

    let mut encoded = [0u8; ml_kem_768::ML_KEM_768_PUBLIC_KEY_LEN];
    let encode_status = unsafe {
        ml_kem_768::rm_crypto_ml_kem_768_encode_public_key(
            public.as_ptr(),
            public.len(),
            encoded.as_mut_ptr(),
            encoded.len(),
        )
    };
    assert_eq!(encode_status, status::CRYPTO_OK);
    let mut decoded = [0u8; ml_kem_768::ML_KEM_768_PUBLIC_KEY_LEN];
    let decode_status = unsafe {
        ml_kem_768::rm_crypto_ml_kem_768_decode_public_key(
            encoded.as_ptr(),
            encoded.len(),
            decoded.as_mut_ptr(),
            decoded.len(),
        )
    };
    assert_eq!(decode_status, status::CRYPTO_OK);
    assert_eq!(decoded, public);
}

#[test]
fn ml_kem_1024_ffi_covers_keygen_encaps_decaps_and_encoding() {
    let mut public = [0u8; ml_kem_1024::ML_KEM_1024_PUBLIC_KEY_LEN];
    let mut secret = [0u8; ml_kem_1024::ML_KEM_1024_SECRET_KEY_LEN];
    let key_status = unsafe {
        ml_kem_1024::rm_crypto_ml_kem_1024_generate_keypair(
            public.as_mut_ptr(),
            public.len(),
            secret.as_mut_ptr(),
            secret.len(),
        )
    };
    assert_eq!(key_status, status::CRYPTO_OK);

    let mut ciphertext = [0u8; ml_kem_1024::ML_KEM_1024_CIPHERTEXT_LEN];
    let mut shared_from_encap = [0u8; ml_kem_1024::ML_KEM_1024_SHARED_SECRET_LEN];
    let encap_status = unsafe {
        ml_kem_1024::rm_crypto_ml_kem_1024_encapsulate(
            public.as_ptr(),
            public.len(),
            ciphertext.as_mut_ptr(),
            ciphertext.len(),
            shared_from_encap.as_mut_ptr(),
            shared_from_encap.len(),
        )
    };
    assert_eq!(encap_status, status::CRYPTO_OK);

    let mut shared_from_decap = [0u8; ml_kem_1024::ML_KEM_1024_SHARED_SECRET_LEN];
    let decap_status = unsafe {
        ml_kem_1024::rm_crypto_ml_kem_1024_decapsulate(
            ciphertext.as_ptr(),
            ciphertext.len(),
            secret.as_ptr(),
            secret.len(),
            shared_from_decap.as_mut_ptr(),
            shared_from_decap.len(),
        )
    };
    assert_eq!(decap_status, status::CRYPTO_OK);
    assert_eq!(shared_from_encap, shared_from_decap);

    let mut encoded = [0u8; ml_kem_1024::ML_KEM_1024_PUBLIC_KEY_LEN];
    let encode_status = unsafe {
        ml_kem_1024::rm_crypto_ml_kem_1024_encode_public_key(
            public.as_ptr(),
            public.len(),
            encoded.as_mut_ptr(),
            encoded.len(),
        )
    };
    assert_eq!(encode_status, status::CRYPTO_OK);
    let mut decoded = [0u8; ml_kem_1024::ML_KEM_1024_PUBLIC_KEY_LEN];
    let decode_status = unsafe {
        ml_kem_1024::rm_crypto_ml_kem_1024_decode_public_key(
            encoded.as_ptr(),
            encoded.len(),
            decoded.as_mut_ptr(),
            decoded.len(),
        )
    };
    assert_eq!(decode_status, status::CRYPTO_OK);
    assert_eq!(decoded, public);
}

#[test]
fn x_wing_ffi_covers_supplied_key_encaps_decaps_and_encoding() {
    let secret = [0x58u8; x_wing::X_WING_SECRET_KEY_LEN];

    let mut public = [0u8; x_wing::X_WING_768_PUBLIC_KEY_LEN];
    let key_status = unsafe {
        x_wing::rm_crypto_x_wing_768_generate_keypair_derand(
            secret.as_ptr(),
            secret.len(),
            public.as_mut_ptr(),
            public.len(),
        )
    };
    assert_eq!(key_status, status::CRYPTO_OK);

    let mut ciphertext = [0u8; x_wing::X_WING_768_CIPHERTEXT_LEN];
    let mut shared_from_encap = [0u8; x_wing::X_WING_SHARED_SECRET_LEN];
    let encap_status = unsafe {
        x_wing::rm_crypto_x_wing_768_encapsulate(
            public.as_ptr(),
            public.len(),
            ciphertext.as_mut_ptr(),
            ciphertext.len(),
            shared_from_encap.as_mut_ptr(),
            shared_from_encap.len(),
        )
    };
    assert_eq!(encap_status, status::CRYPTO_OK);

    let mut shared_from_decap = [0u8; x_wing::X_WING_SHARED_SECRET_LEN];
    let decap_status = unsafe {
        x_wing::rm_crypto_x_wing_768_decapsulate(
            ciphertext.as_ptr(),
            ciphertext.len(),
            secret.as_ptr(),
            secret.len(),
            shared_from_decap.as_mut_ptr(),
            shared_from_decap.len(),
        )
    };
    assert_eq!(decap_status, status::CRYPTO_OK);
    assert_eq!(shared_from_encap, shared_from_decap);

    let mut encoded = [0u8; x_wing::X_WING_768_PUBLIC_KEY_LEN];
    let encode_status = unsafe {
        x_wing::rm_crypto_x_wing_768_encode_public_key(
            public.as_ptr(),
            public.len(),
            encoded.as_mut_ptr(),
            encoded.len(),
        )
    };
    assert_eq!(encode_status, status::CRYPTO_OK);
    assert_eq!(encoded, public);

}

#[test]
fn hpke_ffi_seals_opens_and_rejects_tampering() {
    let private_key: [u8; hpke::HPKE_FFI_P256_PRIVATE_KEY_LEN] = [
        0x21, 0x4f, 0x8b, 0x6c, 0xa2, 0x9d, 0x33, 0x10, 0x95, 0x47, 0x66, 0x12, 0x72, 0x83, 0xaf,
        0xee, 0x0d, 0x19, 0x41, 0x5b, 0x7c, 0x22, 0xd4, 0x39, 0x51, 0x8a, 0xb0, 0x65, 0x2f, 0x91,
        0xc3, 0x44,
    ];
    let public_key: [u8; hpke::HPKE_FFI_P256_PUBLIC_KEY_LEN] = [
        0x04, 0x07, 0xfc, 0xcb, 0x43, 0x45, 0x09, 0x6f, 0x96, 0x21, 0x72, 0x6f, 0xc4, 0xe4, 0x37,
        0xbe, 0x0c, 0xf8, 0x1c, 0x43, 0x10, 0x81, 0xf3, 0x28, 0xe5, 0x54, 0x96, 0x72, 0x39, 0xac,
        0x55, 0x22, 0xee, 0x0d, 0x97, 0x14, 0x75, 0x3e, 0xc6, 0xf7, 0x7f, 0x55, 0x7a, 0xa7, 0x37,
        0x14, 0x26, 0x9d, 0x5a, 0xcf, 0xeb, 0x72, 0x94, 0xbe, 0xbd, 0xcf, 0xfc, 0x67, 0xc1, 0x5a,
        0x65, 0x11, 0x15, 0x5f, 0x80,
    ];
    let info = b"reallyme-hpke-ffi-info";
    let aad = b"reallyme-hpke-ffi-aad";
    let plaintext = b"reallyme hpke ffi plaintext";

    let mut enc = [0u8; hpke::HPKE_FFI_ENCAPSULATED_KEY_MAX_LEN];
    let mut enc_len = 0usize;
    let mut ciphertext = [0u8; 128];
    let mut ciphertext_len = 0usize;
    let seal_status = unsafe {
        hpke::rm_crypto_hpke_seal_base(
            hpke::HPKE_SUITE_P256_SHA256_AES256GCM,
            public_key.as_ptr(),
            public_key.len(),
            info.as_ptr(),
            info.len(),
            aad.as_ptr(),
            aad.len(),
            plaintext.as_ptr(),
            plaintext.len(),
            enc.as_mut_ptr(),
            enc.len(),
            &mut enc_len,
            ciphertext.as_mut_ptr(),
            ciphertext.len(),
            &mut ciphertext_len,
        )
    };
    assert_eq!(seal_status, status::CRYPTO_OK);
    assert_eq!(enc_len, hpke::HPKE_FFI_P256_PUBLIC_KEY_LEN);
    assert_eq!(
        ciphertext_len,
        plaintext.len() + hpke::HPKE_FFI_AEAD_TAG_LEN
    );

    let mut opened = [0u8; 128];
    let mut opened_len = 0usize;
    let open_status = unsafe {
        hpke::rm_crypto_hpke_open_base(
            hpke::HPKE_SUITE_P256_SHA256_AES256GCM,
            enc.as_ptr(),
            enc_len,
            private_key.as_ptr(),
            private_key.len(),
            info.as_ptr(),
            info.len(),
            aad.as_ptr(),
            aad.len(),
            ciphertext.as_ptr(),
            ciphertext_len,
            opened.as_mut_ptr(),
            opened.len(),
            &mut opened_len,
        )
    };
    assert_eq!(open_status, status::CRYPTO_OK);
    assert_eq!(&opened[..opened_len], plaintext);

    ciphertext[0] ^= 0x80;
    let tampered_status = unsafe {
        hpke::rm_crypto_hpke_open_base(
            hpke::HPKE_SUITE_P256_SHA256_AES256GCM,
            enc.as_ptr(),
            enc_len,
            private_key.as_ptr(),
            private_key.len(),
            info.as_ptr(),
            info.len(),
            aad.as_ptr(),
            aad.len(),
            ciphertext.as_ptr(),
            ciphertext_len,
            opened.as_mut_ptr(),
            opened.len(),
            &mut opened_len,
        )
    };
    assert_eq!(tampered_status, status::CRYPTO_AUTHENTICATION_FAILED);
}
