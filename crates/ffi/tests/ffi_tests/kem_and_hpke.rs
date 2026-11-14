// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

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
fn hpke_ffi_seals_opens_and_preserves_outputs_on_authentication_failure() {
    use reallyme_crypto::hpke::{
        HPKE_DHKEM_P256_HKDF_SHA256_AES256GCM, HPKE_DHKEM_X25519_HKDF_SHA256_CHACHA20POLY1305,
    };

    for (ffi_suite, suite) in [
        (
            hpke::HPKE_SUITE_P256_SHA256_AES256GCM,
            HPKE_DHKEM_P256_HKDF_SHA256_AES256GCM,
        ),
        (
            hpke::HPKE_SUITE_X25519_SHA256_CHACHA20_POLY1305,
            HPKE_DHKEM_X25519_HKDF_SHA256_CHACHA20POLY1305,
        ),
    ] {
        let key_pair = reallyme_crypto::hpke::derive_keypair(suite, &[0x21; 32])
            .expect("HPKE seed has the supported width");
        let public_key = &key_pair.public_key;
        let private_key = key_pair.private_key();
        let info = b"reallyme-hpke-ffi-info";
        let aad = b"reallyme-hpke-ffi-aad";
        let plaintext = b"reallyme hpke ffi plaintext";

        let mut enc = [0u8; hpke::HPKE_FFI_ENCAPSULATED_KEY_MAX_LEN];
        let mut enc_len = 0usize;
        let mut ciphertext = [0u8; 128];
        let mut ciphertext_len = 0usize;
        // SAFETY: All inputs and outputs are live and disjoint, with aligned
        // writable length slots and enough capacity for both seal results.
        let seal_status = unsafe {
            hpke::rm_crypto_hpke_seal_base(
                ffi_suite,
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
        assert_eq!(enc_len, public_key.len());
        assert_eq!(
            Some(ciphertext_len),
            plaintext.len().checked_add(hpke::HPKE_FFI_AEAD_TAG_LEN)
        );

        let original_output = [0xa5; 128];
        let mut opened = original_output;
        let mut opened_len = usize::MAX;
        // SAFETY: The seal results are initialized up to the reported lengths.
        // The plaintext buffer and length slot are valid and disjoint from all inputs.
        let open_status = unsafe {
            hpke::rm_crypto_hpke_open_base(
                ffi_suite,
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
        assert_eq!(opened_len, plaintext.len());
        assert_eq!(&opened[..opened_len], plaintext);
        assert_eq!(opened[opened_len..], original_output[opened_len..]);

        ciphertext[0] ^= 0x80;
        opened = original_output;
        opened_len = usize::MAX;
        // SAFETY: Tampering changes one byte within the initialized record and
        // keeps the same valid, disjoint buffers and aligned length slot.
        let tampered_status = unsafe {
            hpke::rm_crypto_hpke_open_base(
                ffi_suite,
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
        assert_eq!(opened, original_output);
        assert_eq!(opened_len, usize::MAX);
    }
}
