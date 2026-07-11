// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(unsafe_code)]

use core::ptr::NonNull;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use crypto_ffi::aes256_gcm;
use crypto_ffi::aes256_gcm_siv;
use crypto_ffi::aes_kw;
use crypto_ffi::argon2id;
use crypto_ffi::constant_time;
use crypto_ffi::csprng;
use crypto_ffi::ed25519;
use crypto_ffi::hkdf;
use crypto_ffi::hmac;
use crypto_ffi::hpke;
use crypto_ffi::ml_dsa_44;
use crypto_ffi::ml_dsa_65;
use crypto_ffi::ml_dsa_87;
use crypto_ffi::ml_kem_1024;
use crypto_ffi::ml_kem_512;
use crypto_ffi::ml_kem_768;
use crypto_ffi::p256;
use crypto_ffi::p384;
use crypto_ffi::p521;
use crypto_ffi::pbkdf2;
use crypto_ffi::rsa as rsa_ffi;
use crypto_ffi::secp256k1;
use crypto_ffi::sha2;
use crypto_ffi::sha2_256;
use crypto_ffi::sha3;
use crypto_ffi::sha3_256;
use crypto_ffi::slh_dsa;
use crypto_ffi::status;
use crypto_ffi::x25519;
use crypto_ffi::x_wing;

#[test]
fn ffi_rejects_null_oversized_and_short_output_pointer_pairs() {
    let message = b"phase 7 boundary vector";
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
fn header_declares_every_exported_ffi_symbol() {
    let header = include_str!("../abi/reallyme_crypto_ffi.h");
    let symbols = [
        "rm_crypto_sha2_256_digest",
        "rm_crypto_sha2_384_digest",
        "rm_crypto_sha2_512_digest",
        "rm_crypto_sha3_224_digest",
        "rm_crypto_sha3_256_digest",
        "rm_crypto_sha3_384_digest",
        "rm_crypto_sha3_512_digest",
        "rm_crypto_aes256_gcm_encrypt",
        "rm_crypto_aes256_gcm_decrypt",
        "rm_crypto_aes256_kw_wrap_key",
        "rm_crypto_aes256_kw_unwrap_key",
        "rm_crypto_aes256_gcm_siv_encrypt",
        "rm_crypto_aes256_gcm_siv_decrypt",
        "rm_crypto_argon2id_derive_key",
        "rm_crypto_hkdf_derive",
        "rm_crypto_pbkdf2_hmac_sha256_derive_key",
        "rm_crypto_pbkdf2_hmac_sha512_derive_key",
        "rm_crypto_hpke_seal_base",
        "rm_crypto_hpke_open_base",
        "rm_crypto_hmac_authenticate",
        "rm_crypto_hmac_verify",
        "rm_crypto_csprng_generate_bytes",
        "rm_crypto_csprng_generate_aead_nonce_12",
        "rm_crypto_csprng_generate_argon2_salt_16",
        "rm_crypto_csprng_generate_argon2_salt_32",
        "rm_crypto_constant_time_equal",
        "rm_crypto_ed25519_generate_keypair",
        "rm_crypto_ed25519_generate_keypair_from_seed",
        "rm_crypto_ed25519_sign",
        "rm_crypto_ed25519_verify",
        "rm_crypto_ed25519_encode_public_key",
        "rm_crypto_ed25519_decode_public_key",
        "rm_crypto_p256_generate_keypair",
        "rm_crypto_p256_generate_keypair_from_secret_key",
        "rm_crypto_p256_sign_der_prehash",
        "rm_crypto_p256_verify_der_prehash",
        "rm_crypto_p256_derive_shared_secret",
        "rm_crypto_p256_compress_public_key",
        "rm_crypto_p256_decompress_public_key",
        "rm_crypto_p384_generate_keypair",
        "rm_crypto_p384_generate_keypair_from_secret_key",
        "rm_crypto_p384_sign_der_prehash",
        "rm_crypto_p384_verify_der_prehash",
        "rm_crypto_p384_compress_public_key",
        "rm_crypto_p384_decompress_public_key",
        "rm_crypto_p521_generate_keypair",
        "rm_crypto_p521_generate_keypair_from_secret_key",
        "rm_crypto_p521_sign_der_prehash",
        "rm_crypto_p521_verify_der_prehash",
        "rm_crypto_p521_compress_public_key",
        "rm_crypto_p521_decompress_public_key",
        "rm_crypto_rsa_verify_pkcs1v15",
        "rm_crypto_rsa_verify_pss",
        "rm_crypto_secp256k1_generate_keypair",
        "rm_crypto_secp256k1_generate_keypair_from_secret_key",
        "rm_crypto_secp256k1_sign",
        "rm_crypto_secp256k1_verify",
        "rm_crypto_secp256k1_encode_public_key",
        "rm_crypto_secp256k1_decode_public_key",
        "rm_crypto_secp256k1_decompress_public_key",
        "rm_crypto_bip340_schnorr_derive_public_key",
        "rm_crypto_bip340_schnorr_sign",
        "rm_crypto_bip340_schnorr_verify",
        "rm_crypto_bip340_schnorr_encode_public_key",
        "rm_crypto_bip340_schnorr_decode_public_key",
        "rm_crypto_x25519_generate_keypair",
        "rm_crypto_x25519_generate_keypair_from_seed",
        "rm_crypto_x25519_derive_shared_secret",
        "rm_crypto_x25519_encode_public_key",
        "rm_crypto_x25519_decode_public_key",
        "rm_crypto_ml_dsa_44_generate_keypair",
        "rm_crypto_ml_dsa_44_generate_keypair_from_seed",
        "rm_crypto_ml_dsa_44_sign",
        "rm_crypto_ml_dsa_44_verify",
        "rm_crypto_ml_dsa_44_encode_public_key",
        "rm_crypto_ml_dsa_44_decode_public_key",
        "rm_crypto_slh_dsa_sha2_128s_generate_keypair",
        "rm_crypto_slh_dsa_sha2_128s_derive_keypair",
        "rm_crypto_slh_dsa_sha2_128s_sign",
        "rm_crypto_slh_dsa_sha2_128s_verify",
        "rm_crypto_slh_dsa_sha2_128s_encode_public_key",
        "rm_crypto_slh_dsa_sha2_128s_decode_public_key",
        "rm_crypto_ml_dsa_65_generate_keypair",
        "rm_crypto_ml_dsa_65_generate_keypair_from_seed",
        "rm_crypto_ml_dsa_65_sign",
        "rm_crypto_ml_dsa_65_verify",
        "rm_crypto_ml_dsa_65_encode_public_key",
        "rm_crypto_ml_dsa_65_decode_public_key",
        "rm_crypto_ml_dsa_87_generate_keypair",
        "rm_crypto_ml_dsa_87_generate_keypair_from_seed",
        "rm_crypto_ml_dsa_87_sign",
        "rm_crypto_ml_dsa_87_verify",
        "rm_crypto_ml_dsa_87_encode_public_key",
        "rm_crypto_ml_dsa_87_decode_public_key",
        "rm_crypto_ml_kem_512_generate_keypair",
        "rm_crypto_ml_kem_512_generate_keypair_from_seed",
        "rm_crypto_ml_kem_512_encapsulate",
        "rm_crypto_ml_kem_512_encapsulate_derand",
        "rm_crypto_ml_kem_512_decapsulate",
        "rm_crypto_ml_kem_512_encode_public_key",
        "rm_crypto_ml_kem_512_decode_public_key",
        "rm_crypto_ml_kem_768_generate_keypair",
        "rm_crypto_ml_kem_768_generate_keypair_from_seed",
        "rm_crypto_ml_kem_768_encapsulate",
        "rm_crypto_ml_kem_768_encapsulate_derand",
        "rm_crypto_ml_kem_768_decapsulate",
        "rm_crypto_ml_kem_768_encode_public_key",
        "rm_crypto_ml_kem_768_decode_public_key",
        "rm_crypto_ml_kem_1024_generate_keypair",
        "rm_crypto_ml_kem_1024_generate_keypair_from_seed",
        "rm_crypto_ml_kem_1024_encapsulate",
        "rm_crypto_ml_kem_1024_encapsulate_derand",
        "rm_crypto_ml_kem_1024_decapsulate",
        "rm_crypto_ml_kem_1024_encode_public_key",
        "rm_crypto_ml_kem_1024_decode_public_key",
        "rm_crypto_x_wing_768_generate_keypair",
        "rm_crypto_x_wing_768_generate_keypair_derand",
        "rm_crypto_x_wing_768_encapsulate",
        "rm_crypto_x_wing_768_encapsulate_derand",
        "rm_crypto_x_wing_768_decapsulate",
        "rm_crypto_x_wing_768_encode_public_key",
        "rm_crypto_x_wing_768_decode_public_key",
        "rm_crypto_x_wing_1024_generate_keypair",
        "rm_crypto_x_wing_1024_generate_keypair_derand",
        "rm_crypto_x_wing_1024_encapsulate",
        "rm_crypto_x_wing_1024_encapsulate_derand",
        "rm_crypto_x_wing_1024_decapsulate",
        "rm_crypto_x_wing_1024_encode_public_key",
        "rm_crypto_x_wing_1024_decode_public_key",
    ];

    for symbol in symbols {
        assert!(header.contains(symbol), "missing symbol {symbol}");
    }
}

#[test]
fn fail_closed_signature_ffi_returns_invalid_signature_for_tampering() {
    let seed = [0x21_u8; ed25519::ED25519_SECRET_KEY_LEN];
    let message = b"ffi fail closed signature verification";
    let mut public_key = [0_u8; ed25519::ED25519_PUBLIC_KEY_LEN];
    let mut secret_key = [0_u8; ed25519::ED25519_SECRET_KEY_LEN];
    let key_status = unsafe {
        ed25519::rm_crypto_ed25519_generate_keypair_from_seed(
            seed.as_ptr(),
            seed.len(),
            public_key.as_mut_ptr(),
            public_key.len(),
            secret_key.as_mut_ptr(),
            secret_key.len(),
        )
    };
    assert_eq!(key_status, status::CRYPTO_OK);

    let mut signature = [0_u8; ed25519::ED25519_SIGNATURE_LEN];
    let sign_status = unsafe {
        ed25519::rm_crypto_ed25519_sign(
            secret_key.as_ptr(),
            secret_key.len(),
            message.as_ptr(),
            message.len(),
            signature.as_mut_ptr(),
            signature.len(),
        )
    };
    assert_eq!(sign_status, status::CRYPTO_OK);

    let valid_status = unsafe {
        ed25519::rm_crypto_ed25519_verify(
            public_key.as_ptr(),
            public_key.len(),
            message.as_ptr(),
            message.len(),
            signature.as_ptr(),
            signature.len(),
        )
    };
    assert_eq!(valid_status, status::CRYPTO_OK);

    signature[0] ^= 0x01;
    let invalid_status = unsafe {
        ed25519::rm_crypto_ed25519_verify(
            public_key.as_ptr(),
            public_key.len(),
            message.as_ptr(),
            message.len(),
            signature.as_ptr(),
            signature.len(),
        )
    };
    assert_eq!(invalid_status, status::CRYPTO_INVALID_SIGNATURE);
}

#[test]
fn supplied_key_ffi_constructors_are_deterministic() {
    let mut ed_public_a = [0u8; ed25519::ED25519_PUBLIC_KEY_LEN];
    let mut ed_public_b = [0u8; ed25519::ED25519_PUBLIC_KEY_LEN];
    let mut ed_secret_a = [0u8; ed25519::ED25519_SECRET_KEY_LEN];
    let mut ed_secret_b = [0u8; ed25519::ED25519_SECRET_KEY_LEN];
    let ed_seed = [0x07u8; ed25519::ED25519_SECRET_KEY_LEN];
    let ed_status_a = unsafe {
        ed25519::rm_crypto_ed25519_generate_keypair_from_seed(
            ed_seed.as_ptr(),
            ed_seed.len(),
            ed_public_a.as_mut_ptr(),
            ed_public_a.len(),
            ed_secret_a.as_mut_ptr(),
            ed_secret_a.len(),
        )
    };
    let ed_status_b = unsafe {
        ed25519::rm_crypto_ed25519_generate_keypair_from_seed(
            ed_seed.as_ptr(),
            ed_seed.len(),
            ed_public_b.as_mut_ptr(),
            ed_public_b.len(),
            ed_secret_b.as_mut_ptr(),
            ed_secret_b.len(),
        )
    };
    assert_eq!(ed_status_a, status::CRYPTO_OK);
    assert_eq!(ed_status_b, status::CRYPTO_OK);
    assert_eq!(ed_public_a, ed_public_b);
    assert_eq!(ed_secret_a, ed_seed);
    assert_eq!(ed_secret_b, ed_seed);
    let ed_bad_status = unsafe {
        ed25519::rm_crypto_ed25519_generate_keypair_from_seed(
            ed_seed.as_ptr(),
            ed_seed.len() - 1,
            ed_public_a.as_mut_ptr(),
            ed_public_a.len(),
            ed_secret_a.as_mut_ptr(),
            ed_secret_a.len(),
        )
    };
    assert_eq!(ed_bad_status, status::CRYPTO_INVALID_KEY);

    let mut p256_secret = [0u8; p256::P256_SECRET_KEY_LEN];
    p256_secret[p256::P256_SECRET_KEY_LEN - 1] = 1;
    let mut p256_public = [0u8; p256::P256_PUBLIC_KEY_COMPRESSED_LEN];
    let mut p256_secret_out = [0u8; p256::P256_SECRET_KEY_LEN];
    let p256_status = unsafe {
        p256::rm_crypto_p256_generate_keypair_from_secret_key(
            p256_secret.as_ptr(),
            p256_secret.len(),
            p256_public.as_mut_ptr(),
            p256_public.len(),
            p256_secret_out.as_mut_ptr(),
            p256_secret_out.len(),
        )
    };
    assert_eq!(p256_status, status::CRYPTO_OK);
    assert_eq!(p256_secret_out, p256_secret);

    let mut p384_secret = [0u8; p384::P384_SECRET_KEY_LEN];
    p384_secret[p384::P384_SECRET_KEY_LEN - 1] = 1;
    let mut p384_public = [0u8; p384::P384_PUBLIC_KEY_COMPRESSED_LEN];
    let mut p384_secret_out = [0u8; p384::P384_SECRET_KEY_LEN];
    let p384_status = unsafe {
        p384::rm_crypto_p384_generate_keypair_from_secret_key(
            p384_secret.as_ptr(),
            p384_secret.len(),
            p384_public.as_mut_ptr(),
            p384_public.len(),
            p384_secret_out.as_mut_ptr(),
            p384_secret_out.len(),
        )
    };
    assert_eq!(p384_status, status::CRYPTO_OK);
    assert_eq!(p384_secret_out, p384_secret);

    let mut p521_secret = [0u8; p521::P521_SECRET_KEY_LEN];
    p521_secret[p521::P521_SECRET_KEY_LEN - 1] = 1;
    let mut p521_public = [0u8; p521::P521_PUBLIC_KEY_COMPRESSED_LEN];
    let mut p521_secret_out = [0u8; p521::P521_SECRET_KEY_LEN];
    let p521_status = unsafe {
        p521::rm_crypto_p521_generate_keypair_from_secret_key(
            p521_secret.as_ptr(),
            p521_secret.len(),
            p521_public.as_mut_ptr(),
            p521_public.len(),
            p521_secret_out.as_mut_ptr(),
            p521_secret_out.len(),
        )
    };
    assert_eq!(p521_status, status::CRYPTO_OK);
    assert_eq!(p521_secret_out, p521_secret);

    let mut secp_secret = [0u8; secp256k1::SECP256K1_SECRET_KEY_LEN];
    secp_secret[secp256k1::SECP256K1_SECRET_KEY_LEN - 1] = 1;
    let mut secp_public = [0u8; secp256k1::SECP256K1_PUBLIC_KEY_COMPRESSED_LEN];
    let mut secp_secret_out = [0u8; secp256k1::SECP256K1_SECRET_KEY_LEN];
    let secp_status = unsafe {
        secp256k1::rm_crypto_secp256k1_generate_keypair_from_secret_key(
            secp_secret.as_ptr(),
            secp_secret.len(),
            secp_public.as_mut_ptr(),
            secp_public.len(),
            secp_secret_out.as_mut_ptr(),
            secp_secret_out.len(),
        )
    };
    assert_eq!(secp_status, status::CRYPTO_OK);
    assert_eq!(secp_secret_out, secp_secret);

    let x25519_seed = [0x09u8; x25519::X25519_SECRET_KEY_LEN];
    let mut x25519_public_a = [0u8; x25519::X25519_PUBLIC_KEY_LEN];
    let mut x25519_public_b = [0u8; x25519::X25519_PUBLIC_KEY_LEN];
    let mut x25519_secret_a = [0u8; x25519::X25519_SECRET_KEY_LEN];
    let mut x25519_secret_b = [0u8; x25519::X25519_SECRET_KEY_LEN];
    let x25519_status_a = unsafe {
        x25519::rm_crypto_x25519_generate_keypair_from_seed(
            x25519_seed.as_ptr(),
            x25519_seed.len(),
            x25519_public_a.as_mut_ptr(),
            x25519_public_a.len(),
            x25519_secret_a.as_mut_ptr(),
            x25519_secret_a.len(),
        )
    };
    let x25519_status_b = unsafe {
        x25519::rm_crypto_x25519_generate_keypair_from_seed(
            x25519_seed.as_ptr(),
            x25519_seed.len(),
            x25519_public_b.as_mut_ptr(),
            x25519_public_b.len(),
            x25519_secret_b.as_mut_ptr(),
            x25519_secret_b.len(),
        )
    };
    assert_eq!(x25519_status_a, status::CRYPTO_OK);
    assert_eq!(x25519_status_b, status::CRYPTO_OK);
    assert_eq!(x25519_public_a, x25519_public_b);
    assert_eq!(x25519_secret_a, x25519_seed);
    assert_eq!(x25519_secret_b, x25519_seed);

    let ml_dsa_seed = [0x0bu8; ml_dsa_44::ML_DSA_44_SECRET_SEED_LEN];
    let mut ml_dsa_44_public = [0u8; ml_dsa_44::ML_DSA_44_PUBLIC_KEY_LEN];
    let mut ml_dsa_44_secret = [0u8; ml_dsa_44::ML_DSA_44_SECRET_SEED_LEN];
    let ml_dsa_44_status = unsafe {
        ml_dsa_44::rm_crypto_ml_dsa_44_generate_keypair_from_seed(
            ml_dsa_seed.as_ptr(),
            ml_dsa_seed.len(),
            ml_dsa_44_public.as_mut_ptr(),
            ml_dsa_44_public.len(),
            ml_dsa_44_secret.as_mut_ptr(),
            ml_dsa_44_secret.len(),
        )
    };
    assert_eq!(ml_dsa_44_status, status::CRYPTO_OK);
    assert_eq!(ml_dsa_44_secret, ml_dsa_seed);

    let mut ml_dsa_65_public = [0u8; ml_dsa_65::ML_DSA_65_PUBLIC_KEY_LEN];
    let mut ml_dsa_65_secret = [0u8; ml_dsa_65::ML_DSA_65_SECRET_SEED_LEN];
    let ml_dsa_65_status = unsafe {
        ml_dsa_65::rm_crypto_ml_dsa_65_generate_keypair_from_seed(
            ml_dsa_seed.as_ptr(),
            ml_dsa_seed.len(),
            ml_dsa_65_public.as_mut_ptr(),
            ml_dsa_65_public.len(),
            ml_dsa_65_secret.as_mut_ptr(),
            ml_dsa_65_secret.len(),
        )
    };
    assert_eq!(ml_dsa_65_status, status::CRYPTO_OK);
    assert_eq!(ml_dsa_65_secret, ml_dsa_seed);

    let mut ml_dsa_87_public = [0u8; ml_dsa_87::ML_DSA_87_PUBLIC_KEY_LEN];
    let mut ml_dsa_87_secret = [0u8; ml_dsa_87::ML_DSA_87_SECRET_SEED_LEN];
    let ml_dsa_87_status = unsafe {
        ml_dsa_87::rm_crypto_ml_dsa_87_generate_keypair_from_seed(
            ml_dsa_seed.as_ptr(),
            ml_dsa_seed.len(),
            ml_dsa_87_public.as_mut_ptr(),
            ml_dsa_87_public.len(),
            ml_dsa_87_secret.as_mut_ptr(),
            ml_dsa_87_secret.len(),
        )
    };
    assert_eq!(ml_dsa_87_status, status::CRYPTO_OK);
    assert_eq!(ml_dsa_87_secret, ml_dsa_seed);

    let ml_kem_seed = [0x0du8; ml_kem_512::ML_KEM_512_SECRET_KEY_LEN];
    let ml_kem_rand = [0x0eu8; ml_kem_512::ML_KEM_512_ENCAPS_RANDOMNESS_LEN];
    let mut kem512_public = [0u8; ml_kem_512::ML_KEM_512_PUBLIC_KEY_LEN];
    let mut kem512_secret = [0u8; ml_kem_512::ML_KEM_512_SECRET_KEY_LEN];
    let kem512_key_status = unsafe {
        ml_kem_512::rm_crypto_ml_kem_512_generate_keypair_from_seed(
            ml_kem_seed.as_ptr(),
            ml_kem_seed.len(),
            kem512_public.as_mut_ptr(),
            kem512_public.len(),
            kem512_secret.as_mut_ptr(),
            kem512_secret.len(),
        )
    };
    assert_eq!(kem512_key_status, status::CRYPTO_OK);
    assert_eq!(kem512_secret, ml_kem_seed);

    let mut kem512_ciphertext = [0u8; ml_kem_512::ML_KEM_512_CIPHERTEXT_LEN];
    let mut kem512_shared_encap = [0u8; ml_kem_512::ML_KEM_512_SHARED_SECRET_LEN];
    let kem512_encap_status = unsafe {
        ml_kem_512::rm_crypto_ml_kem_512_encapsulate_derand(
            kem512_public.as_ptr(),
            kem512_public.len(),
            ml_kem_rand.as_ptr(),
            ml_kem_rand.len(),
            kem512_ciphertext.as_mut_ptr(),
            kem512_ciphertext.len(),
            kem512_shared_encap.as_mut_ptr(),
            kem512_shared_encap.len(),
        )
    };
    assert_eq!(kem512_encap_status, status::CRYPTO_OK);

    let mut kem512_shared_decap = [0u8; ml_kem_512::ML_KEM_512_SHARED_SECRET_LEN];
    let kem512_decap_status = unsafe {
        ml_kem_512::rm_crypto_ml_kem_512_decapsulate(
            kem512_ciphertext.as_ptr(),
            kem512_ciphertext.len(),
            kem512_secret.as_ptr(),
            kem512_secret.len(),
            kem512_shared_decap.as_mut_ptr(),
            kem512_shared_decap.len(),
        )
    };
    assert_eq!(kem512_decap_status, status::CRYPTO_OK);
    assert_eq!(kem512_shared_encap, kem512_shared_decap);

    let mut kem768_public = [0u8; ml_kem_768::ML_KEM_768_PUBLIC_KEY_LEN];
    let mut kem768_secret = [0u8; ml_kem_768::ML_KEM_768_SECRET_KEY_LEN];
    let kem768_key_status = unsafe {
        ml_kem_768::rm_crypto_ml_kem_768_generate_keypair_from_seed(
            ml_kem_seed.as_ptr(),
            ml_kem_seed.len(),
            kem768_public.as_mut_ptr(),
            kem768_public.len(),
            kem768_secret.as_mut_ptr(),
            kem768_secret.len(),
        )
    };
    assert_eq!(kem768_key_status, status::CRYPTO_OK);
    assert_eq!(kem768_secret, ml_kem_seed);

    let mut kem768_ciphertext = [0u8; ml_kem_768::ML_KEM_768_CIPHERTEXT_LEN];
    let mut kem768_shared_encap = [0u8; ml_kem_768::ML_KEM_768_SHARED_SECRET_LEN];
    let kem768_encap_status = unsafe {
        ml_kem_768::rm_crypto_ml_kem_768_encapsulate_derand(
            kem768_public.as_ptr(),
            kem768_public.len(),
            ml_kem_rand.as_ptr(),
            ml_kem_rand.len(),
            kem768_ciphertext.as_mut_ptr(),
            kem768_ciphertext.len(),
            kem768_shared_encap.as_mut_ptr(),
            kem768_shared_encap.len(),
        )
    };
    assert_eq!(kem768_encap_status, status::CRYPTO_OK);

    let mut kem768_shared_decap = [0u8; ml_kem_768::ML_KEM_768_SHARED_SECRET_LEN];
    let kem768_decap_status = unsafe {
        ml_kem_768::rm_crypto_ml_kem_768_decapsulate(
            kem768_ciphertext.as_ptr(),
            kem768_ciphertext.len(),
            kem768_secret.as_ptr(),
            kem768_secret.len(),
            kem768_shared_decap.as_mut_ptr(),
            kem768_shared_decap.len(),
        )
    };
    assert_eq!(kem768_decap_status, status::CRYPTO_OK);
    assert_eq!(kem768_shared_encap, kem768_shared_decap);

    let mut kem1024_public = [0u8; ml_kem_1024::ML_KEM_1024_PUBLIC_KEY_LEN];
    let mut kem1024_secret = [0u8; ml_kem_1024::ML_KEM_1024_SECRET_KEY_LEN];
    let kem1024_key_status = unsafe {
        ml_kem_1024::rm_crypto_ml_kem_1024_generate_keypair_from_seed(
            ml_kem_seed.as_ptr(),
            ml_kem_seed.len(),
            kem1024_public.as_mut_ptr(),
            kem1024_public.len(),
            kem1024_secret.as_mut_ptr(),
            kem1024_secret.len(),
        )
    };
    assert_eq!(kem1024_key_status, status::CRYPTO_OK);
    assert_eq!(kem1024_secret, ml_kem_seed);

    let mut kem1024_ciphertext = [0u8; ml_kem_1024::ML_KEM_1024_CIPHERTEXT_LEN];
    let mut kem1024_shared_encap = [0u8; ml_kem_1024::ML_KEM_1024_SHARED_SECRET_LEN];
    let kem1024_encap_status = unsafe {
        ml_kem_1024::rm_crypto_ml_kem_1024_encapsulate_derand(
            kem1024_public.as_ptr(),
            kem1024_public.len(),
            ml_kem_rand.as_ptr(),
            ml_kem_rand.len(),
            kem1024_ciphertext.as_mut_ptr(),
            kem1024_ciphertext.len(),
            kem1024_shared_encap.as_mut_ptr(),
            kem1024_shared_encap.len(),
        )
    };
    assert_eq!(kem1024_encap_status, status::CRYPTO_OK);

    let mut kem1024_shared_decap = [0u8; ml_kem_1024::ML_KEM_1024_SHARED_SECRET_LEN];
    let kem1024_decap_status = unsafe {
        ml_kem_1024::rm_crypto_ml_kem_1024_decapsulate(
            kem1024_ciphertext.as_ptr(),
            kem1024_ciphertext.len(),
            kem1024_secret.as_ptr(),
            kem1024_secret.len(),
            kem1024_shared_decap.as_mut_ptr(),
            kem1024_shared_decap.len(),
        )
    };
    assert_eq!(kem1024_decap_status, status::CRYPTO_OK);
    assert_eq!(kem1024_shared_encap, kem1024_shared_decap);
}

#[test]
fn rsa_ffi_verifies_pkcs1v15_and_pss() -> Result<(), crypto_core::CryptoError> {
    let public_der = decode_base64url(RSA_PUBLIC_KEY_DER)?;
    let message = decode_base64url(RSA_MESSAGE)?;
    let pkcs1_signature = decode_base64url(RSA_PKCS1V15_SHA256_SIGNATURE)?;
    let pkcs1_status = unsafe {
        rsa_ffi::rm_crypto_rsa_verify_pkcs1v15(
            public_der.as_ptr(),
            public_der.len(),
            rsa_ffi::RSA_PUBLIC_KEY_ENCODING_PKCS1_DER,
            rsa_ffi::RSA_HASH_SHA256,
            message.as_ptr(),
            message.len(),
            pkcs1_signature.as_ptr(),
            pkcs1_signature.len(),
        )
    };
    assert_eq!(pkcs1_status, status::CRYPTO_OK);

    let pss_signature = decode_base64url(RSA_PSS_SHA256_SIGNATURE)?;
    let pss_status = unsafe {
        rsa_ffi::rm_crypto_rsa_verify_pss(
            public_der.as_ptr(),
            public_der.len(),
            rsa_ffi::RSA_PUBLIC_KEY_ENCODING_PKCS1_DER,
            rsa_ffi::RSA_HASH_SHA256,
            rsa_ffi::RSA_HASH_SHA256,
            32,
            message.as_ptr(),
            message.len(),
            pss_signature.as_ptr(),
            pss_signature.len(),
        )
    };
    assert_eq!(pss_status, status::CRYPTO_OK);
    let bad_suite_status = unsafe {
        rsa_ffi::rm_crypto_rsa_verify_pkcs1v15(
            public_der.as_ptr(),
            public_der.len(),
            rsa_ffi::RSA_PUBLIC_KEY_ENCODING_PKCS1_DER,
            99,
            message.as_ptr(),
            message.len(),
            pkcs1_signature.as_ptr(),
            pkcs1_signature.len(),
        )
    };
    assert_eq!(bad_suite_status, status::CRYPTO_INVALID_ARGUMENT);
    Ok(())
}

const RSA_PUBLIC_KEY_DER: &str = "MIIBCgKCAQEAtLGfC3GxzVAbnFDLYwUlIB52PJUl3yVGcY2X-3vFcQsbOhdYKVW7Ug1G0-adGVsz7Sl4CAVZCgDy9LVawN6Wl5TUj8_obkDrtKv9srFmUm0OfYP4REpZq0OBKAs6jf5E5aHqe09edvsO3LOJtVqhHgtFM_xvobGr4TtaPGSoFjssvzJ9YVyK08xDOhCaT4K6ukKlaKBTiOjgVxUtmDRnzct--bNxkhJ88ObqNyJTbp78FWKMsKNfJCTVnKnQIdDMCCQgS6AIXm_d2bPK6FrvDphqfem9ysGQaqPeZjCCoEU9lF9ha_v29bQn6CPxzT7cCYW8V-J_mqhOIwqocTI7jQIDAQAB";
const RSA_MESSAGE: &str = "UmVhbGx5TWUgc2lnbmF0dXJlIGNvbmZvcm1hbmNlIHZlY3Rvcg";
const RSA_PKCS1V15_SHA256_SIGNATURE: &str = "Re77CuddLv7YajqprynKArLWsc_5tMp5UOAgi1M4cHgj9lKJ14VuI78Lx4if-ngxz4hDxwbRMOh0V50DkRYcd_oyfdzecsqo-SisuGGGer5gWJ8h2_8wyrKuSXroNt2CyPUGv5Jn6K5I9krL6Cx0U7_MyE6HZJNSVH1w6VpxNsf8iNvp-p_eFkt8dEVuBFxsNlGQV3ltFNVg99kBDOiammOuXIrkCf_V67xy3Hc2RkptbmNHTnlC8hw8WBoMH5ds5UcYMuHVgRr8CmXr4YNX9Vel46L7UV69FN5xcJNTLEW0_Ylo9N_Csh8urYUbupfvZ49uWMOzyReMg4tzu90lSw";
const RSA_PSS_SHA256_SIGNATURE: &str = "bYeyCHaW_4vy7QDQlAtm7fY5CV9XH4Kt0eINKPRd9E1YFrvI2KLaVgG7-T0uGPu8P_t3BV0n_FJJBRxMlSySqFqT_VllgzXuBJ3A7fC_pFyMPK6A3XZ0Y_3rWShvjeZnBf_doMSjoGuWFSaB0K4IOAiyjyoJ3RGea6ikt-5nGPvaiFb6K3YXZTJXavH8AKu3J19V2kTrUGHZ6Lf5RuqWHFyzFsEzNPcp13ezECkVMZHQEwLxt9Li_mWqXDhPF4bpPCUpGljfmsgqo0RBYogEau7YxqaS15-HhLhWTaJYGEcvWBL9burCgU4nlqfEt9gU0m2EDhhUGR38CS86RSiwEw";

fn decode_base64url(value: &str) -> Result<Vec<u8>, crypto_core::CryptoError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| crypto_core::CryptoError::InvalidKey)
}

#[test]
fn hmac_ffi_authenticates_and_rejects_tampering() {
    let key = [0x0bu8; 20];
    let message = b"Hi There";
    let expected = [
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1,
        0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32,
        0xcf, 0xf7,
    ];
    let mut tag = [0u8; hmac::HMAC_SHA256_TAG_LEN];

    let auth_status = unsafe {
        hmac::rm_crypto_hmac_authenticate(
            hmac::HMAC_SUITE_SHA256,
            key.as_ptr(),
            key.len(),
            message.as_ptr(),
            message.len(),
            tag.as_mut_ptr(),
            tag.len(),
        )
    };
    assert_eq!(auth_status, status::CRYPTO_OK);
    assert_eq!(tag, expected);

    let verify_status = unsafe {
        hmac::rm_crypto_hmac_verify(
            hmac::HMAC_SUITE_SHA256,
            key.as_ptr(),
            key.len(),
            message.as_ptr(),
            message.len(),
            tag.as_ptr(),
            tag.len(),
        )
    };
    assert_eq!(verify_status, status::CRYPTO_OK);

    tag[0] ^= 0x01;
    let tamper_status = unsafe {
        hmac::rm_crypto_hmac_verify(
            hmac::HMAC_SUITE_SHA256,
            key.as_ptr(),
            key.len(),
            message.as_ptr(),
            message.len(),
            tag.as_ptr(),
            tag.len(),
        )
    };
    assert_eq!(tamper_status, status::CRYPTO_AUTHENTICATION_FAILED);
}

#[test]
fn digest_ffis_hash_messages() {
    let message = b"reallyme ffi digest vector";
    let mut sha2_out = [0u8; sha2_256::SHA2_256_DIGEST_LEN];
    let mut sha2_384_out = [0u8; sha2::SHA2_384_DIGEST_LEN];
    let mut sha2_512_out = [0u8; sha2::SHA2_512_DIGEST_LEN];
    let mut sha3_224_out = [0u8; sha3::SHA3_224_DIGEST_LEN];
    let mut sha3_out = [0u8; sha3_256::SHA3_256_DIGEST_LEN];
    let mut sha3_384_out = [0u8; sha3::SHA3_384_DIGEST_LEN];
    let mut sha3_512_out = [0u8; sha3::SHA3_512_DIGEST_LEN];

    let sha2_status = unsafe {
        sha2_256::rm_crypto_sha2_256_digest(
            message.as_ptr(),
            message.len(),
            sha2_out.as_mut_ptr(),
            sha2_out.len(),
        )
    };
    let sha3_status = unsafe {
        sha3_256::rm_crypto_sha3_256_digest(
            message.as_ptr(),
            message.len(),
            sha3_out.as_mut_ptr(),
            sha3_out.len(),
        )
    };
    let sha3_224_status = unsafe {
        sha3::rm_crypto_sha3_224_digest(
            message.as_ptr(),
            message.len(),
            sha3_224_out.as_mut_ptr(),
            sha3_224_out.len(),
        )
    };
    let sha3_384_status = unsafe {
        sha3::rm_crypto_sha3_384_digest(
            message.as_ptr(),
            message.len(),
            sha3_384_out.as_mut_ptr(),
            sha3_384_out.len(),
        )
    };
    let sha3_512_status = unsafe {
        sha3::rm_crypto_sha3_512_digest(
            message.as_ptr(),
            message.len(),
            sha3_512_out.as_mut_ptr(),
            sha3_512_out.len(),
        )
    };
    let sha2_384_status = unsafe {
        sha2::rm_crypto_sha2_384_digest(
            message.as_ptr(),
            message.len(),
            sha2_384_out.as_mut_ptr(),
            sha2_384_out.len(),
        )
    };
    let sha2_512_status = unsafe {
        sha2::rm_crypto_sha2_512_digest(
            message.as_ptr(),
            message.len(),
            sha2_512_out.as_mut_ptr(),
            sha2_512_out.len(),
        )
    };

    assert_eq!(sha2_status, status::CRYPTO_OK);
    assert_eq!(sha2_384_status, status::CRYPTO_OK);
    assert_eq!(sha2_512_status, status::CRYPTO_OK);
    assert_eq!(sha3_224_status, status::CRYPTO_OK);
    assert_eq!(sha3_status, status::CRYPTO_OK);
    assert_eq!(sha3_384_status, status::CRYPTO_OK);
    assert_eq!(sha3_512_status, status::CRYPTO_OK);
    assert_ne!(sha2_out, [0u8; sha2_256::SHA2_256_DIGEST_LEN]);
    assert_ne!(sha2_384_out, [0u8; sha2::SHA2_384_DIGEST_LEN]);
    assert_ne!(sha2_512_out, [0u8; sha2::SHA2_512_DIGEST_LEN]);
    assert_ne!(sha3_224_out, [0u8; sha3::SHA3_224_DIGEST_LEN]);
    assert_ne!(sha3_out, [0u8; sha3_256::SHA3_256_DIGEST_LEN]);
    assert_ne!(sha3_384_out, [0u8; sha3::SHA3_384_DIGEST_LEN]);
    assert_ne!(sha3_512_out, [0u8; sha3::SHA3_512_DIGEST_LEN]);
    assert_ne!(sha2_out, sha3_out);
    assert_eq!(sha2_384_out.len(), sha2::SHA2_384_DIGEST_LEN);
    assert_eq!(sha2_512_out.len(), sha2::SHA2_512_DIGEST_LEN);
    assert_eq!(sha3_224_out.len(), sha3::SHA3_224_DIGEST_LEN);
    assert_eq!(sha3_384_out.len(), sha3::SHA3_384_DIGEST_LEN);
    assert_eq!(sha3_512_out.len(), sha3::SHA3_512_DIGEST_LEN);
}

#[test]
fn aes256_gcm_ffi_encrypts_decrypts_and_rejects_tampering() {
    let key = [7u8; aes256_gcm::AES256_GCM_KEY_LEN];
    let nonce = [9u8; aes256_gcm::AES256_GCM_NONCE_LEN];
    let aad = b"aad";
    let plaintext = b"ffi plaintext";
    let mut ciphertext = [0u8; 64];
    let mut ciphertext_len = 0usize;

    let encrypt_status = unsafe {
        aes256_gcm::rm_crypto_aes256_gcm_encrypt(
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
        plaintext.len() + aes256_gcm::AES256_GCM_TAG_LEN
    );

    let mut decrypted = [0u8; 64];
    let mut decrypted_len = 0usize;
    let decrypt_status = unsafe {
        aes256_gcm::rm_crypto_aes256_gcm_decrypt(
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
        aes256_gcm::rm_crypto_aes256_gcm_decrypt(
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
fn aes256_kw_ffi_wraps_unwraps_and_rejects_tampering() {
    let kek = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let key_data = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f,
    ];
    let expected_wrapped = [
        0x28, 0xc9, 0xf4, 0x04, 0xc4, 0xb8, 0x10, 0xf4, 0xcb, 0xcc, 0xb3, 0x5c, 0xfb, 0x87, 0xf8,
        0x26, 0x3f, 0x57, 0x86, 0xe2, 0xd8, 0x0e, 0xd3, 0x26, 0xcb, 0xc7, 0xf0, 0xe7, 0x1a, 0x99,
        0xf4, 0x3b, 0xfb, 0x98, 0x8b, 0x9b, 0x7a, 0x02, 0xdd, 0x21,
    ];
    let mut wrapped = [0u8; 48];
    let mut wrapped_len = 0usize;

    let wrap_status = unsafe {
        aes_kw::rm_crypto_aes256_kw_wrap_key(
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
        aes_kw::rm_crypto_aes256_kw_unwrap_key(
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
    assert_eq!(&unwrapped[..unwrapped_len], key_data);

    wrapped[0] ^= 0x01;
    let tamper_status = unsafe {
        aes_kw::rm_crypto_aes256_kw_unwrap_key(
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

#[test]
fn argon2id_ffi_derives_and_rejects_invalid_inputs() {
    let secret = b"ffi passphrase";
    let salt = [3u8; 16];
    let mut derived = [0u8; argon2id::ARGON2ID_DERIVED_KEY_LEN];

    let derive_status = unsafe {
        argon2id::rm_crypto_argon2id_derive_key(
            1,
            secret.as_ptr(),
            secret.len(),
            salt.as_ptr(),
            salt.len(),
            derived.as_mut_ptr(),
            derived.len(),
        )
    };
    assert_eq!(derive_status, status::CRYPTO_OK);
    assert_ne!(derived, [0u8; argon2id::ARGON2ID_DERIVED_KEY_LEN]);

    let invalid_status = unsafe {
        argon2id::rm_crypto_argon2id_derive_key(
            99,
            secret.as_ptr(),
            secret.len(),
            salt.as_ptr(),
            salt.len(),
            derived.as_mut_ptr(),
            derived.len(),
        )
    };
    assert_eq!(invalid_status, status::CRYPTO_INVALID_ARGUMENT);
}

#[test]
fn pbkdf2_ffi_derives_known_answers_and_rejects_invalid_inputs() {
    let password = b"password";
    let salt = b"salt";
    let expected_sha256 = [
        0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8,
        0x37, 0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48, 0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b,
        0xe1, 0x7b,
    ];
    let expected_sha512 = [
        0x86, 0x7f, 0x70, 0xcf, 0x1a, 0xde, 0x02, 0xcf, 0xf3, 0x75, 0x25, 0x99, 0xa3, 0xa5, 0x3d,
        0xc4, 0xaf, 0x34, 0xc7, 0xa6, 0x69, 0x81, 0x5a, 0xe5, 0xd5, 0x13, 0x55, 0x4e, 0x1c, 0x8c,
        0xf2, 0x52, 0xc0, 0x2d, 0x47, 0x0a, 0x28, 0x5a, 0x05, 0x01, 0xba, 0xd9, 0x99, 0xbf, 0xe9,
        0x43, 0xc0, 0x8f, 0x05, 0x02, 0x35, 0xd7, 0xd6, 0x8b, 0x1d, 0xa5, 0x5e, 0x63, 0xf7, 0x3b,
        0x60, 0xa5, 0x7f, 0xce,
    ];

    let mut sha256_out = [0u8; 32];
    let sha256_status = unsafe {
        pbkdf2::rm_crypto_pbkdf2_hmac_sha256_derive_key(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            1,
            sha256_out.as_mut_ptr(),
            sha256_out.len(),
        )
    };
    assert_eq!(sha256_status, status::CRYPTO_OK);
    assert_eq!(sha256_out, expected_sha256);

    let mut sha512_out = [0u8; 64];
    let sha512_status = unsafe {
        pbkdf2::rm_crypto_pbkdf2_hmac_sha512_derive_key(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            1,
            sha512_out.as_mut_ptr(),
            sha512_out.len(),
        )
    };
    assert_eq!(sha512_status, status::CRYPTO_OK);
    assert_eq!(sha512_out, expected_sha512);

    let invalid_password_status = unsafe {
        pbkdf2::rm_crypto_pbkdf2_hmac_sha256_derive_key(
            password.as_ptr(),
            0,
            salt.as_ptr(),
            salt.len(),
            1,
            sha256_out.as_mut_ptr(),
            sha256_out.len(),
        )
    };
    assert_eq!(invalid_password_status, status::CRYPTO_INVALID_KEY);

    let invalid_iterations_status = unsafe {
        pbkdf2::rm_crypto_pbkdf2_hmac_sha256_derive_key(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            0,
            sha256_out.as_mut_ptr(),
            sha256_out.len(),
        )
    };
    assert_eq!(invalid_iterations_status, status::CRYPTO_INVALID_ARGUMENT);

    let invalid_output_status = unsafe {
        pbkdf2::rm_crypto_pbkdf2_hmac_sha256_derive_key(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            1,
            sha256_out.as_mut_ptr(),
            0,
        )
    };
    assert_eq!(invalid_output_status, status::CRYPTO_INVALID_ARGUMENT);
}

#[test]
fn hkdf_ffi_derives_supported_lengths_and_rejects_bad_suite() {
    let ikm = b"ffi root key material";
    let salt = b"ffi salt";
    let info = b"reallyme/ffi/hkdf";
    let mut sha2_output = [0u8; 32];
    let mut sha3_output = [0u8; 32];

    let sha2_status = unsafe {
        hkdf::rm_crypto_hkdf_derive(
            hkdf::HKDF_SUITE_SHA2_256,
            ikm.as_ptr(),
            ikm.len(),
            salt.as_ptr(),
            salt.len(),
            info.as_ptr(),
            info.len(),
            sha2_output.as_mut_ptr(),
            sha2_output.len(),
        )
    };
    let sha3_status = unsafe {
        hkdf::rm_crypto_hkdf_derive(
            hkdf::HKDF_SUITE_SHA3_256,
            ikm.as_ptr(),
            ikm.len(),
            salt.as_ptr(),
            salt.len(),
            info.as_ptr(),
            info.len(),
            sha3_output.as_mut_ptr(),
            sha3_output.len(),
        )
    };

    assert_eq!(sha2_status, status::CRYPTO_OK);
    assert_eq!(sha3_status, status::CRYPTO_OK);
    assert_ne!(sha2_output, [0u8; 32]);
    assert_ne!(sha3_output, [0u8; 32]);
    assert_ne!(sha2_output, sha3_output);

    let invalid_status = unsafe {
        hkdf::rm_crypto_hkdf_derive(
            99,
            ikm.as_ptr(),
            ikm.len(),
            salt.as_ptr(),
            salt.len(),
            info.as_ptr(),
            info.len(),
            sha2_output.as_mut_ptr(),
            sha2_output.len(),
        )
    };
    assert_eq!(invalid_status, status::CRYPTO_INVALID_ARGUMENT);
}

#[test]
fn csprng_ffi_generates_random_material() {
    let mut random = [0u8; 32];
    let mut nonce = [0u8; csprng::CSPRNG_AEAD_NONCE_12_LEN];
    let mut salt16 = [0u8; csprng::CSPRNG_ARGON2_SALT_16_LEN];
    let mut salt32 = [0u8; csprng::CSPRNG_ARGON2_SALT_32_LEN];

    let random_status =
        unsafe { csprng::rm_crypto_csprng_generate_bytes(random.as_mut_ptr(), random.len()) };
    let nonce_status =
        unsafe { csprng::rm_crypto_csprng_generate_aead_nonce_12(nonce.as_mut_ptr(), nonce.len()) };
    let salt16_status = unsafe {
        csprng::rm_crypto_csprng_generate_argon2_salt_16(salt16.as_mut_ptr(), salt16.len())
    };
    let salt32_status = unsafe {
        csprng::rm_crypto_csprng_generate_argon2_salt_32(salt32.as_mut_ptr(), salt32.len())
    };

    assert_eq!(random_status, status::CRYPTO_OK);
    assert_eq!(nonce_status, status::CRYPTO_OK);
    assert_eq!(salt16_status, status::CRYPTO_OK);
    assert_eq!(salt32_status, status::CRYPTO_OK);
    assert_ne!(random, [0u8; 32]);
    assert_ne!(nonce, [0u8; csprng::CSPRNG_AEAD_NONCE_12_LEN]);
    assert_ne!(salt16, [0u8; csprng::CSPRNG_ARGON2_SALT_16_LEN]);
    assert_ne!(salt32, [0u8; csprng::CSPRNG_ARGON2_SALT_32_LEN]);
}

#[test]
fn constant_time_ffi_reports_equal_without_throwing_on_mismatch() {
    let left = b"same bytes";
    let right = b"same bytes";
    let different = b"diff bytes";
    let mut equal = 0i32;

    let equal_status = unsafe {
        constant_time::rm_crypto_constant_time_equal(
            left.as_ptr(),
            left.len(),
            right.as_ptr(),
            right.len(),
            &mut equal,
        )
    };
    assert_eq!(equal_status, status::CRYPTO_OK);
    assert_eq!(equal, 1);

    let different_status = unsafe {
        constant_time::rm_crypto_constant_time_equal(
            left.as_ptr(),
            left.len(),
            different.as_ptr(),
            different.len(),
            &mut equal,
        )
    };
    assert_eq!(different_status, status::CRYPTO_OK);
    assert_eq!(equal, 0);
}

#[test]
fn ed25519_ffi_covers_keygen_sign_verify_and_encoding() {
    let message = b"ed25519 ffi";
    let mut public = [0u8; ed25519::ED25519_PUBLIC_KEY_LEN];
    let mut secret = [0u8; ed25519::ED25519_SECRET_KEY_LEN];

    let key_status = unsafe {
        ed25519::rm_crypto_ed25519_generate_keypair(
            public.as_mut_ptr(),
            public.len(),
            secret.as_mut_ptr(),
            secret.len(),
        )
    };
    assert_eq!(key_status, status::CRYPTO_OK);

    let mut signature = [0u8; ed25519::ED25519_SIGNATURE_LEN];
    let sign_status = unsafe {
        ed25519::rm_crypto_ed25519_sign(
            secret.as_ptr(),
            secret.len(),
            message.as_ptr(),
            message.len(),
            signature.as_mut_ptr(),
            signature.len(),
        )
    };
    assert_eq!(sign_status, status::CRYPTO_OK);
    let verify_status = unsafe {
        ed25519::rm_crypto_ed25519_verify(
            public.as_ptr(),
            public.len(),
            message.as_ptr(),
            message.len(),
            signature.as_ptr(),
            signature.len(),
        )
    };
    assert_eq!(verify_status, status::CRYPTO_OK);

    let mut encoded = [0u8; ed25519::ED25519_PUBLIC_KEY_LEN];
    let encode_status = unsafe {
        ed25519::rm_crypto_ed25519_encode_public_key(
            public.as_ptr(),
            public.len(),
            encoded.as_mut_ptr(),
            encoded.len(),
        )
    };
    assert_eq!(encode_status, status::CRYPTO_OK);
    assert_eq!(encoded, public);

    let mut decoded = [0u8; ed25519::ED25519_PUBLIC_KEY_LEN];
    let decode_status = unsafe {
        ed25519::rm_crypto_ed25519_decode_public_key(
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
fn p256_ffi_covers_keygen_sign_verify_and_sec1_encoding() {
    let message = b"p256 ffi";
    let mut public = [0u8; p256::P256_PUBLIC_KEY_COMPRESSED_LEN];
    let mut secret = [0u8; p256::P256_SECRET_KEY_LEN];
    let mut peer_public = [0u8; p256::P256_PUBLIC_KEY_COMPRESSED_LEN];
    let mut peer_secret = [0u8; p256::P256_SECRET_KEY_LEN];
    let key_status = unsafe {
        p256::rm_crypto_p256_generate_keypair(
            public.as_mut_ptr(),
            public.len(),
            secret.as_mut_ptr(),
            secret.len(),
        )
    };
    assert_eq!(key_status, status::CRYPTO_OK);

    let peer_key_status = unsafe {
        p256::rm_crypto_p256_generate_keypair(
            peer_public.as_mut_ptr(),
            peer_public.len(),
            peer_secret.as_mut_ptr(),
            peer_secret.len(),
        )
    };
    assert_eq!(peer_key_status, status::CRYPTO_OK);

    let mut signature = [0u8; p256::P256_SIGNATURE_DER_MAX_LEN];
    let mut signature_len = 0usize;
    let sign_status = unsafe {
        p256::rm_crypto_p256_sign_der_prehash(
            secret.as_ptr(),
            secret.len(),
            message.as_ptr(),
            message.len(),
            signature.as_mut_ptr(),
            signature.len(),
            &mut signature_len,
        )
    };
    assert_eq!(sign_status, status::CRYPTO_OK);
    assert!(signature_len > 0);
    let verify_status = unsafe {
        p256::rm_crypto_p256_verify_der_prehash(
            signature.as_ptr(),
            signature_len,
            message.as_ptr(),
            message.len(),
            public.as_ptr(),
            public.len(),
        )
    };
    assert_eq!(verify_status, status::CRYPTO_OK);

    let mut shared_one = [0u8; p256::P256_SHARED_SECRET_LEN];
    let mut shared_two = [0u8; p256::P256_SHARED_SECRET_LEN];
    let derive_one_status = unsafe {
        p256::rm_crypto_p256_derive_shared_secret(
            secret.as_ptr(),
            secret.len(),
            peer_public.as_ptr(),
            peer_public.len(),
            shared_one.as_mut_ptr(),
            shared_one.len(),
        )
    };
    let derive_two_status = unsafe {
        p256::rm_crypto_p256_derive_shared_secret(
            peer_secret.as_ptr(),
            peer_secret.len(),
            public.as_ptr(),
            public.len(),
            shared_two.as_mut_ptr(),
            shared_two.len(),
        )
    };
    assert_eq!(derive_one_status, status::CRYPTO_OK);
    assert_eq!(derive_two_status, status::CRYPTO_OK);
    assert_eq!(shared_one, shared_two);
    assert_ne!(shared_one, [0u8; p256::P256_SHARED_SECRET_LEN]);

    let mut uncompressed = [0u8; p256::P256_PUBLIC_KEY_UNCOMPRESSED_LEN];
    let decompress_status = unsafe {
        p256::rm_crypto_p256_decompress_public_key(
            public.as_ptr(),
            public.len(),
            uncompressed.as_mut_ptr(),
            uncompressed.len(),
        )
    };
    assert_eq!(decompress_status, status::CRYPTO_OK);

    let mut recompressed = [0u8; p256::P256_PUBLIC_KEY_COMPRESSED_LEN];
    let compress_status = unsafe {
        p256::rm_crypto_p256_compress_public_key(
            uncompressed.as_ptr(),
            uncompressed.len(),
            recompressed.as_mut_ptr(),
            recompressed.len(),
        )
    };
    assert_eq!(compress_status, status::CRYPTO_OK);
    assert_eq!(recompressed, public);
}

#[test]
fn p384_ffi_covers_keygen_sign_verify_and_sec1_encoding() {
    let message = b"p384 ffi";
    let mut public = [0u8; p384::P384_PUBLIC_KEY_COMPRESSED_LEN];
    let mut secret = [0u8; p384::P384_SECRET_KEY_LEN];
    let key_status = unsafe {
        p384::rm_crypto_p384_generate_keypair(
            public.as_mut_ptr(),
            public.len(),
            secret.as_mut_ptr(),
            secret.len(),
        )
    };
    assert_eq!(key_status, status::CRYPTO_OK);

    let mut signature = [0u8; p384::P384_SIGNATURE_DER_MAX_LEN];
    let mut signature_len = 0usize;
    let sign_status = unsafe {
        p384::rm_crypto_p384_sign_der_prehash(
            secret.as_ptr(),
            secret.len(),
            message.as_ptr(),
            message.len(),
            signature.as_mut_ptr(),
            signature.len(),
            &mut signature_len,
        )
    };
    assert_eq!(sign_status, status::CRYPTO_OK);
    assert!(signature_len > 0);
    let verify_status = unsafe {
        p384::rm_crypto_p384_verify_der_prehash(
            signature.as_ptr(),
            signature_len,
            message.as_ptr(),
            message.len(),
            public.as_ptr(),
            public.len(),
        )
    };
    assert_eq!(verify_status, status::CRYPTO_OK);

    let mut uncompressed = [0u8; p384::P384_PUBLIC_KEY_UNCOMPRESSED_LEN];
    let decompress_status = unsafe {
        p384::rm_crypto_p384_decompress_public_key(
            public.as_ptr(),
            public.len(),
            uncompressed.as_mut_ptr(),
            uncompressed.len(),
        )
    };
    assert_eq!(decompress_status, status::CRYPTO_OK);

    let mut recompressed = [0u8; p384::P384_PUBLIC_KEY_COMPRESSED_LEN];
    let compress_status = unsafe {
        p384::rm_crypto_p384_compress_public_key(
            uncompressed.as_ptr(),
            uncompressed.len(),
            recompressed.as_mut_ptr(),
            recompressed.len(),
        )
    };
    assert_eq!(compress_status, status::CRYPTO_OK);
    assert_eq!(recompressed, public);
}

#[test]
fn p521_ffi_covers_keygen_sign_verify_and_sec1_encoding() {
    let message = b"p521 ffi";
    let mut public = [0u8; p521::P521_PUBLIC_KEY_COMPRESSED_LEN];
    let mut secret = [0u8; p521::P521_SECRET_KEY_LEN];
    let key_status = unsafe {
        p521::rm_crypto_p521_generate_keypair(
            public.as_mut_ptr(),
            public.len(),
            secret.as_mut_ptr(),
            secret.len(),
        )
    };
    assert_eq!(key_status, status::CRYPTO_OK);

    let mut signature = [0u8; p521::P521_SIGNATURE_DER_MAX_LEN];
    let mut signature_len = 0usize;
    let sign_status = unsafe {
        p521::rm_crypto_p521_sign_der_prehash(
            secret.as_ptr(),
            secret.len(),
            message.as_ptr(),
            message.len(),
            signature.as_mut_ptr(),
            signature.len(),
            &mut signature_len,
        )
    };
    assert_eq!(sign_status, status::CRYPTO_OK);
    assert!(signature_len > 0);
    let verify_status = unsafe {
        p521::rm_crypto_p521_verify_der_prehash(
            signature.as_ptr(),
            signature_len,
            message.as_ptr(),
            message.len(),
            public.as_ptr(),
            public.len(),
        )
    };
    assert_eq!(verify_status, status::CRYPTO_OK);

    let mut uncompressed = [0u8; p521::P521_PUBLIC_KEY_UNCOMPRESSED_LEN];
    let decompress_status = unsafe {
        p521::rm_crypto_p521_decompress_public_key(
            public.as_ptr(),
            public.len(),
            uncompressed.as_mut_ptr(),
            uncompressed.len(),
        )
    };
    assert_eq!(decompress_status, status::CRYPTO_OK);

    let mut recompressed = [0u8; p521::P521_PUBLIC_KEY_COMPRESSED_LEN];
    let compress_status = unsafe {
        p521::rm_crypto_p521_compress_public_key(
            uncompressed.as_ptr(),
            uncompressed.len(),
            recompressed.as_mut_ptr(),
            recompressed.len(),
        )
    };
    assert_eq!(compress_status, status::CRYPTO_OK);
    assert_eq!(recompressed, public);
}

#[test]
fn secp256k1_ffi_covers_keygen_sign_verify_and_encoding() {
    let message = b"secp256k1 ffi";
    let mut public = [0u8; secp256k1::SECP256K1_PUBLIC_KEY_COMPRESSED_LEN];
    let mut secret = [0u8; secp256k1::SECP256K1_SECRET_KEY_LEN];
    let key_status = unsafe {
        secp256k1::rm_crypto_secp256k1_generate_keypair(
            public.as_mut_ptr(),
            public.len(),
            secret.as_mut_ptr(),
            secret.len(),
        )
    };
    assert_eq!(key_status, status::CRYPTO_OK);

    let mut signature = [0u8; secp256k1::SECP256K1_SIGNATURE_LEN];
    let sign_status = unsafe {
        secp256k1::rm_crypto_secp256k1_sign(
            secret.as_ptr(),
            secret.len(),
            message.as_ptr(),
            message.len(),
            signature.as_mut_ptr(),
            signature.len(),
        )
    };
    assert_eq!(sign_status, status::CRYPTO_OK);
    let verify_status = unsafe {
        secp256k1::rm_crypto_secp256k1_verify(
            signature.as_ptr(),
            signature.len(),
            message.as_ptr(),
            message.len(),
            public.as_ptr(),
            public.len(),
        )
    };
    assert_eq!(verify_status, status::CRYPTO_OK);

    let mut encoded = [0u8; secp256k1::SECP256K1_PUBLIC_KEY_COMPRESSED_LEN];
    let encode_status = unsafe {
        secp256k1::rm_crypto_secp256k1_encode_public_key(
            public.as_ptr(),
            public.len(),
            encoded.as_mut_ptr(),
            encoded.len(),
        )
    };
    assert_eq!(encode_status, status::CRYPTO_OK);
    assert_eq!(encoded, public);

    let mut decoded = [0u8; secp256k1::SECP256K1_PUBLIC_KEY_COMPRESSED_LEN];
    let decode_status = unsafe {
        secp256k1::rm_crypto_secp256k1_decode_public_key(
            encoded.as_ptr(),
            encoded.len(),
            decoded.as_mut_ptr(),
            decoded.len(),
        )
    };
    assert_eq!(decode_status, status::CRYPTO_OK);
    assert_eq!(decoded, public);

    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    let decompress_status = unsafe {
        secp256k1::rm_crypto_secp256k1_decompress_public_key(
            public.as_ptr(),
            public.len(),
            x.as_mut_ptr(),
            x.len(),
            y.as_mut_ptr(),
            y.len(),
        )
    };
    assert_eq!(decompress_status, status::CRYPTO_OK);
}

#[test]
fn bip340_schnorr_ffi_covers_official_vector_and_encoding() {
    let mut secret = [0u8; secp256k1::SECP256K1_SECRET_KEY_LEN];
    secret[31] = 0x03;
    let public = [
        0xf9, 0x30, 0x8a, 0x01, 0x92, 0x58, 0xc3, 0x10, 0x49, 0x34, 0x4f, 0x85, 0xf8, 0x9d, 0x52,
        0x29, 0xb5, 0x31, 0xc8, 0x45, 0x83, 0x6f, 0x99, 0xb0, 0x86, 0x01, 0xf1, 0x13, 0xbc, 0xe0,
        0x36, 0xf9,
    ];
    let aux_rand = [0u8; secp256k1::BIP340_SCHNORR_AUX_RAND_LEN];
    let message = [0u8; secp256k1::BIP340_SCHNORR_MESSAGE_LEN];
    let expected_signature = [
        0xe9, 0x07, 0x83, 0x1f, 0x80, 0x84, 0x8d, 0x10, 0x69, 0xa5, 0x37, 0x1b, 0x40, 0x24, 0x10,
        0x36, 0x4b, 0xdf, 0x1c, 0x5f, 0x83, 0x07, 0xb0, 0x08, 0x4c, 0x55, 0xf1, 0xce, 0x2d, 0xca,
        0x82, 0x15, 0x25, 0xf6, 0x6a, 0x4a, 0x85, 0xea, 0x8b, 0x71, 0xe4, 0x82, 0xa7, 0x4f, 0x38,
        0x2d, 0x2c, 0xe5, 0xeb, 0xee, 0xe8, 0xfd, 0xb2, 0x17, 0x2f, 0x47, 0x7d, 0xf4, 0x90, 0x0d,
        0x31, 0x05, 0x36, 0xc0,
    ];

    let mut derived = [0u8; secp256k1::BIP340_SCHNORR_PUBLIC_KEY_LEN];
    let derive_status = unsafe {
        secp256k1::rm_crypto_bip340_schnorr_derive_public_key(
            secret.as_ptr(),
            secret.len(),
            derived.as_mut_ptr(),
            derived.len(),
        )
    };
    assert_eq!(derive_status, status::CRYPTO_OK);
    assert_eq!(derived, public);

    let mut signature = [0u8; secp256k1::BIP340_SCHNORR_SIGNATURE_LEN];
    let sign_status = unsafe {
        secp256k1::rm_crypto_bip340_schnorr_sign(
            secret.as_ptr(),
            secret.len(),
            message.as_ptr(),
            message.len(),
            aux_rand.as_ptr(),
            aux_rand.len(),
            signature.as_mut_ptr(),
            signature.len(),
        )
    };
    assert_eq!(sign_status, status::CRYPTO_OK);
    assert_eq!(signature, expected_signature);
    let verify_status = unsafe {
        secp256k1::rm_crypto_bip340_schnorr_verify(
            signature.as_ptr(),
            signature.len(),
            message.as_ptr(),
            message.len(),
            public.as_ptr(),
            public.len(),
        )
    };
    assert_eq!(verify_status, status::CRYPTO_OK);

    let mut tampered = signature;
    tampered[0] ^= 0x01;
    let tampered_status = unsafe {
        secp256k1::rm_crypto_bip340_schnorr_verify(
            tampered.as_ptr(),
            tampered.len(),
            message.as_ptr(),
            message.len(),
            public.as_ptr(),
            public.len(),
        )
    };
    assert_eq!(tampered_status, status::CRYPTO_INVALID_SIGNATURE);

    let mut encoded = [0u8; secp256k1::BIP340_SCHNORR_PUBLIC_KEY_LEN];
    let encode_status = unsafe {
        secp256k1::rm_crypto_bip340_schnorr_encode_public_key(
            public.as_ptr(),
            public.len(),
            encoded.as_mut_ptr(),
            encoded.len(),
        )
    };
    assert_eq!(encode_status, status::CRYPTO_OK);
    assert_eq!(encoded, public);

    let mut decoded = [0u8; secp256k1::BIP340_SCHNORR_PUBLIC_KEY_LEN];
    let decode_status = unsafe {
        secp256k1::rm_crypto_bip340_schnorr_decode_public_key(
            encoded.as_ptr(),
            encoded.len(),
            decoded.as_mut_ptr(),
            decoded.len(),
        )
    };
    assert_eq!(decode_status, status::CRYPTO_OK);
    assert_eq!(decoded, public);

    let invalid_message_status = unsafe {
        secp256k1::rm_crypto_bip340_schnorr_sign(
            secret.as_ptr(),
            secret.len(),
            message[1..].as_ptr(),
            message[1..].len(),
            aux_rand.as_ptr(),
            aux_rand.len(),
            signature.as_mut_ptr(),
            signature.len(),
        )
    };
    assert_eq!(invalid_message_status, status::CRYPTO_INVALID_ARGUMENT);
}

#[test]
fn x25519_ffi_covers_keygen_derive_and_encoding() {
    let mut alice_public = [0u8; x25519::X25519_PUBLIC_KEY_LEN];
    let mut alice_secret = [0u8; x25519::X25519_SECRET_KEY_LEN];
    let mut bob_public = [0u8; x25519::X25519_PUBLIC_KEY_LEN];
    let mut bob_secret = [0u8; x25519::X25519_SECRET_KEY_LEN];

    let alice_status = unsafe {
        x25519::rm_crypto_x25519_generate_keypair(
            alice_public.as_mut_ptr(),
            alice_public.len(),
            alice_secret.as_mut_ptr(),
            alice_secret.len(),
        )
    };
    let bob_status = unsafe {
        x25519::rm_crypto_x25519_generate_keypair(
            bob_public.as_mut_ptr(),
            bob_public.len(),
            bob_secret.as_mut_ptr(),
            bob_secret.len(),
        )
    };
    assert_eq!(alice_status, status::CRYPTO_OK);
    assert_eq!(bob_status, status::CRYPTO_OK);

    let mut alice_shared = [0u8; x25519::X25519_SHARED_SECRET_LEN];
    let mut bob_shared = [0u8; x25519::X25519_SHARED_SECRET_LEN];
    let alice_derive = unsafe {
        x25519::rm_crypto_x25519_derive_shared_secret(
            alice_secret.as_ptr(),
            alice_secret.len(),
            bob_public.as_ptr(),
            bob_public.len(),
            alice_shared.as_mut_ptr(),
            alice_shared.len(),
        )
    };
    let bob_derive = unsafe {
        x25519::rm_crypto_x25519_derive_shared_secret(
            bob_secret.as_ptr(),
            bob_secret.len(),
            alice_public.as_ptr(),
            alice_public.len(),
            bob_shared.as_mut_ptr(),
            bob_shared.len(),
        )
    };
    assert_eq!(alice_derive, status::CRYPTO_OK);
    assert_eq!(bob_derive, status::CRYPTO_OK);
    assert_eq!(alice_shared, bob_shared);

    let mut encoded = [0u8; x25519::X25519_PUBLIC_KEY_LEN];
    let encode_status = unsafe {
        x25519::rm_crypto_x25519_encode_public_key(
            alice_public.as_ptr(),
            alice_public.len(),
            encoded.as_mut_ptr(),
            encoded.len(),
        )
    };
    assert_eq!(encode_status, status::CRYPTO_OK);
    let mut decoded = [0u8; x25519::X25519_PUBLIC_KEY_LEN];
    let decode_status = unsafe {
        x25519::rm_crypto_x25519_decode_public_key(
            encoded.as_ptr(),
            encoded.len(),
            decoded.as_mut_ptr(),
            decoded.len(),
        )
    };
    assert_eq!(decode_status, status::CRYPTO_OK);
    assert_eq!(decoded, alice_public);
}

#[test]
fn ml_dsa_44_ffi_covers_keygen_sign_verify_and_encoding() {
    let message = b"ml-dsa-44 ffi";
    let mut public = [0u8; ml_dsa_44::ML_DSA_44_PUBLIC_KEY_LEN];
    let mut secret = [0u8; ml_dsa_44::ML_DSA_44_SECRET_SEED_LEN];
    let key_status = unsafe {
        ml_dsa_44::rm_crypto_ml_dsa_44_generate_keypair(
            public.as_mut_ptr(),
            public.len(),
            secret.as_mut_ptr(),
            secret.len(),
        )
    };
    assert_eq!(key_status, status::CRYPTO_OK);

    let mut signature = [0u8; ml_dsa_44::ML_DSA_44_SIGNATURE_LEN];
    let sign_status = unsafe {
        ml_dsa_44::rm_crypto_ml_dsa_44_sign(
            secret.as_ptr(),
            secret.len(),
            message.as_ptr(),
            message.len(),
            signature.as_mut_ptr(),
            signature.len(),
        )
    };
    assert_eq!(sign_status, status::CRYPTO_OK);
    let verify_status = unsafe {
        ml_dsa_44::rm_crypto_ml_dsa_44_verify(
            public.as_ptr(),
            public.len(),
            message.as_ptr(),
            message.len(),
            signature.as_ptr(),
            signature.len(),
        )
    };
    assert_eq!(verify_status, status::CRYPTO_OK);

    let mut encoded = [0u8; ml_dsa_44::ML_DSA_44_PUBLIC_KEY_LEN];
    let encode_status = unsafe {
        ml_dsa_44::rm_crypto_ml_dsa_44_encode_public_key(
            public.as_ptr(),
            public.len(),
            encoded.as_mut_ptr(),
            encoded.len(),
        )
    };
    assert_eq!(encode_status, status::CRYPTO_OK);
    assert_eq!(encoded, public);

    let mut decoded = [0u8; ml_dsa_44::ML_DSA_44_PUBLIC_KEY_LEN];
    let decode_status = unsafe {
        ml_dsa_44::rm_crypto_ml_dsa_44_decode_public_key(
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
fn slh_dsa_sha2_128s_ffi_covers_keygen_sign_verify_and_encoding() {
    let message = b"slh-dsa-sha2-128s ffi";
    let sk_seed = [0x11u8; slh_dsa::SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN];
    let sk_prf = [0x22u8; slh_dsa::SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN];
    let pk_seed = [0x33u8; slh_dsa::SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN];
    let mut public = [0u8; slh_dsa::SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN];
    let mut secret = [0u8; slh_dsa::SLH_DSA_SHA2_128S_SECRET_KEY_LEN];
    let key_status = unsafe {
        slh_dsa::rm_crypto_slh_dsa_sha2_128s_derive_keypair(
            sk_seed.as_ptr(),
            sk_seed.len(),
            sk_prf.as_ptr(),
            sk_prf.len(),
            pk_seed.as_ptr(),
            pk_seed.len(),
            public.as_mut_ptr(),
            public.len(),
            secret.as_mut_ptr(),
            secret.len(),
        )
    };
    assert_eq!(key_status, status::CRYPTO_OK);

    let mut signature = [0u8; slh_dsa::SLH_DSA_SHA2_128S_SIGNATURE_LEN];
    let sign_status = unsafe {
        slh_dsa::rm_crypto_slh_dsa_sha2_128s_sign(
            secret.as_ptr(),
            secret.len(),
            message.as_ptr(),
            message.len(),
            signature.as_mut_ptr(),
            signature.len(),
        )
    };
    assert_eq!(sign_status, status::CRYPTO_OK);
    let verify_status = unsafe {
        slh_dsa::rm_crypto_slh_dsa_sha2_128s_verify(
            public.as_ptr(),
            public.len(),
            message.as_ptr(),
            message.len(),
            signature.as_ptr(),
            signature.len(),
        )
    };
    assert_eq!(verify_status, status::CRYPTO_OK);

    let tampered_status = unsafe {
        slh_dsa::rm_crypto_slh_dsa_sha2_128s_verify(
            public.as_ptr(),
            public.len(),
            b"tampered".as_ptr(),
            b"tampered".len(),
            signature.as_ptr(),
            signature.len(),
        )
    };
    assert_eq!(tampered_status, status::CRYPTO_INVALID_SIGNATURE);

    let mut encoded = [0u8; slh_dsa::SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN];
    let encode_status = unsafe {
        slh_dsa::rm_crypto_slh_dsa_sha2_128s_encode_public_key(
            public.as_ptr(),
            public.len(),
            encoded.as_mut_ptr(),
            encoded.len(),
        )
    };
    assert_eq!(encode_status, status::CRYPTO_OK);
    assert_eq!(encoded, public);

    let mut decoded = [0u8; slh_dsa::SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN];
    let decode_status = unsafe {
        slh_dsa::rm_crypto_slh_dsa_sha2_128s_decode_public_key(
            encoded.as_ptr(),
            encoded.len(),
            decoded.as_mut_ptr(),
            decoded.len(),
        )
    };
    assert_eq!(decode_status, status::CRYPTO_OK);
    assert_eq!(decoded, public);

    let invalid_key_status = unsafe {
        slh_dsa::rm_crypto_slh_dsa_sha2_128s_sign(
            secret[1..].as_ptr(),
            secret[1..].len(),
            message.as_ptr(),
            message.len(),
            signature.as_mut_ptr(),
            signature.len(),
        )
    };
    assert_eq!(invalid_key_status, status::CRYPTO_INVALID_KEY);
}

#[test]
fn ml_dsa_65_ffi_covers_keygen_sign_verify_and_encoding() {
    let message = b"ml-dsa-65 ffi";
    let mut public = [0u8; ml_dsa_65::ML_DSA_65_PUBLIC_KEY_LEN];
    let mut secret = [0u8; ml_dsa_65::ML_DSA_65_SECRET_SEED_LEN];
    let key_status = unsafe {
        ml_dsa_65::rm_crypto_ml_dsa_65_generate_keypair(
            public.as_mut_ptr(),
            public.len(),
            secret.as_mut_ptr(),
            secret.len(),
        )
    };
    assert_eq!(key_status, status::CRYPTO_OK);

    let mut signature = [0u8; ml_dsa_65::ML_DSA_65_SIGNATURE_LEN];
    let sign_status = unsafe {
        ml_dsa_65::rm_crypto_ml_dsa_65_sign(
            secret.as_ptr(),
            secret.len(),
            message.as_ptr(),
            message.len(),
            signature.as_mut_ptr(),
            signature.len(),
        )
    };
    assert_eq!(sign_status, status::CRYPTO_OK);
    let verify_status = unsafe {
        ml_dsa_65::rm_crypto_ml_dsa_65_verify(
            public.as_ptr(),
            public.len(),
            message.as_ptr(),
            message.len(),
            signature.as_ptr(),
            signature.len(),
        )
    };
    assert_eq!(verify_status, status::CRYPTO_OK);

    let mut encoded = [0u8; ml_dsa_65::ML_DSA_65_PUBLIC_KEY_LEN];
    let encode_status = unsafe {
        ml_dsa_65::rm_crypto_ml_dsa_65_encode_public_key(
            public.as_ptr(),
            public.len(),
            encoded.as_mut_ptr(),
            encoded.len(),
        )
    };
    assert_eq!(encode_status, status::CRYPTO_OK);
    assert_eq!(encoded, public);

    let mut decoded = [0u8; ml_dsa_65::ML_DSA_65_PUBLIC_KEY_LEN];
    let decode_status = unsafe {
        ml_dsa_65::rm_crypto_ml_dsa_65_decode_public_key(
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
fn ml_dsa_87_ffi_covers_keygen_sign_verify_and_encoding() {
    let message = b"ml-dsa-87 ffi";
    let mut public = [0u8; ml_dsa_87::ML_DSA_87_PUBLIC_KEY_LEN];
    let mut secret = [0u8; ml_dsa_87::ML_DSA_87_SECRET_SEED_LEN];
    let key_status = unsafe {
        ml_dsa_87::rm_crypto_ml_dsa_87_generate_keypair(
            public.as_mut_ptr(),
            public.len(),
            secret.as_mut_ptr(),
            secret.len(),
        )
    };
    assert_eq!(key_status, status::CRYPTO_OK);

    let mut signature = [0u8; ml_dsa_87::ML_DSA_87_SIGNATURE_LEN];
    let sign_status = unsafe {
        ml_dsa_87::rm_crypto_ml_dsa_87_sign(
            secret.as_ptr(),
            secret.len(),
            message.as_ptr(),
            message.len(),
            signature.as_mut_ptr(),
            signature.len(),
        )
    };
    assert_eq!(sign_status, status::CRYPTO_OK);
    let verify_status = unsafe {
        ml_dsa_87::rm_crypto_ml_dsa_87_verify(
            public.as_ptr(),
            public.len(),
            message.as_ptr(),
            message.len(),
            signature.as_ptr(),
            signature.len(),
        )
    };
    assert_eq!(verify_status, status::CRYPTO_OK);

    let mut encoded = [0u8; ml_dsa_87::ML_DSA_87_PUBLIC_KEY_LEN];
    let encode_status = unsafe {
        ml_dsa_87::rm_crypto_ml_dsa_87_encode_public_key(
            public.as_ptr(),
            public.len(),
            encoded.as_mut_ptr(),
            encoded.len(),
        )
    };
    assert_eq!(encode_status, status::CRYPTO_OK);
    assert_eq!(encoded, public);

    let mut decoded = [0u8; ml_dsa_87::ML_DSA_87_PUBLIC_KEY_LEN];
    let decode_status = unsafe {
        ml_dsa_87::rm_crypto_ml_dsa_87_decode_public_key(
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
fn x_wing_ffi_covers_derand_encaps_decaps_and_encoding() {
    let secret = [0x58u8; x_wing::X_WING_SECRET_KEY_LEN];
    let seed = [0x91u8; x_wing::X_WING_ENCAPS_SEED_LEN];

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
        x_wing::rm_crypto_x_wing_768_encapsulate_derand(
            public.as_ptr(),
            public.len(),
            seed.as_ptr(),
            seed.len(),
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

    let mut public_1024 = [0u8; x_wing::X_WING_1024_PUBLIC_KEY_LEN];
    let key_status_1024 = unsafe {
        x_wing::rm_crypto_x_wing_1024_generate_keypair_derand(
            secret.as_ptr(),
            secret.len(),
            public_1024.as_mut_ptr(),
            public_1024.len(),
        )
    };
    assert_eq!(key_status_1024, status::CRYPTO_OK);

    let mut ciphertext_1024 = [0u8; x_wing::X_WING_1024_CIPHERTEXT_LEN];
    let mut shared_1024 = [0u8; x_wing::X_WING_SHARED_SECRET_LEN];
    let encap_status_1024 = unsafe {
        x_wing::rm_crypto_x_wing_1024_encapsulate_derand(
            public_1024.as_ptr(),
            public_1024.len(),
            seed.as_ptr(),
            seed.len(),
            ciphertext_1024.as_mut_ptr(),
            ciphertext_1024.len(),
            shared_1024.as_mut_ptr(),
            shared_1024.len(),
        )
    };
    assert_eq!(encap_status_1024, status::CRYPTO_OK);
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
