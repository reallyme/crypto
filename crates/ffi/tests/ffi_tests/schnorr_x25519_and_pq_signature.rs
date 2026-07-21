// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#[test]
fn bip340_schnorr_ffi_covers_official_vector_and_encoding() {
    let mut secret = [0u8; secp256k1::SECP256K1_SECRET_KEY_LEN];
    secret[31] = 0x03;
    let public = [
        0xf9, 0x30, 0x8a, 0x01, 0x92, 0x58, 0xc3, 0x10, 0x49, 0x34, 0x4f, 0x85, 0xf8, 0x9d, 0x52,
        0x29, 0xb5, 0x31, 0xc8, 0x45, 0x83, 0x6f, 0x99, 0xb0, 0x86, 0x01, 0xf1, 0x13, 0xbc, 0xe0,
        0x36, 0xf9,
    ];
    let aux_rand = [0u8; bip340_schnorr::BIP340_SCHNORR_AUX_RAND_LEN];
    let message = [0u8; bip340_schnorr::BIP340_SCHNORR_MESSAGE_LEN];
    let expected_signature = [
        0xe9, 0x07, 0x83, 0x1f, 0x80, 0x84, 0x8d, 0x10, 0x69, 0xa5, 0x37, 0x1b, 0x40, 0x24, 0x10,
        0x36, 0x4b, 0xdf, 0x1c, 0x5f, 0x83, 0x07, 0xb0, 0x08, 0x4c, 0x55, 0xf1, 0xce, 0x2d, 0xca,
        0x82, 0x15, 0x25, 0xf6, 0x6a, 0x4a, 0x85, 0xea, 0x8b, 0x71, 0xe4, 0x82, 0xa7, 0x4f, 0x38,
        0x2d, 0x2c, 0xe5, 0xeb, 0xee, 0xe8, 0xfd, 0xb2, 0x17, 0x2f, 0x47, 0x7d, 0xf4, 0x90, 0x0d,
        0x31, 0x05, 0x36, 0xc0,
    ];

    let mut derived = [0u8; bip340_schnorr::BIP340_SCHNORR_PUBLIC_KEY_LEN];
    let derive_status = unsafe {
        bip340_schnorr::rm_crypto_bip340_schnorr_derive_public_key(
            secret.as_ptr(),
            secret.len(),
            derived.as_mut_ptr(),
            derived.len(),
        )
    };
    assert_eq!(derive_status, status::CRYPTO_OK);
    assert_eq!(derived, public);

    let mut signature = [0u8; bip340_schnorr::BIP340_SCHNORR_SIGNATURE_LEN];
    let sign_status = unsafe {
        bip340_schnorr::rm_crypto_bip340_schnorr_sign(
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
        bip340_schnorr::rm_crypto_bip340_schnorr_verify(
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
        bip340_schnorr::rm_crypto_bip340_schnorr_verify(
            tampered.as_ptr(),
            tampered.len(),
            message.as_ptr(),
            message.len(),
            public.as_ptr(),
            public.len(),
        )
    };
    assert_eq!(tampered_status, status::CRYPTO_INVALID_SIGNATURE);

    let mut encoded = [0u8; bip340_schnorr::BIP340_SCHNORR_PUBLIC_KEY_LEN];
    let encode_status = unsafe {
        bip340_schnorr::rm_crypto_bip340_schnorr_encode_public_key(
            public.as_ptr(),
            public.len(),
            encoded.as_mut_ptr(),
            encoded.len(),
        )
    };
    assert_eq!(encode_status, status::CRYPTO_OK);
    assert_eq!(encoded, public);

    let mut decoded = [0u8; bip340_schnorr::BIP340_SCHNORR_PUBLIC_KEY_LEN];
    let decode_status = unsafe {
        bip340_schnorr::rm_crypto_bip340_schnorr_decode_public_key(
            encoded.as_ptr(),
            encoded.len(),
            decoded.as_mut_ptr(),
            decoded.len(),
        )
    };
    assert_eq!(decode_status, status::CRYPTO_OK);
    assert_eq!(decoded, public);

    let invalid_message_status = unsafe {
        bip340_schnorr::rm_crypto_bip340_schnorr_sign(
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
