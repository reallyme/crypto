// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

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
        ml_kem_512::rm_crypto_ml_kem_512_encapsulate(
            kem512_public.as_ptr(),
            kem512_public.len(),
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
        ml_kem_768::rm_crypto_ml_kem_768_encapsulate(
            kem768_public.as_ptr(),
            kem768_public.len(),
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
        ml_kem_1024::rm_crypto_ml_kem_1024_encapsulate(
            kem1024_public.as_ptr(),
            kem1024_public.len(),
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
