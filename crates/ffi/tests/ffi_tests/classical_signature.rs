// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

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

    let mut expanded = [0u8; ed25519::ED25519_SIGNATURE_LEN];
    expanded[..ed25519::ED25519_SECRET_KEY_LEN].copy_from_slice(&secret);
    expanded[ed25519::ED25519_SECRET_KEY_LEN..].copy_from_slice(&public);
    let expanded_status = unsafe {
        ed25519::rm_crypto_ed25519_sign(
            expanded.as_ptr(),
            expanded.len(),
            message.as_ptr(),
            message.len(),
            signature.as_mut_ptr(),
            signature.len(),
        )
    };
    assert_eq!(expanded_status, status::CRYPTO_INVALID_KEY);

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
    let mut peer_public = [0u8; p384::P384_PUBLIC_KEY_COMPRESSED_LEN];
    let mut peer_secret = [0u8; p384::P384_SECRET_KEY_LEN];
    let key_status = unsafe {
        p384::rm_crypto_p384_generate_keypair(
            public.as_mut_ptr(),
            public.len(),
            secret.as_mut_ptr(),
            secret.len(),
        )
    };
    assert_eq!(key_status, status::CRYPTO_OK);

    let peer_key_status = unsafe {
        p384::rm_crypto_p384_generate_keypair(
            peer_public.as_mut_ptr(),
            peer_public.len(),
            peer_secret.as_mut_ptr(),
            peer_secret.len(),
        )
    };
    assert_eq!(peer_key_status, status::CRYPTO_OK);

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

    let mut shared_one = [0u8; p384::P384_SHARED_SECRET_LEN];
    let mut shared_two = [0u8; p384::P384_SHARED_SECRET_LEN];
    let derive_one_status = unsafe {
        p384::rm_crypto_p384_derive_shared_secret(
            secret.as_ptr(),
            secret.len(),
            peer_public.as_ptr(),
            peer_public.len(),
            shared_one.as_mut_ptr(),
            shared_one.len(),
        )
    };
    let derive_two_status = unsafe {
        p384::rm_crypto_p384_derive_shared_secret(
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
    assert_ne!(shared_one, [0u8; p384::P384_SHARED_SECRET_LEN]);

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
    let mut peer_public = [0u8; p521::P521_PUBLIC_KEY_COMPRESSED_LEN];
    let mut peer_secret = [0u8; p521::P521_SECRET_KEY_LEN];
    let key_status = unsafe {
        p521::rm_crypto_p521_generate_keypair(
            public.as_mut_ptr(),
            public.len(),
            secret.as_mut_ptr(),
            secret.len(),
        )
    };
    assert_eq!(key_status, status::CRYPTO_OK);

    let peer_key_status = unsafe {
        p521::rm_crypto_p521_generate_keypair(
            peer_public.as_mut_ptr(),
            peer_public.len(),
            peer_secret.as_mut_ptr(),
            peer_secret.len(),
        )
    };
    assert_eq!(peer_key_status, status::CRYPTO_OK);

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

    let mut shared_one = [0u8; p521::P521_SHARED_SECRET_LEN];
    let mut shared_two = [0u8; p521::P521_SHARED_SECRET_LEN];
    let derive_one_status = unsafe {
        p521::rm_crypto_p521_derive_shared_secret(
            secret.as_ptr(),
            secret.len(),
            peer_public.as_ptr(),
            peer_public.len(),
            shared_one.as_mut_ptr(),
            shared_one.len(),
        )
    };
    let derive_two_status = unsafe {
        p521::rm_crypto_p521_derive_shared_secret(
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
    assert_ne!(shared_one, [0u8; p521::P521_SHARED_SECRET_LEN]);

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
