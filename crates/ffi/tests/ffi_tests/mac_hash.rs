// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

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
