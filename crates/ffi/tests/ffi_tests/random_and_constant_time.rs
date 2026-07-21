// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

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
