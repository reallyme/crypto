// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

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
