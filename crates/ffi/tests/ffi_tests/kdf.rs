// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#[test]
fn kmac256_ffi_derives_known_answer_and_rejects_invalid_inputs() {
    let vector = load_shared_vector("kmac256.json");
    let key = vector_bytes(&vector, "key");
    let context = vector_bytes(&vector, "context");
    let customization = vector_bytes(&vector, "customization");
    let expected = vector_bytes(&vector, "derived_key");
    let mut output = [0u8; 64];
    let status = unsafe {
        kmac::rm_crypto_kmac256_derive(
            key.as_ptr(),
            key.len(),
            context.as_ptr(),
            context.len(),
            customization.as_ptr(),
            customization.len(),
            output.as_mut_ptr(),
            output.len(),
        )
    };
    assert_eq!(status, status::CRYPTO_OK);
    assert_eq!(&output[..expected.len()], expected.as_slice());

    let short_key = [0u8; kmac::KMAC256_MIN_KEY_LEN - 1];
    let invalid_key_status = unsafe {
        kmac::rm_crypto_kmac256_derive(
            short_key.as_ptr(),
            short_key.len(),
            context.as_ptr(),
            context.len(),
            customization.as_ptr(),
            customization.len(),
            output.as_mut_ptr(),
            output.len(),
        )
    };
    assert_eq!(invalid_key_status, status::CRYPTO_INVALID_KEY);

    let invalid_output_status = unsafe {
        kmac::rm_crypto_kmac256_derive(
            key.as_ptr(),
            key.len(),
            context.as_ptr(),
            context.len(),
            customization.as_ptr(),
            customization.len(),
            output.as_mut_ptr(),
            0,
        )
    };
    assert_eq!(invalid_output_status, status::CRYPTO_INVALID_ARGUMENT);

    let oversized_context = vec![0u8; kmac::KMAC256_MAX_CONTEXT_LEN + 1];
    let oversized_context_status = unsafe {
        kmac::rm_crypto_kmac256_derive(
            key.as_ptr(),
            key.len(),
            oversized_context.as_ptr(),
            oversized_context.len(),
            customization.as_ptr(),
            customization.len(),
            output.as_mut_ptr(),
            output.len(),
        )
    };
    assert_eq!(oversized_context_status, status::CRYPTO_INVALID_ARGUMENT);

    let oversized_key = vec![0u8; kmac::KMAC256_MAX_KEY_LEN + 1];
    let oversized_key_status = unsafe {
        kmac::rm_crypto_kmac256_derive(
            oversized_key.as_ptr(),
            oversized_key.len(),
            context.as_ptr(),
            context.len(),
            customization.as_ptr(),
            customization.len(),
            output.as_mut_ptr(),
            output.len(),
        )
    };
    assert_eq!(oversized_key_status, status::CRYPTO_INVALID_KEY);
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
    let vectors = load_shared_vector("pbkdf2.json");
    let sha256_vector = vectors
        .get("pbkdf2_hmac_sha256")
        .expect("SHA-256 PBKDF2 vector must exist");
    let sha512_vector = vectors
        .get("pbkdf2_hmac_sha512")
        .expect("SHA-512 PBKDF2 vector must exist");
    let password = vector_bytes(sha256_vector, "password");
    let salt = vector_bytes(sha256_vector, "salt");
    let iterations = u32::try_from(
        sha256_vector
            .get("iterations")
            .and_then(Value::as_u64)
            .expect("PBKDF2 iterations must be an unsigned integer"),
    )
    .expect("PBKDF2 iterations must fit u32");
    let expected_sha256 = vector_bytes(sha256_vector, "derived_key");
    let expected_sha512 = vector_bytes(sha512_vector, "derived_key");

    let mut sha256_out = [0u8; 32];
    let sha256_status = unsafe {
        pbkdf2::rm_crypto_pbkdf2_hmac_sha256_derive_key(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            iterations,
            sha256_out.as_mut_ptr(),
            sha256_out.len(),
        )
    };
    assert_eq!(sha256_status, status::CRYPTO_OK);
    assert_eq!(sha256_out.as_slice(), expected_sha256);

    let mut sha512_out = [0u8; 64];
    let sha512_status = unsafe {
        pbkdf2::rm_crypto_pbkdf2_hmac_sha512_derive_key(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            iterations,
            sha512_out.as_mut_ptr(),
            sha512_out.len(),
        )
    };
    assert_eq!(sha512_status, status::CRYPTO_OK);
    assert_eq!(sha512_out.as_slice(), expected_sha512);

    let invalid_password_status = unsafe {
        pbkdf2::rm_crypto_pbkdf2_hmac_sha256_derive_key(
            password.as_ptr(),
            0,
            salt.as_ptr(),
            salt.len(),
            iterations,
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
            pbkdf2::PBKDF2_ITERATIONS_MIN - 1,
            sha256_out.as_mut_ptr(),
            sha256_out.len(),
        )
    };
    assert_eq!(invalid_iterations_status, status::CRYPTO_INVALID_ARGUMENT);

    let excessive_iterations_status = unsafe {
        pbkdf2::rm_crypto_pbkdf2_hmac_sha512_derive_key(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            pbkdf2::PBKDF2_ITERATIONS_MAX + 1,
            sha512_out.as_mut_ptr(),
            sha512_out.len(),
        )
    };
    assert_eq!(excessive_iterations_status, status::CRYPTO_INVALID_ARGUMENT);

    let invalid_output_status = unsafe {
        pbkdf2::rm_crypto_pbkdf2_hmac_sha256_derive_key(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            iterations,
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
fn expensive_kdf_ffis_reject_null_outputs_at_preflight() {
    let key = [0x41_u8; kmac::KMAC256_MIN_KEY_LEN];
    let password = b"FFI hardening password";
    let salt = [0x52_u8; 16];
    let info = b"FFI hardening kdf preflight";

    let kmac_status = unsafe {
        kmac::rm_crypto_kmac256_derive(
            key.as_ptr(),
            key.len(),
            core::ptr::null(),
            0,
            core::ptr::null(),
            0,
            core::ptr::null_mut(),
            32,
        )
    };
    assert_eq!(kmac_status, status::CRYPTO_INVALID_ARGUMENT);

    let argon2_status = unsafe {
        argon2id::rm_crypto_argon2id_derive_key(
            1,
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            core::ptr::null_mut(),
            argon2id::ARGON2ID_DERIVED_KEY_LEN,
        )
    };
    assert_eq!(argon2_status, status::CRYPTO_INVALID_ARGUMENT);

    let pbkdf2_status = unsafe {
        pbkdf2::rm_crypto_pbkdf2_hmac_sha256_derive_key(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            pbkdf2::PBKDF2_ITERATIONS_MIN,
            core::ptr::null_mut(),
            32,
        )
    };
    assert_eq!(pbkdf2_status, status::CRYPTO_INVALID_ARGUMENT);

    let hkdf_status = unsafe {
        hkdf::rm_crypto_hkdf_derive(
            hkdf::HKDF_SUITE_SHA2_256,
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            info.as_ptr(),
            info.len(),
            core::ptr::null_mut(),
            32,
        )
    };
    assert_eq!(hkdf_status, status::CRYPTO_INVALID_ARGUMENT);
}
