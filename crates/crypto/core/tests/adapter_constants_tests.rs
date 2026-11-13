// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Assigned coarse transport values remain stable across metadata generation.

#![allow(missing_docs)]
use crypto_core::contract_constants;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn assigned_adapter_numbers_remain_unchanged() {
    assert_eq!(contract_constants::ffi_status::CRYPTO_OK, 0);
    assert_eq!(contract_constants::ffi_status::CRYPTO_INVALID_ARGUMENT, -1);
    assert_eq!(contract_constants::ffi_status::CRYPTO_INVALID_KEY, -2);
    assert_eq!(contract_constants::ffi_status::CRYPTO_INVALID_SIGNATURE, -3);
    assert_eq!(
        contract_constants::ffi_status::CRYPTO_INVALID_CIPHERTEXT,
        -4
    );
    assert_eq!(contract_constants::ffi_status::CRYPTO_BUFFER_TOO_SMALL, -5);
    assert_eq!(
        contract_constants::ffi_status::CRYPTO_AUTHENTICATION_FAILED,
        -6
    );
    assert_eq!(contract_constants::ffi_status::CRYPTO_INTERNAL_ERROR, -128);
    assert_eq!(contract_constants::wasm_status::WASM_ERROR_INVALID_INPUT, 1);
    assert_eq!(
        contract_constants::wasm_status::WASM_ERROR_INVALID_SIGNATURE,
        2
    );
    assert_eq!(
        contract_constants::wasm_status::WASM_ERROR_AUTHENTICATION_FAILED,
        3
    );
    assert_eq!(
        contract_constants::wasm_status::WASM_ERROR_PROVIDER_FAILURE,
        4
    );
    assert_eq!(
        contract_constants::wasm_status::WASM_ERROR_UNSUPPORTED_ALGORITHM,
        5
    );
    assert_eq!(
        contract_constants::kotlin_native_status::KOTLIN_NATIVE_OK,
        0
    );
    assert_eq!(
        contract_constants::kotlin_native_status::KOTLIN_NATIVE_INVALID_INPUT,
        1
    );
    assert_eq!(
        contract_constants::kotlin_native_status::KOTLIN_NATIVE_AUTHENTICATION_FAILED,
        2
    );
    assert_eq!(
        contract_constants::kotlin_native_status::KOTLIN_NATIVE_BACKEND_INTERNAL,
        5
    );
    assert_eq!(
        contract_constants::kotlin_native_status::KOTLIN_NATIVE_INVALID_SIGNATURE,
        6
    );
    assert_eq!(contract_constants::ffi_suite::HKDF_SUITE_SHA2_256, 1);
    assert_eq!(contract_constants::ffi_suite::HKDF_SUITE_SHA3_256, 2);
    assert_eq!(contract_constants::ffi_suite::HMAC_SUITE_SHA256, 1);
    assert_eq!(contract_constants::ffi_suite::HMAC_SUITE_SHA512, 2);
    assert_eq!(
        contract_constants::ffi_suite::HPKE_SUITE_P256_SHA256_AES256GCM,
        1
    );
    assert_eq!(
        contract_constants::ffi_suite::HPKE_SUITE_X25519_SHA256_CHACHA20_POLY1305,
        2
    );
    assert_eq!(
        contract_constants::wasm_suite::HPKE_SUITE_P256_SHA256_AES256GCM,
        1
    );
    assert_eq!(
        contract_constants::wasm_suite::HPKE_SUITE_X25519_SHA256_CHACHA20POLY1305,
        2
    );
    assert_eq!(contract_constants::rsa_ffi::RSA_HASH_SHA1_FFI_ID, 1);
    assert_eq!(contract_constants::rsa_ffi::RSA_HASH_SHA256_FFI_ID, 2);
    assert_eq!(contract_constants::rsa_ffi::RSA_HASH_SHA384_FFI_ID, 3);
    assert_eq!(contract_constants::rsa_ffi::RSA_HASH_SHA512_FFI_ID, 4);
    assert_eq!(contract_constants::rsa_ffi::RSA_DER_PKCS1_FFI_ID, 1);
    assert_eq!(contract_constants::rsa_ffi::RSA_DER_SPKI_FFI_ID, 2);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn fixed_native_adapter_caps_remain_unchanged() {
    assert_eq!(
        contract_constants::adapter_limits::MAX_JNI_BYTE_INPUT_LENGTH,
        1_048_576
    );
    assert_eq!(
        contract_constants::adapter_limits::MAX_WASM_INPUT_LENGTH,
        1_048_576
    );
    assert_eq!(
        contract_constants::adapter_limits::MAX_WASM_CIPHERTEXT_LENGTH,
        1_048_592
    );
    assert_eq!(
        contract_constants::adapter_limits::MAX_FFI_INPUT_RANGES_PER_CALL,
        32
    );
    assert_eq!(
        contract_constants::adapter_limits::MAX_FFI_OUTPUT_RANGES_PER_CALL,
        32
    );
}
