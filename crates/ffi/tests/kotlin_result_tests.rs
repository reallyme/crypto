// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Tests for deterministic Kotlin-native status mapping.

use crypto_ffi::kotlin_result::{
    status_from_crypto_status, KOTLIN_NATIVE_AUTHENTICATION_FAILED, KOTLIN_NATIVE_BACKEND_INTERNAL,
    KOTLIN_NATIVE_INVALID_INPUT, KOTLIN_NATIVE_INVALID_SIGNATURE,
};
use crypto_ffi::status::{
    CRYPTO_AUTHENTICATION_FAILED, CRYPTO_BUFFER_TOO_SMALL, CRYPTO_INTERNAL_ERROR,
    CRYPTO_INVALID_ARGUMENT, CRYPTO_INVALID_CIPHERTEXT, CRYPTO_INVALID_KEY,
    CRYPTO_INVALID_SIGNATURE,
};

#[test]
fn c_statuses_map_to_typed_kotlin_statuses() {
    assert_eq!(
        status_from_crypto_status(CRYPTO_INVALID_ARGUMENT),
        KOTLIN_NATIVE_INVALID_INPUT
    );
    assert_eq!(
        status_from_crypto_status(CRYPTO_INVALID_KEY),
        KOTLIN_NATIVE_INVALID_INPUT
    );
    assert_eq!(
        status_from_crypto_status(CRYPTO_INVALID_CIPHERTEXT),
        KOTLIN_NATIVE_INVALID_INPUT
    );
    assert_eq!(
        status_from_crypto_status(CRYPTO_BUFFER_TOO_SMALL),
        KOTLIN_NATIVE_BACKEND_INTERNAL
    );
    assert_eq!(
        status_from_crypto_status(CRYPTO_AUTHENTICATION_FAILED),
        KOTLIN_NATIVE_AUTHENTICATION_FAILED
    );
    assert_eq!(
        status_from_crypto_status(CRYPTO_INVALID_SIGNATURE),
        KOTLIN_NATIVE_INVALID_SIGNATURE
    );
    assert_eq!(
        status_from_crypto_status(CRYPTO_INTERNAL_ERROR),
        KOTLIN_NATIVE_BACKEND_INTERNAL
    );
}
