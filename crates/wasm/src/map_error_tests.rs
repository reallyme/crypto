// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{classify, WasmErrorCode};
use crypto_core::CryptoError;

#[test]
fn wasm_transport_numbers_remain_unchanged() {
    assert_eq!(
        [
            WasmErrorCode::InvalidInput.value(),
            WasmErrorCode::InvalidSignature.value(),
            WasmErrorCode::AuthenticationFailed.value(),
            WasmErrorCode::ProviderFailure.value(),
            WasmErrorCode::UnsupportedAlgorithm.value()
        ],
        [1, 2, 3, 4, 5]
    );
}

#[test]
fn canonical_signature_authentication_and_provider_reasons_have_stable_projection() {
    let cases = [
        (CryptoError::PRIMITIVE_INVALID_PARAMETER, 1),
        (CryptoError::PRIMITIVE_INVALID_LENGTH, 1),
        (CryptoError::PRIMITIVE_INVALID_KEY, 1),
        (CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY, 1),
        (CryptoError::PRIMITIVE_INVALID_PRIVATE_KEY, 1),
        (CryptoError::PRIMITIVE_INVALID_SIGNATURE, 2),
        (CryptoError::PRIMITIVE_VERIFICATION_FAILED, 3),
        (CryptoError::PRIMITIVE_AUTHENTICATION_FAILED, 3),
        (CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM, 5),
        (CryptoError::PROVIDER_UNSUPPORTED_BACKEND, 5),
        (CryptoError::PROVIDER_UNAVAILABLE, 4),
        (CryptoError::BACKEND_INVALID_STATE, 4),
        (CryptoError::BACKEND_INTERNAL, 4),
    ];
    for (error, expected) in cases {
        assert_eq!(classify(error).value(), expected);
    }
}

#[test]
fn provider_access_hardware_and_randomness_failures_are_never_success_or_input_errors() {
    for error in [
        CryptoError::PROVIDER_RANDOMNESS_UNAVAILABLE,
        CryptoError::PROVIDER_KEY_EXISTS,
        CryptoError::PROVIDER_KEY_NOT_FOUND,
        CryptoError::PROVIDER_ACCESS_DENIED,
        CryptoError::PROVIDER_USER_AUTHENTICATION_REQUIRED,
        CryptoError::PROVIDER_USER_CANCELED,
        CryptoError::PROVIDER_HARDWARE_UNAVAILABLE,
        CryptoError::PROVIDER_HARDWARE_REJECTED_KEY,
    ] {
        assert_eq!(classify(error), WasmErrorCode::ProviderFailure);
    }
}

#[test]
fn every_existing_error_has_one_of_the_five_nonzero_transport_codes() {
    for error in [
        CryptoError::PRIMITIVE_INVALID_PARAMETER,
        CryptoError::PRIMITIVE_INVALID_LENGTH,
        CryptoError::PRIMITIVE_INVALID_KEY,
        CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY,
        CryptoError::PRIMITIVE_INVALID_PRIVATE_KEY,
        CryptoError::PRIMITIVE_INVALID_NONCE,
        CryptoError::PRIMITIVE_INVALID_SALT,
        CryptoError::PRIMITIVE_INVALID_PASSWORD,
        CryptoError::PRIMITIVE_INVALID_ENCODING,
        CryptoError::PRIMITIVE_INVALID_SIGNATURE,
        CryptoError::PRIMITIVE_VERIFICATION_FAILED,
        CryptoError::PRIMITIVE_AUTHENTICATION_FAILED,
        CryptoError::PRIMITIVE_MALFORMED_CIPHERTEXT,
        CryptoError::PRIMITIVE_INVALID_TAG,
        CryptoError::PRIMITIVE_INVALID_SHARED_SECRET,
        CryptoError::PRIMITIVE_MALFORMED_PROTOBUF,
        CryptoError::PRIMITIVE_MALFORMED_JSON,
        CryptoError::PRIMITIVE_RESOURCE_LIMIT_EXCEEDED,
        CryptoError::PRIMITIVE_MISSING_OPERATION,
        CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM,
        CryptoError::PROVIDER_UNSUPPORTED_BACKEND,
        CryptoError::PROVIDER_UNAVAILABLE,
        CryptoError::PROVIDER_RANDOMNESS_UNAVAILABLE,
        CryptoError::PROVIDER_KEY_EXISTS,
        CryptoError::PROVIDER_KEY_NOT_FOUND,
        CryptoError::PROVIDER_ACCESS_DENIED,
        CryptoError::PROVIDER_USER_AUTHENTICATION_REQUIRED,
        CryptoError::PROVIDER_USER_CANCELED,
        CryptoError::PROVIDER_HARDWARE_UNAVAILABLE,
        CryptoError::PROVIDER_HARDWARE_REJECTED_KEY,
        CryptoError::BACKEND_INVALID_STATE,
        CryptoError::BACKEND_INTERNAL,
    ] {
        assert!((1..=5).contains(&classify(error).value()));
    }
}
