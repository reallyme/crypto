// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::{CryptoError, CryptoErrorReason};
use wasm_bindgen::JsValue;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WasmErrorCode {
    InvalidInput,
    InvalidSignature,
    AuthenticationFailed,
    ProviderFailure,
    UnsupportedAlgorithm,
}

impl WasmErrorCode {
    const fn value(self) -> u32 {
        match self {
            Self::InvalidInput => {
                crypto_core::contract_constants::wasm_status::WASM_ERROR_INVALID_INPUT
            }
            Self::InvalidSignature => {
                crypto_core::contract_constants::wasm_status::WASM_ERROR_INVALID_SIGNATURE
            }
            Self::AuthenticationFailed => {
                crypto_core::contract_constants::wasm_status::WASM_ERROR_AUTHENTICATION_FAILED
            }
            Self::ProviderFailure => {
                crypto_core::contract_constants::wasm_status::WASM_ERROR_PROVIDER_FAILURE
            }
            Self::UnsupportedAlgorithm => {
                crypto_core::contract_constants::wasm_status::WASM_ERROR_UNSUPPORTED_ALGORITHM
            }
        }
    }

    fn into_js_value(self) -> JsValue {
        // Every u32 is represented exactly by a JavaScript number. No provider
        // text or caller bytes are carried into this numeric projection.
        JsValue::from_f64(f64::from(self.value()))
    }
}

pub(crate) fn invalid_input() -> JsValue {
    WasmErrorCode::InvalidInput.into_js_value()
}
pub(crate) fn provider_failure() -> JsValue {
    WasmErrorCode::ProviderFailure.into_js_value()
}
pub(crate) fn invalid_signature() -> JsValue {
    WasmErrorCode::InvalidSignature.into_js_value()
}
pub(crate) fn authentication_failed() -> JsValue {
    WasmErrorCode::AuthenticationFailed.into_js_value()
}
pub(crate) fn unsupported_algorithm() -> JsValue {
    WasmErrorCode::UnsupportedAlgorithm.into_js_value()
}

fn classify(error: CryptoError) -> WasmErrorCode {
    match error.reason() {
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SIGNATURE => {
            WasmErrorCode::InvalidSignature
        }
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_VERIFICATION_FAILED => {
            WasmErrorCode::AuthenticationFailed
        }
        CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_BACKEND => {
            WasmErrorCode::UnsupportedAlgorithm
        }
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PUBLIC_KEY
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PRIVATE_KEY
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_NONCE
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SALT
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PASSWORD
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_ENCODING
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_CIPHERTEXT
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_TAG
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SHARED_SECRET
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_JSON
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MISSING_OPERATION => {
            WasmErrorCode::InvalidInput
        }
        CryptoErrorReason::CRYPTO_ERROR_REASON_UNSPECIFIED
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_KEY_EXISTS
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_KEY_NOT_FOUND
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_ACCESS_DENIED
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_USER_AUTHENTICATION_REQUIRED
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_USER_CANCELED
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_UNAVAILABLE
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_REJECTED_KEY
        | CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INVALID_STATE
        | CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL => WasmErrorCode::ProviderFailure,
    }
}

pub(crate) fn map_crypto_error(error: CryptoError) -> JsValue {
    match classify(error) {
        WasmErrorCode::InvalidInput => invalid_input(),
        WasmErrorCode::InvalidSignature => invalid_signature(),
        WasmErrorCode::AuthenticationFailed => authentication_failed(),
        WasmErrorCode::ProviderFailure => provider_failure(),
        WasmErrorCode::UnsupportedAlgorithm => unsupported_algorithm(),
    }
}

#[cfg(test)]
#[path = "map_error_tests.rs"]
mod tests;
