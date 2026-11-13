// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::public_key_error;
use crypto_core::CryptoError;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn generic_key_rejection_gains_public_key_context() {
    assert_eq!(
        public_key_error(CryptoError::PRIMITIVE_INVALID_KEY),
        CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn canonical_provider_and_internal_failures_are_preserved() {
    for error in [
        CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY,
        CryptoError::PRIMITIVE_INVALID_LENGTH,
        CryptoError::PROVIDER_UNAVAILABLE,
        CryptoError::PROVIDER_UNSUPPORTED_BACKEND,
        CryptoError::BACKEND_INTERNAL,
    ] {
        assert_eq!(public_key_error(error), error);
    }
}
