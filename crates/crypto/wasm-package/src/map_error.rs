// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use wasm_bindgen::JsValue;

pub(crate) fn invalid_input() -> JsValue {
    JsValue::from_str("invalid-input")
}

pub(crate) fn provider_failure() -> JsValue {
    JsValue::from_str("provider-failure")
}

pub(crate) fn invalid_signature() -> JsValue {
    JsValue::from_str("invalid-signature")
}

pub(crate) fn unsupported_algorithm() -> JsValue {
    JsValue::from_str("unsupported-algorithm")
}

pub(crate) fn map_crypto_error(error: CryptoError) -> JsValue {
    match error {
        CryptoError::InvalidKey => invalid_input(),
        CryptoError::InvalidAeadKeyLength { .. }
        | CryptoError::InvalidAeadNonceLength { .. }
        | CryptoError::InvalidCiphertextLength { .. } => invalid_input(),
        CryptoError::Unsupported => invalid_input(),
        CryptoError::AeadDecrypt { .. }
        | CryptoError::AeadEncrypt { .. }
        | CryptoError::ConstantTimeComparison { .. }
        | CryptoError::Hkdf { .. }
        | CryptoError::Kdf { .. }
        | CryptoError::KemFailure { .. }
        | CryptoError::KeyAgreementFailure { .. }
        | CryptoError::KeyWrap { .. }
        | CryptoError::Mac { .. }
        | CryptoError::Rng { .. }
        | CryptoError::Signature { .. } => provider_failure(),
    }
}
