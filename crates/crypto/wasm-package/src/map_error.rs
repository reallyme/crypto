// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, KeyWrapFailureKind, SignatureFailureKind, SignatureOperation};
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
        CryptoError::InvalidKey
        | CryptoError::InvalidAeadKeyLength { .. }
        | CryptoError::InvalidAeadNonceLength { .. }
        | CryptoError::InvalidCiphertextLength { .. } => invalid_input(),
        CryptoError::Unsupported => unsupported_algorithm(),
        CryptoError::Signature {
            kind: SignatureFailureKind::InvalidPrivateKey | SignatureFailureKind::InvalidPublicKey,
            ..
        } => invalid_input(),
        CryptoError::Signature {
            operation: SignatureOperation::Verify,
            kind: SignatureFailureKind::InvalidSignature | SignatureFailureKind::InvalidMessage,
            ..
        } => invalid_signature(),
        CryptoError::KeyWrap {
            kind:
                KeyWrapFailureKind::InvalidKekLength
                | KeyWrapFailureKind::InvalidPlaintextLength
                | KeyWrapFailureKind::InvalidWrappedLength
                | KeyWrapFailureKind::LengthOverflow,
            ..
        } => invalid_input(),
        CryptoError::ConstantTimeComparison { .. } => invalid_signature(),
        CryptoError::AeadEncrypt { .. }
        | CryptoError::AeadDecrypt { .. }
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
