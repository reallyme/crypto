// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{
    AeadFailureKind, ConstantTimeFailureKind, CryptoError, HkdfFailureKind, KdfFailureKind,
    KeyAgreementFailureKind, KeyWrapFailureKind, MacFailureKind, RngFailureKind,
    SignatureFailureKind, SignatureOperation,
};
use wasm_bindgen::JsValue;

#[derive(Clone, Copy)]
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
            Self::InvalidInput => 1,
            Self::InvalidSignature => 2,
            Self::AuthenticationFailed => 3,
            Self::ProviderFailure => 4,
            Self::UnsupportedAlgorithm => 5,
        }
    }

    fn into_js_value(self) -> JsValue {
        // JavaScript numbers represent every u32 exactly. A numeric boundary
        // code keeps the raw WASM transport deterministic without turning an
        // error category into an allocated or attacker-influenced string.
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
            kind: SignatureFailureKind::InvalidMessage,
            ..
        } => invalid_input(),
        CryptoError::Signature {
            operation: SignatureOperation::Verify,
            kind: SignatureFailureKind::InvalidSignature,
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
        CryptoError::AeadEncrypt {
            kind:
                AeadFailureKind::InvalidKeyMaterial
                | AeadFailureKind::LengthOverflow
                | AeadFailureKind::InvalidOutputLength,
            ..
        }
        | CryptoError::AeadDecrypt {
            kind:
                AeadFailureKind::InvalidKeyMaterial
                | AeadFailureKind::LengthOverflow
                | AeadFailureKind::ShortCiphertext
                | AeadFailureKind::InvalidOutputLength,
            ..
        }
        | CryptoError::Hkdf {
            kind:
                HkdfFailureKind::InvalidIkmLength
                | HkdfFailureKind::InvalidDomainTagLength
                | HkdfFailureKind::InvalidDomainTagByte
                | HkdfFailureKind::LengthOverflow
                | HkdfFailureKind::InvalidOutputLength,
            ..
        }
        | CryptoError::Kdf {
            kind:
                KdfFailureKind::InvalidSecretLength
                | KdfFailureKind::InvalidSaltLength
                | KdfFailureKind::InvalidOutputLength
                | KdfFailureKind::InvalidIterationCount
                | KdfFailureKind::InvalidParams,
            ..
        }
        | CryptoError::KeyAgreementFailure {
            kind: KeyAgreementFailureKind::DeriveSharedSecretFailed,
        }
        | CryptoError::Mac {
            kind: MacFailureKind::InvalidKeyLength | MacFailureKind::InvalidTagLength,
            ..
        }
        | CryptoError::Rng {
            kind: RngFailureKind::InvalidOutputLength,
            ..
        } => invalid_input(),
        CryptoError::AeadDecrypt {
            kind: AeadFailureKind::AuthenticationFailed,
            ..
        }
        | CryptoError::KeyWrap {
            kind: KeyWrapFailureKind::IntegrityCheckFailed,
            ..
        }
        | CryptoError::Mac {
            kind: MacFailureKind::VerificationFailed,
            ..
        } => authentication_failed(),
        CryptoError::ConstantTimeComparison {
            kind: ConstantTimeFailureKind::LengthMismatch,
            ..
        } => invalid_input(),
        CryptoError::ConstantTimeComparison {
            kind: ConstantTimeFailureKind::NotEqual,
            ..
        } => invalid_signature(),
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
        _ => provider_failure(),
    }
}
