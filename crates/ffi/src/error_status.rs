// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical schema errors project into the existing, coarse C status domain.
//!
//! Operation context disambiguates a signature width from ciphertext width.
//! The structured protobuf route keeps the full canonical reason independently.

use crypto_core::{CryptoError, CryptoErrorReason};

use crate::status::{
    CryptoStatus, CRYPTO_AUTHENTICATION_FAILED, CRYPTO_INTERNAL_ERROR, CRYPTO_INVALID_ARGUMENT,
    CRYPTO_INVALID_CIPHERTEXT, CRYPTO_INVALID_KEY, CRYPTO_INVALID_SIGNATURE,
};

#[derive(Clone, Copy)]
enum Context {
    KeyManagement,
    Sign,
    Verify,
    KeyAgreement,
    KemEncapsulation,
    KemDecapsulation,
    Wrap,
    Unwrap,
    Mac,
    Kdf,
    Hpke,
    AeadSeal,
    AeadOpen,
}

impl Context {
    const fn invalid_length(self) -> CryptoStatus {
        match self {
            Self::KeyManagement | Self::KeyAgreement | Self::KemEncapsulation => CRYPTO_INVALID_KEY,
            Self::Verify => CRYPTO_INVALID_SIGNATURE,
            Self::KemDecapsulation | Self::Unwrap | Self::AeadOpen => CRYPTO_INVALID_CIPHERTEXT,
            Self::Sign | Self::Wrap | Self::Mac | Self::Kdf | Self::Hpke | Self::AeadSeal => {
                CRYPTO_INVALID_ARGUMENT
            }
        }
    }

    const fn verification_failed(self) -> CryptoStatus {
        match self {
            Self::Sign | Self::Verify => CRYPTO_INVALID_SIGNATURE,
            Self::KemDecapsulation => CRYPTO_INVALID_CIPHERTEXT,
            Self::Unwrap | Self::Mac | Self::Hpke | Self::AeadOpen => CRYPTO_AUTHENTICATION_FAILED,
            Self::KeyManagement
            | Self::KeyAgreement
            | Self::KemEncapsulation
            | Self::Wrap
            | Self::Kdf
            | Self::AeadSeal => CRYPTO_INTERNAL_ERROR,
        }
    }

    const fn unsupported_algorithm(self) -> CryptoStatus {
        match self {
            Self::KeyManagement
            | Self::Sign
            | Self::Verify
            | Self::KeyAgreement
            | Self::KemEncapsulation
            | Self::KemDecapsulation => CRYPTO_INVALID_KEY,
            Self::Hpke => CRYPTO_INVALID_ARGUMENT,
            Self::Wrap | Self::Unwrap | Self::Mac | Self::Kdf | Self::AeadSeal | Self::AeadOpen => {
                CRYPTO_INTERNAL_ERROR
            }
        }
    }
}

fn project(error: CryptoError, context: Context) -> CryptoStatus {
    match error.reason() {
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PUBLIC_KEY
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PRIVATE_KEY => {
            CRYPTO_INVALID_KEY
        }
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH => context.invalid_length(),
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PASSWORD => {
            if matches!(context, Context::Kdf) {
                CRYPTO_INVALID_KEY
            } else {
                CRYPTO_INVALID_ARGUMENT
            }
        }
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SIGNATURE => {
            CRYPTO_INVALID_SIGNATURE
        }
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_VERIFICATION_FAILED => {
            context.verification_failed()
        }
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED => {
            CRYPTO_AUTHENTICATION_FAILED
        }
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_CIPHERTEXT => {
            CRYPTO_INVALID_CIPHERTEXT
        }
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_TAG => {
            // The raw HMAC ABI historically classifies a wrong-width tag as
            // an invalid argument; canonical specificity must preserve it.
            if matches!(context, Context::Mac) {
                CRYPTO_INVALID_ARGUMENT
            } else {
                CRYPTO_INVALID_CIPHERTEXT
            }
        }
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SHARED_SECRET => {
            if matches!(context, Context::KeyAgreement) {
                CRYPTO_INVALID_KEY
            } else {
                CRYPTO_INTERNAL_ERROR
            }
        }
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_NONCE
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SALT
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_ENCODING
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_JSON
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MISSING_OPERATION => {
            CRYPTO_INVALID_ARGUMENT
        }
        CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM => {
            context.unsupported_algorithm()
        }
        CryptoErrorReason::CRYPTO_ERROR_REASON_UNSPECIFIED
        | CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_BACKEND
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
        | CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL => CRYPTO_INTERNAL_ERROR,
    }
}

pub(crate) fn key_management_status(error: CryptoError) -> CryptoStatus {
    project(error, Context::KeyManagement)
}

pub(crate) fn sign_status(error: CryptoError) -> CryptoStatus {
    project(error, Context::Sign)
}

pub(crate) fn verify_status(error: CryptoError) -> CryptoStatus {
    project(error, Context::Verify)
}

pub(crate) fn key_agreement_status(error: CryptoError) -> CryptoStatus {
    project(error, Context::KeyAgreement)
}

pub(crate) fn kem_encapsulation_status(error: CryptoError) -> CryptoStatus {
    project(error, Context::KemEncapsulation)
}

pub(crate) fn kem_decapsulation_status(error: CryptoError) -> CryptoStatus {
    project(error, Context::KemDecapsulation)
}

pub(crate) fn wrap_status(error: CryptoError) -> CryptoStatus {
    project(error, Context::Wrap)
}

pub(crate) fn unwrap_status(error: CryptoError) -> CryptoStatus {
    project(error, Context::Unwrap)
}

pub(crate) fn mac_status(error: CryptoError) -> CryptoStatus {
    project(error, Context::Mac)
}

pub(crate) fn kdf_status(error: CryptoError) -> CryptoStatus {
    project(error, Context::Kdf)
}

pub(crate) fn hpke_status(error: CryptoError) -> CryptoStatus {
    project(error, Context::Hpke)
}

pub(crate) fn aead_seal_status(error: CryptoError) -> CryptoStatus {
    project(error, Context::AeadSeal)
}

pub(crate) fn aead_open_status(error: CryptoError) -> CryptoStatus {
    project(error, Context::AeadOpen)
}

#[cfg(test)]
#[path = "error_status_tests.rs"]
mod tests;
