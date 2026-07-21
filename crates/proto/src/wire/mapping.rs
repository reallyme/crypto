// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{
    AeadFailureKind, ConstantTimeFailureKind, CryptoError, HkdfFailureKind, KdfFailureKind,
    KemFailureKind, KeyAgreementFailureKind, KeyWrapFailureKind, MacFailureKind, RngFailureKind,
    SignatureFailureKind,
};

use crate::generated::proto::reallyme::crypto::v1::CryptoErrorReason;

use super::error::CryptoWireError;

impl From<CryptoError> for CryptoWireError {
    fn from(value: CryptoError) -> Self {
        match value {
            CryptoError::InvalidKey => Self::primitive_internal(
                CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
            ),
            CryptoError::InvalidAeadKeyLength { .. } => Self::primitive_internal(
                CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
            ),
            CryptoError::InvalidAeadNonceLength { .. } => Self::primitive_internal(
                CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_NONCE,
            ),
            CryptoError::InvalidCiphertextLength { .. } => Self::primitive_internal(
                CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH,
            ),
            CryptoError::AeadEncrypt { kind, .. } => map_aead_failure(kind),
            CryptoError::AeadDecrypt { kind, .. } => map_aead_failure(kind),
            CryptoError::Signature { kind, .. } => map_signature_failure(kind),
            CryptoError::KeyAgreementFailure { kind } => map_key_agreement_failure(kind),
            CryptoError::KemFailure { kind } => map_kem_failure(kind),
            CryptoError::KeyWrap { kind, .. } => map_key_wrap_failure(kind),
            CryptoError::Kdf { kind, .. } => map_kdf_failure(kind),
            CryptoError::Hkdf { kind, .. } => map_hkdf_failure(kind),
            CryptoError::Mac { kind, .. } => map_mac_failure(kind),
            CryptoError::Rng { kind, .. } => map_rng_failure(kind),
            CryptoError::ConstantTimeComparison { kind, .. } => map_constant_time_failure(kind),
            CryptoError::Unsupported => Self::provider_internal(
                CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM,
            ),
            _ => Self::backend_internal(CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL),
        }
    }
}

fn map_aead_failure(kind: AeadFailureKind) -> CryptoWireError {
    match kind {
        AeadFailureKind::InvalidKeyMaterial => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
        ),
        AeadFailureKind::LengthOverflow | AeadFailureKind::InvalidOutputLength => {
            CryptoWireError::primitive_internal(
                CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH,
            )
        }
        AeadFailureKind::ShortCiphertext => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_CIPHERTEXT,
        ),
        AeadFailureKind::AuthenticationFailed => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED,
        ),
        AeadFailureKind::BackendFailure => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
        _ => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
    }
}

fn map_signature_failure(kind: SignatureFailureKind) -> CryptoWireError {
    match kind {
        SignatureFailureKind::InvalidPrivateKey => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PRIVATE_KEY,
        ),
        SignatureFailureKind::InvalidPublicKey => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PUBLIC_KEY,
        ),
        SignatureFailureKind::InvalidSignature => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SIGNATURE,
        ),
        SignatureFailureKind::InvalidMessage => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER,
        ),
        SignatureFailureKind::SecureEnclaveUnavailable => CryptoWireError::provider_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE,
        ),
        SignatureFailureKind::SecureEnclaveRejectedKey => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
        ),
        SignatureFailureKind::BackendFailure | SignatureFailureKind::KeyGenerationFailed => {
            CryptoWireError::backend_internal(
                CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
            )
        }
        _ => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
    }
}

fn map_key_agreement_failure(kind: KeyAgreementFailureKind) -> CryptoWireError {
    match kind {
        KeyAgreementFailureKind::DeriveSharedSecretFailed => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SHARED_SECRET,
        ),
        KeyAgreementFailureKind::KeyGenerationFailed => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
        _ => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
    }
}

fn map_kem_failure(kind: KemFailureKind) -> CryptoWireError {
    match kind {
        KemFailureKind::DecapsulateFailed => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED,
        ),
        KemFailureKind::KeyGenerationFailed | KemFailureKind::EncapsulateFailed => {
            CryptoWireError::backend_internal(
                CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
            )
        }
        _ => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
    }
}

fn map_key_wrap_failure(kind: KeyWrapFailureKind) -> CryptoWireError {
    match kind {
        KeyWrapFailureKind::InvalidKekLength
        | KeyWrapFailureKind::InvalidPlaintextLength
        | KeyWrapFailureKind::InvalidWrappedLength
        | KeyWrapFailureKind::LengthOverflow => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH,
        ),
        KeyWrapFailureKind::IntegrityCheckFailed => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED,
        ),
        KeyWrapFailureKind::BackendFailure => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
        _ => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
    }
}

fn map_kdf_failure(kind: KdfFailureKind) -> CryptoWireError {
    match kind {
        KdfFailureKind::InvalidSecretLength => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PASSWORD,
        ),
        KdfFailureKind::InvalidSaltLength => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SALT,
        ),
        KdfFailureKind::InvalidOutputLength => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH,
        ),
        KdfFailureKind::InvalidIterationCount | KdfFailureKind::InvalidParams => {
            CryptoWireError::primitive_internal(
                CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER,
            )
        }
        KdfFailureKind::DerivationFailed => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
        _ => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
    }
}

fn map_hkdf_failure(kind: HkdfFailureKind) -> CryptoWireError {
    match kind {
        HkdfFailureKind::InvalidIkmLength => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
        ),
        HkdfFailureKind::InvalidDomainTagLength
        | HkdfFailureKind::LengthOverflow
        | HkdfFailureKind::InvalidOutputLength => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH,
        ),
        HkdfFailureKind::InvalidDomainTagByte => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_ENCODING,
        ),
        HkdfFailureKind::ExpandFailed => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
        _ => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
    }
}

fn map_mac_failure(kind: MacFailureKind) -> CryptoWireError {
    match kind {
        MacFailureKind::InvalidKeyLength => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
        ),
        MacFailureKind::InvalidTagLength => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_TAG,
        ),
        MacFailureKind::VerificationFailed => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_VERIFICATION_FAILED,
        ),
        MacFailureKind::BackendFailure => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
        _ => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
    }
}

fn map_rng_failure(kind: RngFailureKind) -> CryptoWireError {
    match kind {
        RngFailureKind::EntropyUnavailable => CryptoWireError::provider_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE,
        ),
        RngFailureKind::InvalidOutputLength => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH,
        ),
        _ => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
    }
}

fn map_constant_time_failure(kind: ConstantTimeFailureKind) -> CryptoWireError {
    match kind {
        ConstantTimeFailureKind::LengthMismatch => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH,
        ),
        ConstantTimeFailureKind::NotEqual => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_VERIFICATION_FAILED,
        ),
        _ => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
    }
}
