// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

/// Stable, redacted operation-layer error.
///
/// This is the domain error shape future operation implementations return
/// before adapter-specific mapping. Variants carry only typed reasons so FFI,
/// protobuf, SDK, and telemetry paths cannot accidentally include raw inputs,
/// secrets, backend exception text, or arbitrary strings.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OperationError {
    /// The primitive rejected caller-controlled data or verification failed.
    #[error("primitive operation failure: {reason}")]
    Primitive {
        /// Fixed primitive failure reason.
        reason: PrimitiveErrorReason,
    },
    /// Provider policy, availability, or lane support rejected the request.
    #[error("provider operation failure: {reason}")]
    Provider {
        /// Fixed provider failure reason.
        reason: ProviderErrorReason,
    },
    /// Backend execution failed after the request crossed the semantic layer.
    #[error("backend operation failure: {reason}")]
    Backend {
        /// Fixed backend failure reason.
        reason: BackendErrorReason,
    },
}

/// Primitive-origin failure reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrimitiveErrorReason {
    /// A required algorithm selector was absent.
    MissingAlgorithm,
    /// A required operation selector was absent.
    MissingOperation,
    /// Key material failed length or mathematical validity checks.
    InvalidKey,
    /// A public key failed length, encoding, or mathematical validity checks.
    InvalidPublicKey,
    /// A private key failed length, encoding, or mathematical validity checks.
    InvalidPrivateKey,
    /// A ciphertext or encapsulated key failed structural validation.
    MalformedCiphertext,
    /// A typed operation parameter violated its protocol contract.
    InvalidParameter,
    /// Nonce, IV, salt, tag, signature, or ciphertext length was invalid.
    InvalidLength,
    /// A checked buffer length, offset, or capacity calculation overflowed.
    LengthOverflow,
    /// Authentication, MAC, signature, or constant-time equality failed.
    VerificationFailed,
    /// A raw key-agreement output failed contributory or shape validation.
    InvalidSharedSecret,
    /// A primitive resource limit was exceeded.
    ResourceLimitExceeded,
}

impl core::fmt::Display for PrimitiveErrorReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let reason = match self {
            PrimitiveErrorReason::MissingAlgorithm => "missing algorithm",
            PrimitiveErrorReason::MissingOperation => "missing operation",
            PrimitiveErrorReason::InvalidKey => "invalid key",
            PrimitiveErrorReason::InvalidPublicKey => "invalid public key",
            PrimitiveErrorReason::InvalidPrivateKey => "invalid private key",
            PrimitiveErrorReason::MalformedCiphertext => "malformed ciphertext",
            PrimitiveErrorReason::InvalidParameter => "invalid parameter",
            PrimitiveErrorReason::InvalidLength => "invalid length",
            PrimitiveErrorReason::LengthOverflow => "length overflow",
            PrimitiveErrorReason::VerificationFailed => "verification failed",
            PrimitiveErrorReason::InvalidSharedSecret => "invalid shared secret",
            PrimitiveErrorReason::ResourceLimitExceeded => "resource limit exceeded",
        };
        write!(f, "{reason}")
    }
}

/// Provider-origin failure reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProviderErrorReason {
    /// The selected algorithm is not supported by the selected lane/provider.
    UnsupportedAlgorithm,
    /// The requested provider is unavailable in this build or on this device.
    ProviderUnavailable,
    /// The selected provider could not obtain cryptographic randomness.
    RandomnessUnavailable,
    /// Policy forbids fallback or cross-lane substitution for this operation.
    FallbackProhibited,
    /// Required platform authentication or hardware state is unavailable.
    PlatformUnavailable,
    /// A persistent platform key already exists for the requested identifier.
    KeyExists,
    /// The requested persistent platform key does not exist.
    KeyNotFound,
    /// Platform access-control policy denied the operation.
    AccessDenied,
    /// The platform requires user authentication before continuing.
    UserAuthenticationRequired,
    /// The user canceled an authentication or consent operation.
    UserCanceled,
    /// The requested hardware-backed security level is unavailable.
    HardwareUnavailable,
    /// The hardware provider rejected the key or operation.
    HardwareRejectedKey,
}

impl core::fmt::Display for ProviderErrorReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let reason = match self {
            ProviderErrorReason::UnsupportedAlgorithm => "unsupported algorithm",
            ProviderErrorReason::ProviderUnavailable => "provider unavailable",
            ProviderErrorReason::RandomnessUnavailable => "provider randomness unavailable",
            ProviderErrorReason::FallbackProhibited => "fallback prohibited",
            ProviderErrorReason::PlatformUnavailable => "platform unavailable",
            ProviderErrorReason::KeyExists => "key exists",
            ProviderErrorReason::KeyNotFound => "key not found",
            ProviderErrorReason::AccessDenied => "access denied",
            ProviderErrorReason::UserAuthenticationRequired => "user authentication required",
            ProviderErrorReason::UserCanceled => "user canceled",
            ProviderErrorReason::HardwareUnavailable => "hardware unavailable",
            ProviderErrorReason::HardwareRejectedKey => "hardware rejected key",
        };
        write!(f, "{reason}")
    }
}

/// Backend-origin failure reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BackendErrorReason {
    /// A backend returned an output shape that violates the operation contract.
    InvalidOutput,
    /// A panic firewall or equivalent adapter guard caught an unexpected fault.
    PanicContained,
    /// A backend reported a fixed, redacted internal failure.
    Internal,
}

impl core::fmt::Display for BackendErrorReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let reason = match self {
            BackendErrorReason::InvalidOutput => "invalid output",
            BackendErrorReason::PanicContained => "panic contained",
            BackendErrorReason::Internal => "internal failure",
        };
        write!(f, "{reason}")
    }
}
