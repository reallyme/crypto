// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::Algorithm;
use crypto_dispatch::AlgorithmError;
use thiserror::Error;

/// Reason a signing request failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerFailureKind {
    /// Dispatch rejected the request (unsupported algorithm or invalid key).
    DispatchRejected,
}

impl core::fmt::Display for SignerFailureKind {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            SignerFailureKind::DispatchRejected => "dispatch rejected signing request",
        };
        write!(formatter, "{detail}")
    }
}

/// Error returned when a signing operation fails.
#[derive(Debug, Error)]
pub enum SignerError {
    /// Signing failed for the given algorithm.
    #[error("signer failed for {algorithm}: {kind}")]
    SignFailed {
        /// The signature algorithm that was requested.
        algorithm: Algorithm,
        /// The category of failure.
        kind: SignerFailureKind,
        /// The underlying dispatch error.
        #[source]
        source: AlgorithmError,
    },
}

/// Reason a verification request failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierFailureKind {
    /// The signature did not verify for the given message and public key.
    SignatureInvalid,
    /// Dispatch rejected the request (unsupported algorithm, malformed
    /// key or signature encoding).
    DispatchRejected,
}

impl core::fmt::Display for VerifierFailureKind {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            VerifierFailureKind::SignatureInvalid => "signature invalid",
            VerifierFailureKind::DispatchRejected => "dispatch rejected verification request",
        };
        write!(formatter, "{detail}")
    }
}

/// Error returned when a verification operation fails.
#[derive(Debug, Error)]
pub enum VerifierError {
    /// Verification failed for the given algorithm.
    #[error("verification failed for {algorithm}: {kind}")]
    VerifyFailed {
        /// The signature algorithm that was requested.
        algorithm: Algorithm,
        /// The category of failure.
        kind: VerifierFailureKind,
        /// The underlying dispatch error.
        #[source]
        source: AlgorithmError,
    },
}

impl VerifierError {
    /// True when the failure means the signature itself is invalid (as
    /// opposed to an unsupported algorithm or malformed input).
    pub fn is_signature_invalid(&self) -> bool {
        matches!(
            self,
            VerifierError::VerifyFailed {
                kind: VerifierFailureKind::SignatureInvalid,
                ..
            }
        )
    }
}
