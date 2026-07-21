// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Inspectable provider decisions for algorithm-selected dispatch.

use crypto_core::Algorithm;

use crate::AlgorithmError;

/// Operation requested from the dispatch provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProviderOperation {
    /// Generate a fresh raw keypair.
    GenerateKeyPair,
    /// Reconstruct a keypair from caller-owned secret material.
    DeriveKeyPair,
    /// Produce a detached signature.
    Sign,
    /// Verify a detached signature.
    Verify,
    /// Derive a raw key-agreement shared secret.
    DeriveSharedSecret,
    /// Encapsulate to a KEM public key.
    KemEncapsulate,
    /// Decapsulate a KEM ciphertext.
    KemDecapsulate,
}

/// Concrete implementation class selected by dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProviderKind {
    /// Package-owned Rust implementation selected by Cargo feature policy.
    PackageOwnedRust,
}

/// Runtime lane in which the provider executes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProviderLane {
    /// Native Rust target.
    Native,
    /// `wasm32` Rust target using package-owned implementations.
    Wasm,
}

/// Residency of secret key material used by this dispatch package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyResidency {
    /// Secret material resides in caller or provider process memory.
    ProcessMemory,
}

/// Secret-input copy behavior at the provider boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyCopyBoundary {
    /// The operation has no secret-key input.
    NoSecretInput,
    /// The provider borrows caller-owned secret bytes for the duration of one call.
    BorrowedCallerSecret,
    /// The provider creates a new secret owner for the result.
    ProviderCreatesSecret,
}

/// Sensitivity and cleanup contract for the provider result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProviderOutputPolicy {
    /// The result contains no secret-bearing output.
    PublicOnly,
    /// Secret output is returned in a zeroizing Rust owner.
    ZeroizingSecret,
}

/// Fixed provider-policy reason recorded for a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProviderPolicyReason {
    /// The requested operation and algorithm are supported in the compiled lane.
    SelectedCompiledImplementation,
    /// The algorithm does not implement the requested operation family.
    RejectedOperationMismatch,
    /// The matching implementation was not compiled into this package.
    RejectedFeatureDisabled,
}

/// Whether dispatch selected or rejected the requested provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProviderDisposition {
    /// The provider was selected.
    Selected,
    /// The provider was rejected without trying another implementation.
    Rejected,
}

/// Explicit fallback policy attached to every provider decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FallbackPolicy {
    /// Cross-provider and cross-lane fallback is prohibited.
    Prohibited,
}

/// Complete, non-secret provider decision produced before dispatch executes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProviderDecision {
    /// Requested operation.
    pub operation: ProviderOperation,
    /// Requested algorithm.
    pub algorithm: Algorithm,
    /// Provider implementation class considered by policy.
    pub provider_kind: ProviderKind,
    /// Runtime lane considered by policy.
    pub lane: ProviderLane,
    /// Whether the provider was selected or rejected.
    pub disposition: ProviderDisposition,
    /// Fixed reason for the selection or rejection.
    pub reason: ProviderPolicyReason,
    /// Secret-key residency for the route.
    pub key_residency: KeyResidency,
    /// Secret-input copy behavior for the route.
    pub key_copy_boundary: KeyCopyBoundary,
    /// Output sensitivity and cleanup contract.
    pub output_policy: ProviderOutputPolicy,
    /// Explicit fallback disposition.
    pub fallback: FallbackPolicy,
}

impl ProviderDecision {
    /// Returns true only when the reviewed provider was selected.
    #[must_use]
    pub fn is_selected(self) -> bool {
        self.disposition == ProviderDisposition::Selected
    }
}

/// Resolve one provider decision without executing cryptographic work.
#[must_use]
pub fn provider_decision(operation: ProviderOperation, algorithm: Algorithm) -> ProviderDecision {
    let operation_supported = operation_supports_algorithm(operation, algorithm);
    let implementation_compiled = implementation_is_compiled(algorithm);
    let (disposition, reason) = if !operation_supported {
        (
            ProviderDisposition::Rejected,
            ProviderPolicyReason::RejectedOperationMismatch,
        )
    } else if !implementation_compiled {
        (
            ProviderDisposition::Rejected,
            ProviderPolicyReason::RejectedFeatureDisabled,
        )
    } else {
        (
            ProviderDisposition::Selected,
            ProviderPolicyReason::SelectedCompiledImplementation,
        )
    };

    ProviderDecision {
        operation,
        algorithm,
        provider_kind: ProviderKind::PackageOwnedRust,
        lane: compiled_lane(),
        disposition,
        reason,
        key_residency: KeyResidency::ProcessMemory,
        key_copy_boundary: key_copy_boundary(operation),
        output_policy: output_policy(operation),
        fallback: FallbackPolicy::Prohibited,
    }
}

pub(crate) fn require_provider(
    operation: ProviderOperation,
    algorithm: Algorithm,
) -> Result<ProviderDecision, AlgorithmError> {
    let decision = provider_decision(operation, algorithm);
    if decision.is_selected() {
        Ok(decision)
    } else {
        Err(AlgorithmError::UnsupportedAlgorithm(algorithm))
    }
}

const fn compiled_lane() -> ProviderLane {
    #[cfg(target_arch = "wasm32")]
    {
        ProviderLane::Wasm
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        ProviderLane::Native
    }
}

const fn key_copy_boundary(operation: ProviderOperation) -> KeyCopyBoundary {
    match operation {
        ProviderOperation::GenerateKeyPair => KeyCopyBoundary::ProviderCreatesSecret,
        ProviderOperation::DeriveKeyPair
        | ProviderOperation::Sign
        | ProviderOperation::DeriveSharedSecret
        | ProviderOperation::KemDecapsulate => KeyCopyBoundary::BorrowedCallerSecret,
        ProviderOperation::Verify | ProviderOperation::KemEncapsulate => {
            KeyCopyBoundary::NoSecretInput
        }
    }
}

const fn output_policy(operation: ProviderOperation) -> ProviderOutputPolicy {
    match operation {
        ProviderOperation::GenerateKeyPair
        | ProviderOperation::DeriveKeyPair
        | ProviderOperation::DeriveSharedSecret
        | ProviderOperation::KemEncapsulate
        | ProviderOperation::KemDecapsulate => ProviderOutputPolicy::ZeroizingSecret,
        ProviderOperation::Sign | ProviderOperation::Verify => ProviderOutputPolicy::PublicOnly,
    }
}

const fn operation_supports_algorithm(operation: ProviderOperation, algorithm: Algorithm) -> bool {
    match operation {
        ProviderOperation::GenerateKeyPair | ProviderOperation::DeriveKeyPair => {
            !matches!(algorithm, Algorithm::SlhDsaSha2_128s)
        }
        ProviderOperation::Sign | ProviderOperation::Verify => matches!(
            algorithm,
            Algorithm::Ed25519
                | Algorithm::P256
                | Algorithm::P384
                | Algorithm::P521
                | Algorithm::Secp256k1
                | Algorithm::MlDsa44
                | Algorithm::MlDsa65
                | Algorithm::MlDsa87
        ),
        ProviderOperation::DeriveSharedSecret => matches!(
            algorithm,
            Algorithm::P256 | Algorithm::P384 | Algorithm::P521 | Algorithm::X25519
        ),
        ProviderOperation::KemEncapsulate | ProviderOperation::KemDecapsulate => matches!(
            algorithm,
            Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 | Algorithm::XWing768
        ),
    }
}

const fn implementation_is_compiled(algorithm: Algorithm) -> bool {
    match algorithm {
        Algorithm::Ed25519 => cfg!(feature = "ed25519"),
        Algorithm::X25519 => cfg!(feature = "x25519"),
        Algorithm::P256 => cfg!(feature = "p256"),
        Algorithm::P384 => cfg!(feature = "p384"),
        Algorithm::P521 => cfg!(feature = "p521"),
        Algorithm::Secp256k1 => cfg!(feature = "secp256k1"),
        Algorithm::MlDsa44 => cfg!(feature = "ml-dsa-44"),
        Algorithm::MlDsa65 => cfg!(feature = "ml-dsa-65"),
        Algorithm::MlDsa87 => cfg!(feature = "ml-dsa-87"),
        Algorithm::SlhDsaSha2_128s => false,
        Algorithm::MlKem512 => cfg!(feature = "ml-kem-512"),
        Algorithm::MlKem768 => cfg!(feature = "ml-kem-768"),
        Algorithm::MlKem1024 => cfg!(feature = "ml-kem-1024"),
        Algorithm::XWing768 => cfg!(feature = "x-wing"),
    }
}
