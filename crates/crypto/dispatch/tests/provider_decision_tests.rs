// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]

use crypto_core::Algorithm;
use crypto_dispatch::{
    provider_decision, FallbackPolicy, ProviderDisposition, ProviderOperation, ProviderPolicyReason,
};
#[cfg(all(feature = "native", any(feature = "ed25519", feature = "ml-kem-512")))]
use crypto_dispatch::{KeyCopyBoundary, ProviderOutputPolicy};
#[cfg(all(feature = "native", feature = "ed25519"))]
use crypto_dispatch::{KeyResidency, ProviderKind};

#[cfg(all(feature = "ed25519", feature = "native"))]
#[test]
fn selected_provider_records_lane_custody_copy_and_fallback_policy() {
    let decision = provider_decision(ProviderOperation::Sign, Algorithm::Ed25519);

    assert_eq!(decision.operation, ProviderOperation::Sign);
    assert_eq!(decision.algorithm, Algorithm::Ed25519);
    assert_eq!(decision.provider_kind, ProviderKind::PackageOwnedRust);
    assert_eq!(decision.disposition, ProviderDisposition::Selected);
    assert_eq!(
        decision.reason,
        ProviderPolicyReason::SelectedCompiledImplementation
    );
    assert_eq!(decision.key_residency, KeyResidency::ProcessMemory);
    assert_eq!(
        decision.key_copy_boundary,
        KeyCopyBoundary::BorrowedCallerSecret
    );
    assert_eq!(decision.output_policy, ProviderOutputPolicy::PublicOnly);
    assert_eq!(decision.fallback, FallbackPolicy::Prohibited);
}

#[test]
fn operation_mismatch_is_rejected_without_fallback() {
    let decision = provider_decision(ProviderOperation::Sign, Algorithm::X25519);

    assert_eq!(decision.disposition, ProviderDisposition::Rejected);
    assert_eq!(
        decision.reason,
        ProviderPolicyReason::RejectedOperationMismatch
    );
    assert_eq!(decision.fallback, FallbackPolicy::Prohibited);
}

#[cfg(not(feature = "ed25519"))]
#[test]
fn disabled_provider_is_rejected_without_fallback() {
    let decision = provider_decision(ProviderOperation::Sign, Algorithm::Ed25519);

    assert_eq!(decision.disposition, ProviderDisposition::Rejected);
    assert_eq!(
        decision.reason,
        ProviderPolicyReason::RejectedFeatureDisabled
    );
    assert_eq!(decision.fallback, FallbackPolicy::Prohibited);
}

#[cfg(all(feature = "ml-kem-512", feature = "native"))]
#[test]
fn secret_output_policy_is_explicit_for_kem_encapsulation() {
    let decision = provider_decision(ProviderOperation::KemEncapsulate, Algorithm::MlKem512);

    assert_eq!(decision.disposition, ProviderDisposition::Selected);
    assert_eq!(decision.key_copy_boundary, KeyCopyBoundary::NoSecretInput);
    assert_eq!(
        decision.output_policy,
        ProviderOutputPolicy::ZeroizingSecret
    );
}

#[cfg(all(feature = "ed25519", not(any(feature = "native", feature = "wasm"))))]
#[test]
fn backendless_feature_cannot_claim_a_selected_provider() {
    let decision = provider_decision(ProviderOperation::Sign, Algorithm::Ed25519);
    assert_eq!(decision.disposition, ProviderDisposition::Rejected);
    assert_eq!(
        decision.reason,
        ProviderPolicyReason::RejectedFeatureDisabled
    );
}

#[cfg(all(
    feature = "wasm",
    not(feature = "native"),
    target_arch = "wasm32",
    feature = "p384"
))]
#[test]
fn wasm_only_lane_rejects_native_only_key_derivation() {
    let decision = provider_decision(ProviderOperation::DeriveKeyPair, Algorithm::P384);
    assert_eq!(decision.disposition, ProviderDisposition::Rejected);
    assert_eq!(
        decision.reason,
        ProviderPolicyReason::RejectedFeatureDisabled
    );
}
