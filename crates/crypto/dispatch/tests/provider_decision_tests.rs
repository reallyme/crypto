// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]

use crypto_core::Algorithm;
use crypto_dispatch::{
    provider_decision, FallbackPolicy, KeyCopyBoundary, KeyResidency, ProviderDisposition,
    ProviderKind, ProviderOperation, ProviderOutputPolicy, ProviderPolicyReason,
};

#[cfg(feature = "ed25519")]
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

#[cfg(feature = "ml-kem-512")]
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
