// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generated/native policy parity and closed-boundary rejection coverage.

#![cfg(feature = "proto")]
#![allow(missing_docs, clippy::expect_used)]

use buffa::{EnumValue, Enumeration};
use crypto_core::Algorithm;
use crypto_core::CryptoError;
use crypto_dispatch::{
    provider_decision, ProviderDecision, ProviderDisposition, ProviderOperation,
    ProviderPolicyReason,
};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    FallbackPolicy as ProtoFallbackPolicy, KeyCopyBoundary as ProtoKeyCopyBoundary,
    KeyResidency as ProtoKeyResidency, ProviderDisposition as ProtoProviderDisposition,
    ProviderKind as ProtoProviderKind, ProviderLane as ProtoProviderLane,
    ProviderOperation as ProtoProviderOperation, ProviderOutputPolicy as ProtoProviderOutputPolicy,
    ProviderPolicyReason as ProtoProviderPolicyReason,
};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    KeyAlgorithm, ProviderDecision as ProtoProviderDecision,
};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn provider_operation_has_total_schema_parity() {
    assert_enum_parity::<ProtoProviderOperation, crypto_dispatch::ProviderOperation>();
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn provider_kind_has_total_schema_parity() {
    assert_enum_parity::<ProtoProviderKind, crypto_dispatch::ProviderKind>();
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn provider_lane_has_total_schema_parity() {
    assert_enum_parity::<ProtoProviderLane, crypto_dispatch::ProviderLane>();
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn key_residency_has_total_schema_parity() {
    assert_enum_parity::<ProtoKeyResidency, crypto_dispatch::KeyResidency>();
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn key_copy_boundary_has_total_schema_parity() {
    assert_enum_parity::<ProtoKeyCopyBoundary, crypto_dispatch::KeyCopyBoundary>();
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn provider_output_policy_has_total_schema_parity() {
    assert_enum_parity::<ProtoProviderOutputPolicy, crypto_dispatch::ProviderOutputPolicy>();
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn provider_policy_reason_has_total_schema_parity() {
    assert_enum_parity::<ProtoProviderPolicyReason, crypto_dispatch::ProviderPolicyReason>();
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn provider_disposition_has_total_schema_parity() {
    assert_enum_parity::<ProtoProviderDisposition, crypto_dispatch::ProviderDisposition>();
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn fallback_policy_has_total_schema_parity() {
    assert_enum_parity::<ProtoFallbackPolicy, crypto_dispatch::FallbackPolicy>();
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn decision_record_preserves_every_native_policy_field() {
    for operation in ProtoProviderOperation::values() {
        let Ok(operation) = ProviderOperation::try_from(buffa::EnumValue::from(*operation)) else {
            continue;
        };
        // X25519/sign is an operation mismatch in every compiled feature set.
        // The other operations also exercise disabled and selected decisions
        // according to the unchanged native feature policy.
        let native = provider_decision(operation, Algorithm::X25519);
        let wire = ProtoProviderDecision::from(native);
        assert_decision_fields(native, &wire);
        assert!(wire.__buffa_unknown_fields.is_empty());
    }
    let native = provider_decision(ProviderOperation::Sign, Algorithm::X25519);
    assert_eq!(native.disposition, ProviderDisposition::Rejected);
    assert_eq!(
        native.reason,
        ProviderPolicyReason::RejectedOperationMismatch
    );
    let wire = ProtoProviderDecision::from(native);
    assert_eq!(
        wire.disposition.as_known(),
        Some(ProtoProviderDisposition::PROVIDER_DISPOSITION_REJECTED)
    );
    assert_eq!(
        wire.reason.as_known(),
        Some(ProtoProviderPolicyReason::PROVIDER_POLICY_REASON_REJECTED_OPERATION_MISMATCH)
    );
    assert_eq!(
        wire.fallback.as_known(),
        Some(ProtoFallbackPolicy::FALLBACK_POLICY_PROHIBITED)
    );
}

fn assert_decision_fields(native: ProviderDecision, wire: &ProtoProviderDecision) {
    assert_eq!(
        wire.operation.as_known(),
        Some(ProtoProviderOperation::from(native.operation))
    );
    assert_eq!(
        wire.algorithm.as_known(),
        Some(KeyAlgorithm::from(native.algorithm))
    );
    assert_eq!(
        wire.provider_kind.as_known(),
        Some(ProtoProviderKind::from(native.provider_kind))
    );
    assert_eq!(
        wire.lane.as_known(),
        Some(ProtoProviderLane::from(native.lane))
    );
    assert_eq!(
        wire.disposition.as_known(),
        Some(ProtoProviderDisposition::from(native.disposition))
    );
    assert_eq!(
        wire.reason.as_known(),
        Some(ProtoProviderPolicyReason::from(native.reason))
    );
    assert_eq!(
        wire.key_residency.as_known(),
        Some(ProtoKeyResidency::from(native.key_residency))
    );
    assert_eq!(
        wire.key_copy_boundary.as_known(),
        Some(ProtoKeyCopyBoundary::from(native.key_copy_boundary))
    );
    assert_eq!(
        wire.output_policy.as_known(),
        Some(ProtoProviderOutputPolicy::from(native.output_policy))
    );
    assert_eq!(
        wire.fallback.as_known(),
        Some(ProtoFallbackPolicy::from(native.fallback))
    );
}

fn assert_enum_parity<P, N>()
where
    P: Enumeration + From<N> + PartialEq + core::fmt::Debug + 'static,
    N: TryFrom<EnumValue<P>, Error = CryptoError> + PartialEq + core::fmt::Debug,
{
    for value in P::values() {
        let converted = N::try_from(EnumValue::from(*value));
        if value.to_i32() == 0 {
            assert_eq!(converted, Err(CryptoError::PRIMITIVE_INVALID_PARAMETER));
        } else {
            let native = converted.expect("every declared nonzero policy value has a native peer");
            assert_eq!(P::from(native), *value);
        }
    }
    for unknown in [i32::MIN, -1, 1, 99, 999_999, i32::MAX] {
        let value = EnumValue::<P>::from(unknown);
        assert!(value.as_known().is_none());
        assert_eq!(
            N::try_from(value),
            Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn query_requests_recompute_the_native_decision_and_reject_modifiers() {
    use buffa::Message;
    use crypto_proto::generated::proto::reallyme::crypto::v1::{
        KeyAlgorithm, ProviderDecisionRequest,
    };
    let mut request = ProviderDecisionRequest {
        operation: ProtoProviderOperation::PROVIDER_OPERATION_VERIFY.into(),
        algorithm: KeyAlgorithm::KEY_ALGORITHM_P256.into(),
        __buffa_unknown_fields: Default::default(),
    };
    assert_eq!(
        ProviderDecision::try_from(&request),
        Ok(provider_decision(
            ProviderOperation::Verify,
            crypto_core::Algorithm::P256
        )),
    );
    request.operation = ProtoProviderOperation::PROVIDER_OPERATION_UNSPECIFIED.into();
    assert_eq!(
        ProviderDecision::try_from(&request),
        Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    request.operation = ProtoProviderOperation::PROVIDER_OPERATION_VERIFY.into();
    assert!(request.merge_from_slice(&[0xa0, 0x06, 0x01]).is_ok());
    assert_eq!(
        ProviderDecision::try_from(&request),
        Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
}
