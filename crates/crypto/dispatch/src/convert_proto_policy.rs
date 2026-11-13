// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Schema policy descriptors preserve native policy and never authorize execution.

use crate::provider::{
    FallbackPolicy, KeyCopyBoundary, KeyResidency, ProviderDecision, ProviderDisposition,
    ProviderKind, ProviderLane, ProviderOperation, ProviderOutputPolicy, ProviderPolicyReason,
};
use buffa::EnumValue;
use crypto_core::CryptoError;
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

impl TryFrom<EnumValue<ProtoProviderOperation>> for ProviderOperation {
    type Error = CryptoError;

    fn try_from(value: EnumValue<ProtoProviderOperation>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(ProtoProviderOperation::PROVIDER_OPERATION_GENERATE_KEY_PAIR) => {
                Ok(Self::GenerateKeyPair)
            }
            Some(ProtoProviderOperation::PROVIDER_OPERATION_DERIVE_KEY_PAIR) => {
                Ok(Self::DeriveKeyPair)
            }
            Some(ProtoProviderOperation::PROVIDER_OPERATION_SIGN) => Ok(Self::Sign),
            Some(ProtoProviderOperation::PROVIDER_OPERATION_VERIFY) => Ok(Self::Verify),
            Some(ProtoProviderOperation::PROVIDER_OPERATION_DERIVE_SHARED_SECRET) => {
                Ok(Self::DeriveSharedSecret)
            }
            Some(ProtoProviderOperation::PROVIDER_OPERATION_KEM_ENCAPSULATE) => {
                Ok(Self::KemEncapsulate)
            }
            Some(ProtoProviderOperation::PROVIDER_OPERATION_KEM_DECAPSULATE) => {
                Ok(Self::KemDecapsulate)
            }
            // Zero and unknown future values cannot silently select a policy.
            _ => Err(CryptoError::PRIMITIVE_INVALID_PARAMETER),
        }
    }
}

impl From<ProviderOperation> for ProtoProviderOperation {
    fn from(value: ProviderOperation) -> Self {
        // Keep this exhaustive so new native variants require a schema decision.
        match value {
            ProviderOperation::GenerateKeyPair => Self::PROVIDER_OPERATION_GENERATE_KEY_PAIR,
            ProviderOperation::DeriveKeyPair => Self::PROVIDER_OPERATION_DERIVE_KEY_PAIR,
            ProviderOperation::Sign => Self::PROVIDER_OPERATION_SIGN,
            ProviderOperation::Verify => Self::PROVIDER_OPERATION_VERIFY,
            ProviderOperation::DeriveSharedSecret => Self::PROVIDER_OPERATION_DERIVE_SHARED_SECRET,
            ProviderOperation::KemEncapsulate => Self::PROVIDER_OPERATION_KEM_ENCAPSULATE,
            ProviderOperation::KemDecapsulate => Self::PROVIDER_OPERATION_KEM_DECAPSULATE,
        }
    }
}

impl TryFrom<EnumValue<ProtoProviderKind>> for ProviderKind {
    type Error = CryptoError;

    fn try_from(value: EnumValue<ProtoProviderKind>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(ProtoProviderKind::PROVIDER_KIND_PACKAGE_OWNED_RUST) => Ok(Self::PackageOwnedRust),
            // Zero and unknown future values cannot silently select a policy.
            _ => Err(CryptoError::PRIMITIVE_INVALID_PARAMETER),
        }
    }
}

impl From<ProviderKind> for ProtoProviderKind {
    fn from(value: ProviderKind) -> Self {
        // Keep this exhaustive so new native variants require a schema decision.
        match value {
            ProviderKind::PackageOwnedRust => Self::PROVIDER_KIND_PACKAGE_OWNED_RUST,
        }
    }
}

impl TryFrom<EnumValue<ProtoProviderLane>> for ProviderLane {
    type Error = CryptoError;

    fn try_from(value: EnumValue<ProtoProviderLane>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(ProtoProviderLane::PROVIDER_LANE_NATIVE) => Ok(Self::Native),
            Some(ProtoProviderLane::PROVIDER_LANE_WASM) => Ok(Self::Wasm),
            // Zero and unknown future values cannot silently select a policy.
            _ => Err(CryptoError::PRIMITIVE_INVALID_PARAMETER),
        }
    }
}

impl From<ProviderLane> for ProtoProviderLane {
    fn from(value: ProviderLane) -> Self {
        // Keep this exhaustive so new native variants require a schema decision.
        match value {
            ProviderLane::Native => Self::PROVIDER_LANE_NATIVE,
            ProviderLane::Wasm => Self::PROVIDER_LANE_WASM,
        }
    }
}

impl TryFrom<EnumValue<ProtoKeyResidency>> for KeyResidency {
    type Error = CryptoError;

    fn try_from(value: EnumValue<ProtoKeyResidency>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(ProtoKeyResidency::KEY_RESIDENCY_PROCESS_MEMORY) => Ok(Self::ProcessMemory),
            // Zero and unknown future values cannot silently select a policy.
            _ => Err(CryptoError::PRIMITIVE_INVALID_PARAMETER),
        }
    }
}

impl From<KeyResidency> for ProtoKeyResidency {
    fn from(value: KeyResidency) -> Self {
        // Keep this exhaustive so new native variants require a schema decision.
        match value {
            KeyResidency::ProcessMemory => Self::KEY_RESIDENCY_PROCESS_MEMORY,
        }
    }
}

impl TryFrom<EnumValue<ProtoKeyCopyBoundary>> for KeyCopyBoundary {
    type Error = CryptoError;

    fn try_from(value: EnumValue<ProtoKeyCopyBoundary>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(ProtoKeyCopyBoundary::KEY_COPY_BOUNDARY_NO_SECRET_INPUT) => {
                Ok(Self::NoSecretInput)
            }
            Some(ProtoKeyCopyBoundary::KEY_COPY_BOUNDARY_BORROWED_CALLER_SECRET) => {
                Ok(Self::BorrowedCallerSecret)
            }
            Some(ProtoKeyCopyBoundary::KEY_COPY_BOUNDARY_PROVIDER_CREATES_SECRET) => {
                Ok(Self::ProviderCreatesSecret)
            }
            // Zero and unknown future values cannot silently select a policy.
            _ => Err(CryptoError::PRIMITIVE_INVALID_PARAMETER),
        }
    }
}

impl From<KeyCopyBoundary> for ProtoKeyCopyBoundary {
    fn from(value: KeyCopyBoundary) -> Self {
        // Keep this exhaustive so new native variants require a schema decision.
        match value {
            KeyCopyBoundary::NoSecretInput => Self::KEY_COPY_BOUNDARY_NO_SECRET_INPUT,
            KeyCopyBoundary::BorrowedCallerSecret => Self::KEY_COPY_BOUNDARY_BORROWED_CALLER_SECRET,
            KeyCopyBoundary::ProviderCreatesSecret => {
                Self::KEY_COPY_BOUNDARY_PROVIDER_CREATES_SECRET
            }
        }
    }
}

impl TryFrom<EnumValue<ProtoProviderOutputPolicy>> for ProviderOutputPolicy {
    type Error = CryptoError;

    fn try_from(value: EnumValue<ProtoProviderOutputPolicy>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(ProtoProviderOutputPolicy::PROVIDER_OUTPUT_POLICY_PUBLIC_ONLY) => {
                Ok(Self::PublicOnly)
            }
            Some(ProtoProviderOutputPolicy::PROVIDER_OUTPUT_POLICY_ZEROIZING_SECRET) => {
                Ok(Self::ZeroizingSecret)
            }
            // Zero and unknown future values cannot silently select a policy.
            _ => Err(CryptoError::PRIMITIVE_INVALID_PARAMETER),
        }
    }
}

impl From<ProviderOutputPolicy> for ProtoProviderOutputPolicy {
    fn from(value: ProviderOutputPolicy) -> Self {
        // Keep this exhaustive so new native variants require a schema decision.
        match value {
            ProviderOutputPolicy::PublicOnly => Self::PROVIDER_OUTPUT_POLICY_PUBLIC_ONLY,
            ProviderOutputPolicy::ZeroizingSecret => Self::PROVIDER_OUTPUT_POLICY_ZEROIZING_SECRET,
        }
    }
}

impl TryFrom<EnumValue<ProtoProviderPolicyReason>> for ProviderPolicyReason {
    type Error = CryptoError;

    fn try_from(value: EnumValue<ProtoProviderPolicyReason>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(
                ProtoProviderPolicyReason::PROVIDER_POLICY_REASON_SELECTED_COMPILED_IMPLEMENTATION,
            ) => Ok(Self::SelectedCompiledImplementation),
            Some(ProtoProviderPolicyReason::PROVIDER_POLICY_REASON_REJECTED_OPERATION_MISMATCH) => {
                Ok(Self::RejectedOperationMismatch)
            }
            Some(ProtoProviderPolicyReason::PROVIDER_POLICY_REASON_REJECTED_FEATURE_DISABLED) => {
                Ok(Self::RejectedFeatureDisabled)
            }
            // Zero and unknown future values cannot silently select a policy.
            _ => Err(CryptoError::PRIMITIVE_INVALID_PARAMETER),
        }
    }
}

impl From<ProviderPolicyReason> for ProtoProviderPolicyReason {
    fn from(value: ProviderPolicyReason) -> Self {
        // Keep this exhaustive so new native variants require a schema decision.
        match value {
            ProviderPolicyReason::SelectedCompiledImplementation => {
                Self::PROVIDER_POLICY_REASON_SELECTED_COMPILED_IMPLEMENTATION
            }
            ProviderPolicyReason::RejectedOperationMismatch => {
                Self::PROVIDER_POLICY_REASON_REJECTED_OPERATION_MISMATCH
            }
            ProviderPolicyReason::RejectedFeatureDisabled => {
                Self::PROVIDER_POLICY_REASON_REJECTED_FEATURE_DISABLED
            }
        }
    }
}

impl TryFrom<EnumValue<ProtoProviderDisposition>> for ProviderDisposition {
    type Error = CryptoError;

    fn try_from(value: EnumValue<ProtoProviderDisposition>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(ProtoProviderDisposition::PROVIDER_DISPOSITION_SELECTED) => Ok(Self::Selected),
            Some(ProtoProviderDisposition::PROVIDER_DISPOSITION_REJECTED) => Ok(Self::Rejected),
            // Zero and unknown future values cannot silently select a policy.
            _ => Err(CryptoError::PRIMITIVE_INVALID_PARAMETER),
        }
    }
}

impl From<ProviderDisposition> for ProtoProviderDisposition {
    fn from(value: ProviderDisposition) -> Self {
        // Keep this exhaustive so new native variants require a schema decision.
        match value {
            ProviderDisposition::Selected => Self::PROVIDER_DISPOSITION_SELECTED,
            ProviderDisposition::Rejected => Self::PROVIDER_DISPOSITION_REJECTED,
        }
    }
}

impl TryFrom<EnumValue<ProtoFallbackPolicy>> for FallbackPolicy {
    type Error = CryptoError;

    fn try_from(value: EnumValue<ProtoFallbackPolicy>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(ProtoFallbackPolicy::FALLBACK_POLICY_PROHIBITED) => Ok(Self::Prohibited),
            // Zero and unknown future values cannot silently select a policy.
            _ => Err(CryptoError::PRIMITIVE_INVALID_PARAMETER),
        }
    }
}

impl From<FallbackPolicy> for ProtoFallbackPolicy {
    fn from(value: FallbackPolicy) -> Self {
        // Keep this exhaustive so new native variants require a schema decision.
        match value {
            FallbackPolicy::Prohibited => Self::FALLBACK_POLICY_PROHIBITED,
        }
    }
}

// Only native decisions may become boundary records. There is deliberately no
// generated-record-to-native conversion that could accept policy overrides.
impl From<ProviderDecision> for ProtoProviderDecision {
    fn from(value: ProviderDecision) -> Self {
        // An added native field must acquire a schema mapping before this compiles.
        let ProviderDecision {
            operation,
            algorithm,
            provider_kind,
            lane,
            disposition,
            reason,
            key_residency,
            key_copy_boundary,
            output_policy,
            fallback,
        } = value;
        Self {
            operation: ProtoProviderOperation::from(operation).into(),
            algorithm: KeyAlgorithm::from(algorithm).into(),
            provider_kind: ProtoProviderKind::from(provider_kind).into(),
            lane: ProtoProviderLane::from(lane).into(),
            disposition: ProtoProviderDisposition::from(disposition).into(),
            reason: ProtoProviderPolicyReason::from(reason).into(),
            key_residency: ProtoKeyResidency::from(key_residency).into(),
            key_copy_boundary: ProtoKeyCopyBoundary::from(key_copy_boundary).into(),
            output_policy: ProtoProviderOutputPolicy::from(output_policy).into(),
            fallback: ProtoFallbackPolicy::from(fallback).into(),
            __buffa_unknown_fields: Default::default(),
        }
    }
}

// Query inputs select an existing operation and key type. Compute policy from
// the compiled provider; caller-supplied decision records are never consumed.
impl TryFrom<&crypto_proto::generated::proto::reallyme::crypto::v1::ProviderDecisionRequest>
    for ProviderDecision
{
    type Error = CryptoError;

    fn try_from(
        request: &crypto_proto::generated::proto::reallyme::crypto::v1::ProviderDecisionRequest,
    ) -> Result<Self, Self::Error> {
        use crypto_proto::generated::proto::reallyme::crypto::v1::CryptoKeyAlgorithmIdentifier;
        if !request.__buffa_unknown_fields.is_empty() {
            return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER);
        }
        let operation = ProviderOperation::try_from(request.operation)?;
        let key = CryptoKeyAlgorithmIdentifier {
            algorithm: request.algorithm,
            __buffa_unknown_fields: Default::default(),
        };
        let algorithm = crypto_core::Algorithm::try_from(&key)?;
        Ok(crate::provider::provider_decision(operation, algorithm))
    }
}

impl From<ProviderDecision>
    for crypto_proto::generated::proto::reallyme::crypto::v1::ProviderDecisionResult
{
    fn from(value: ProviderDecision) -> Self {
        Self {
            decision: buffa::MessageField::some(value.into()),
            __buffa_unknown_fields: Default::default(),
        }
    }
}
