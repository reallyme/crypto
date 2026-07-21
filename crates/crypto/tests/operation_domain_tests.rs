// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]

use reallyme_crypto::core::RngOutputKind;
use reallyme_crypto::operations::{OperationError, ProviderErrorReason};
use reallyme_crypto::secret_material::{
    operation_secret_material_policy, random_fill_secret_material_policy, BufferOwner,
    DestructionPolicy, ExportPolicy, OutputMaterial, SecretMaterialOperation, SecretSensitivity,
    ZeroizationPolicy,
};

#[test]
fn secret_results_require_zeroizing_owners() {
    let secret_operations = [
        SecretMaterialOperation::AeadOpen,
        SecretMaterialOperation::KeyUnwrap,
        SecretMaterialOperation::KeyDerivation,
        SecretMaterialOperation::KeyAgreementSharedSecret,
        SecretMaterialOperation::KemDecapsulate,
        SecretMaterialOperation::HpkeOpen,
        SecretMaterialOperation::HpkeExport,
    ];

    for operation in secret_operations {
        let policy = operation_secret_material_policy(operation);
        assert_eq!(policy.output_material, OutputMaterial::Secret);
        assert_eq!(policy.output.owner, BufferOwner::OperationLayer);
        assert_eq!(policy.output.sensitivity, SecretSensitivity::Secret);
        assert_eq!(
            policy.output.zeroization,
            ZeroizationPolicy::OwnerZeroizesOnDrop
        );
        assert_eq!(policy.output.export, ExportPolicy::SecretOwnerRequired);
        assert_eq!(policy.output.destruction, DestructionPolicy::ZeroizeOnDrop);
    }
}

#[test]
fn caller_owned_random_output_keeps_cleanup_with_the_caller() {
    let policy = random_fill_secret_material_policy(RngOutputKind::Aes256GcmKey);

    assert_eq!(policy.output.owner, BufferOwner::Caller);
    assert_eq!(
        policy.output.zeroization,
        ZeroizationPolicy::CallerRetainsResponsibility
    );
    assert_eq!(
        policy.output.destruction,
        DestructionPolicy::CallerControlled
    );
}

#[test]
fn random_fill_policy_distinguishes_public_nonce_and_secret_key_output() {
    let nonce = random_fill_secret_material_policy(RngOutputKind::AeadNonce12);
    let key = random_fill_secret_material_policy(RngOutputKind::Aes256GcmKey);

    assert_eq!(nonce.output.sensitivity, SecretSensitivity::Public);
    assert_eq!(nonce.output.zeroization, ZeroizationPolicy::NotRequired);
    assert_eq!(key.output.sensitivity, SecretSensitivity::Secret);
    assert_eq!(
        key.output.zeroization,
        ZeroizationPolicy::CallerRetainsResponsibility
    );
}

#[test]
fn random_fill_policy_requires_argon2_salt_owners_to_clear_on_drop() {
    for kind in [RngOutputKind::Argon2Salt16, RngOutputKind::Argon2Salt32] {
        let policy = random_fill_secret_material_policy(kind);

        assert_eq!(policy.output.sensitivity, SecretSensitivity::Sensitive);
        assert_eq!(
            policy.output.zeroization,
            ZeroizationPolicy::OwnerZeroizesOnDrop
        );
        assert_eq!(policy.output.destruction, DestructionPolicy::ZeroizeOnDrop);
    }
}

#[test]
fn public_results_do_not_downgrade_secret_input_ownership() {
    let policy = operation_secret_material_policy(SecretMaterialOperation::SignatureSign);

    assert_eq!(policy.output_material, OutputMaterial::Public);
    assert_eq!(policy.input.owner, BufferOwner::Caller);
    assert_eq!(policy.input.sensitivity, SecretSensitivity::Secret);
    assert_eq!(
        policy.input.zeroization,
        ZeroizationPolicy::CallerRetainsResponsibility
    );
    assert_eq!(policy.request_wire.sensitivity, SecretSensitivity::Secret);
    assert_eq!(
        policy.request_wire.zeroization,
        ZeroizationPolicy::OwnerZeroizesOnDrop
    );
}

#[test]
fn signature_verification_does_not_invent_secret_material() {
    let policy = operation_secret_material_policy(SecretMaterialOperation::SignatureVerify);

    assert_eq!(policy.input.sensitivity, SecretSensitivity::Public);
    assert_eq!(policy.output.sensitivity, SecretSensitivity::Public);
    assert_eq!(policy.output_material, OutputMaterial::Public);
}

#[test]
fn key_generation_does_not_invent_a_secret_input_owner() {
    let policy = operation_secret_material_policy(SecretMaterialOperation::SignatureKeyGeneration);

    assert_eq!(policy.input.sensitivity, SecretSensitivity::Public);
    assert_eq!(policy.output_material, OutputMaterial::Mixed);
    assert_eq!(policy.output.sensitivity, SecretSensitivity::Secret);
    assert_eq!(
        policy.output.zeroization,
        ZeroizationPolicy::OwnerZeroizesOnDrop
    );
}

#[test]
fn platform_lifecycle_failures_are_fixed_provider_reasons() {
    let reasons = [
        (
            ProviderErrorReason::KeyExists,
            "provider operation failure: key exists",
        ),
        (
            ProviderErrorReason::KeyNotFound,
            "provider operation failure: key not found",
        ),
        (
            ProviderErrorReason::AccessDenied,
            "provider operation failure: access denied",
        ),
        (
            ProviderErrorReason::UserAuthenticationRequired,
            "provider operation failure: user authentication required",
        ),
        (
            ProviderErrorReason::UserCanceled,
            "provider operation failure: user canceled",
        ),
        (
            ProviderErrorReason::HardwareUnavailable,
            "provider operation failure: hardware unavailable",
        ),
        (
            ProviderErrorReason::HardwareRejectedKey,
            "provider operation failure: hardware rejected key",
        ),
    ];

    for (reason, expected) in reasons {
        let error = OperationError::Provider { reason };
        assert_eq!(error.to_string(), expected);
    }
}
