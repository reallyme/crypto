// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generated/native policy parity and closed-boundary rejection coverage.

#![cfg(feature = "operation-response")]
#![allow(missing_docs, clippy::expect_used)]

use buffa::{EnumValue, Enumeration};
use crypto_core::CryptoError;
use crypto_core::RngOutputKind;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    BufferOwner as ProtoBufferOwner, DestructionPolicy as ProtoDestructionPolicy,
    ExportPolicy as ProtoExportPolicy, OutputMaterial as ProtoOutputMaterial,
    RetentionPolicy as ProtoRetentionPolicy,
    SecretMaterialOperation as ProtoSecretMaterialOperation,
    SecretSensitivity as ProtoSecretSensitivity, ZeroizationPolicy as ProtoZeroizationPolicy,
};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    MaterialPolicy as ProtoMaterialPolicy,
    OperationSecretMaterialPolicy as ProtoOperationSecretMaterialPolicy,
    RngOutputKind as ProtoRngOutputKind,
};
use reallyme_crypto::secret_material::{
    operation_secret_material_policy, random_fill_secret_material_policy, MaterialPolicy,
    OperationSecretMaterialPolicy, SecretMaterialOperation,
};

#[test]
fn buffer_owner_has_total_schema_parity() {
    assert_enum_parity::<ProtoBufferOwner, reallyme_crypto::secret_material::BufferOwner>();
}

#[test]
fn secret_sensitivity_has_total_schema_parity() {
    assert_enum_parity::<ProtoSecretSensitivity, reallyme_crypto::secret_material::SecretSensitivity>(
    );
}

#[test]
fn output_material_has_total_schema_parity() {
    assert_enum_parity::<ProtoOutputMaterial, reallyme_crypto::secret_material::OutputMaterial>();
}

#[test]
fn retention_policy_has_total_schema_parity() {
    assert_enum_parity::<ProtoRetentionPolicy, reallyme_crypto::secret_material::RetentionPolicy>();
}

#[test]
fn export_policy_has_total_schema_parity() {
    assert_enum_parity::<ProtoExportPolicy, reallyme_crypto::secret_material::ExportPolicy>();
}

#[test]
fn zeroization_policy_has_total_schema_parity() {
    assert_enum_parity::<ProtoZeroizationPolicy, reallyme_crypto::secret_material::ZeroizationPolicy>(
    );
}

#[test]
fn destruction_policy_has_total_schema_parity() {
    assert_enum_parity::<ProtoDestructionPolicy, reallyme_crypto::secret_material::DestructionPolicy>(
    );
}

#[test]
fn secret_material_operation_has_total_schema_parity() {
    assert_enum_parity::<
        ProtoSecretMaterialOperation,
        reallyme_crypto::secret_material::SecretMaterialOperation,
    >();
}

#[test]
fn native_zero_aead_seal_is_valid_but_schema_zero_is_not() {
    assert_eq!(SecretMaterialOperation::AeadSeal as u32, 0);
    assert_eq!(
        ProtoSecretMaterialOperation::from(SecretMaterialOperation::AeadSeal).to_i32(),
        100
    );
    assert_eq!(
        SecretMaterialOperation::try_from(EnumValue::<ProtoSecretMaterialOperation>::from(0)),
        Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    assert_eq!(
        SecretMaterialOperation::try_from(buffa::EnumValue::from(
            ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_AEAD_SEAL
        )),
        Ok(SecretMaterialOperation::AeadSeal)
    );
    assert_eq!(SecretMaterialOperation::SignatureEncoding as u32, 31);
}

#[test]
fn every_operation_record_preserves_every_native_policy_field() {
    for operation in ProtoSecretMaterialOperation::values() {
        let Ok(operation) = SecretMaterialOperation::try_from(buffa::EnumValue::from(*operation))
        else {
            continue;
        };
        let native = operation_secret_material_policy(operation);
        let wire = ProtoOperationSecretMaterialPolicy::from(native);
        assert_operation_fields(native, &wire);
    }
}

#[test]
fn every_random_purpose_record_preserves_every_native_policy_field() {
    for kind in ProtoRngOutputKind::values() {
        let Ok(kind) = RngOutputKind::try_from(buffa::EnumValue::from(*kind)) else {
            continue;
        };
        let native = random_fill_secret_material_policy(kind);
        let wire = ProtoOperationSecretMaterialPolicy::from(native);
        assert_operation_fields(native, &wire);
    }
}

fn assert_operation_fields(
    native: OperationSecretMaterialPolicy,
    wire: &ProtoOperationSecretMaterialPolicy,
) {
    assert_material_fields(
        native.input,
        wire.input.as_option().expect("input policy is present"),
    );
    assert_material_fields(
        native.output,
        wire.output.as_option().expect("output policy is present"),
    );
    assert_material_fields(
        native.request_wire,
        wire.request_wire
            .as_option()
            .expect("request policy is present"),
    );
    assert_material_fields(
        native.response_wire,
        wire.response_wire
            .as_option()
            .expect("response policy is present"),
    );
    assert_eq!(
        wire.output_material.as_known(),
        Some(ProtoOutputMaterial::from(native.output_material))
    );
    assert!(wire.__buffa_unknown_fields.is_empty());
}

fn assert_material_fields(native: MaterialPolicy, wire: &ProtoMaterialPolicy) {
    assert_eq!(
        wire.owner.as_known(),
        Some(ProtoBufferOwner::from(native.owner))
    );
    assert_eq!(
        wire.sensitivity.as_known(),
        Some(ProtoSecretSensitivity::from(native.sensitivity))
    );
    assert_eq!(
        wire.retention.as_known(),
        Some(ProtoRetentionPolicy::from(native.retention))
    );
    assert_eq!(
        wire.zeroization.as_known(),
        Some(ProtoZeroizationPolicy::from(native.zeroization))
    );
    assert_eq!(
        wire.export.as_known(),
        Some(ProtoExportPolicy::from(native.export))
    );
    assert_eq!(
        wire.destruction.as_known(),
        Some(ProtoDestructionPolicy::from(native.destruction))
    );
    assert!(wire.__buffa_unknown_fields.is_empty());
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
