// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(feature = "operation-response")]
#![allow(missing_docs, clippy::expect_used)]
use buffa::{EnumValue, Enumeration, Message};
use crypto_core::{CryptoError, RngOutputKind};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoMaterialPolicyQueryRequest, CryptoRandomFillPolicyQueryRequest,
    OperationSecretMaterialPolicy, RngOutputKind as ProtoPurpose,
    SecretMaterialOperation as ProtoOperation,
};
use reallyme_crypto::secret_material::{
    contract::{operation_policy, random_fill_policy},
    operation_secret_material_policy, random_fill_secret_material_policy, SecretMaterialOperation,
};

#[test]
fn operation_query_preserves_every_generated_policy_and_rejects_zero() {
    fn require_cleanup<T: zeroize::ZeroizeOnDrop>() {}
    require_cleanup::<CryptoMaterialPolicyQueryRequest>();
    for operation in ProtoOperation::values() {
        let request = CryptoMaterialPolicyQueryRequest {
            operation: (*operation).into(),
            __buffa_unknown_fields: Default::default(),
        };
        let expected = SecretMaterialOperation::try_from(request.operation)
            .map(operation_secret_material_policy)
            .map(OperationSecretMaterialPolicy::from);
        assert_eq!(operation_policy(&request), expected);
    }
}
#[test]
fn random_fill_query_preserves_every_existing_purpose_policy() {
    fn require_cleanup<T: zeroize::ZeroizeOnDrop>() {}
    require_cleanup::<CryptoRandomFillPolicyQueryRequest>();
    for purpose in ProtoPurpose::values() {
        let request = CryptoRandomFillPolicyQueryRequest {
            purpose: (*purpose).into(),
            __buffa_unknown_fields: Default::default(),
        };
        let expected = RngOutputKind::try_from(request.purpose)
            .map(random_fill_secret_material_policy)
            .map(OperationSecretMaterialPolicy::from);
        assert_eq!(random_fill_policy(&request), expected);
    }
}
#[test]
fn policy_queries_reject_unknown_selectors_and_unknown_modifiers() -> Result<(), buffa::DecodeError>
{
    for unknown in [0, -1, 1, i32::MAX] {
        let operation = CryptoMaterialPolicyQueryRequest {
            operation: EnumValue::from(unknown),
            __buffa_unknown_fields: Default::default(),
        };
        let random = CryptoRandomFillPolicyQueryRequest {
            purpose: EnumValue::from(unknown),
            __buffa_unknown_fields: Default::default(),
        };
        assert_eq!(
            operation_policy(&operation),
            Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
        );
        assert_eq!(
            random_fill_policy(&random),
            Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
        );
    }
    let mut operation = CryptoMaterialPolicyQueryRequest {
        operation: ProtoOperation::from(SecretMaterialOperation::Hash).into(),
        __buffa_unknown_fields: Default::default(),
    };
    operation.merge_from_slice(&[0xa0, 0x06, 1])?;
    assert_eq!(
        operation_policy(&operation),
        Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    let mut random = CryptoRandomFillPolicyQueryRequest {
        purpose: ProtoPurpose::from(RngOutputKind::Generic).into(),
        __buffa_unknown_fields: Default::default(),
    };
    random.merge_from_slice(&[0xa0, 0x06, 1])?;
    assert_eq!(
        random_fill_policy(&random),
        Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    Ok(())
}
