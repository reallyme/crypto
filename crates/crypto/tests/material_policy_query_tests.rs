// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::expect_used)]
#![cfg(feature = "operation-response")]
use buffa::{EnumValue, Enumeration};
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

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn operation_query_preserves_every_generated_policy_and_rejects_zero() {
    fn require_cleanup<T: zeroize::ZeroizeOnDrop>() {}
    require_cleanup::<CryptoMaterialPolicyQueryRequest>();
    for operation in ProtoOperation::values() {
        let request = CryptoMaterialPolicyQueryRequest {
            operation: (*operation).into(),
        };
        let expected = SecretMaterialOperation::try_from(request.operation)
            .map(operation_secret_material_policy)
            .map(OperationSecretMaterialPolicy::from);
        assert_eq!(operation_policy(&request), expected);
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn random_fill_query_preserves_every_existing_purpose_policy() {
    fn require_cleanup<T: zeroize::ZeroizeOnDrop>() {}
    require_cleanup::<CryptoRandomFillPolicyQueryRequest>();
    for purpose in ProtoPurpose::values() {
        let request = CryptoRandomFillPolicyQueryRequest {
            purpose: (*purpose).into(),
        };
        let expected = RngOutputKind::try_from(request.purpose)
            .map(random_fill_secret_material_policy)
            .map(OperationSecretMaterialPolicy::from);
        assert_eq!(random_fill_policy(&request), expected);
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn policy_queries_reject_unknown_selectors_and_unknown_modifiers() -> Result<(), buffa::DecodeError>
{
    for unknown in [0, -1, 1, i32::MAX] {
        let operation = CryptoMaterialPolicyQueryRequest {
            operation: EnumValue::from(unknown),
        };
        let random = CryptoRandomFillPolicyQueryRequest {
            purpose: EnumValue::from(unknown),
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
    let operation = CryptoMaterialPolicyQueryRequest {
        operation: ProtoOperation::from(SecretMaterialOperation::Hash).into(),
    };
    assert_unknown_wire(&operation, &[0xa0, 0x06, 1]);
    let random = CryptoRandomFillPolicyQueryRequest {
        purpose: ProtoPurpose::from(RngOutputKind::Generic).into(),
    };
    assert_unknown_wire(&random, &[0xa0, 0x06, 1]);
    Ok(())
}

fn assert_unknown_wire<M: buffa::Message>(message: &M, modifier: &[u8]) {
    let mut wire = message.encode_to_vec();
    wire.extend_from_slice(modifier);
    assert!(matches!(crypto_proto::wire::decode_protobuf::<M>(&wire),
        Err(error) if error == crypto_proto::wire::CryptoWireError::malformed_protobuf()));
}
