// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Retained unknown-byte ownership in descriptive numeric protobuf records.

#![allow(missing_docs, clippy::expect_used)]
#![cfg(feature = "generated")]

use buffa::{DecodeError, DecodeOptions, ExtensionSet, Message};
use reallyme_crypto_proto::generated::proto::reallyme::crypto::v1::{
    Argon2Caps, Argon2CapsOwnedView, Argon2ParamsProfile, MaterialPolicy,
    OperationSecretMaterialPolicy,
};

// Unknown groups may contain future byte-bearing fields even when every known
// field is numeric. Error cases exercise owner lifetime and typed failures;
// they do not inspect freed memory or claim to erase caller-borrowed input.
const UNKNOWN_GROUP: &[u8] = &[0xa3, 0x06, 0x0a, 3, b'k', b'e', b'y', 0xa4, 0x06];
const PARTIAL_GROUP: &[u8] = &[0xa3, 0x06, 0x0a, 3, b'k', b'e', b'y'];

fn check_unknown_contract<M>() -> Result<(), DecodeError>
where
    M: Message + ExtensionSet + core::fmt::Debug + zeroize::ZeroizeOnDrop,
{
    assert!(core::mem::needs_drop::<M>());
    let mut message = M::decode_from_slice(UNKNOWN_GROUP)?;
    assert_eq!(message.unknown_fields().len(), 1);
    assert_eq!(message.encode_to_vec(), UNKNOWN_GROUP);
    let cloned = message.clone();
    assert_eq!(cloned, message);
    assert_eq!(cloned.encode_to_vec(), UNKNOWN_GROUP);
    message.clear();
    assert!(message.unknown_fields().is_empty());
    assert!(message.encode_to_vec().is_empty());
    assert_eq!(cloned.encode_to_vec(), UNKNOWN_GROUP);
    assert!(format!("{cloned:?}").ends_with("(<redacted>)"));
    assert!(matches!(
        M::decode_from_slice(PARTIAL_GROUP),
        Err(DecodeError::UnexpectedEof)
    ));
    let wrong_end = [0xa3, 0x06, 0x0a, 3, b'k', b'e', b'y', 0xac, 0x06];
    assert!(matches!(
        M::decode_from_slice(&wrong_end),
        Err(DecodeError::InvalidEndGroup(101))
    ));
    let wrong_nested_end = [
        0xa3, 0x06, 0xab, 0x06, 0x0a, 3, b'k', b'e', b'y', 0xa4, 0x06,
    ];
    assert!(matches!(
        M::decode_from_slice(&wrong_nested_end),
        Err(DecodeError::InvalidEndGroup(100))
    ));
    let limited: Result<M, _> = DecodeOptions::new()
        .with_unknown_field_limit(1)
        .decode_from_slice(UNKNOWN_GROUP);
    assert!(matches!(
        limited,
        Err(DecodeError::UnknownFieldLimitExceeded)
    ));
    let no_depth: Result<M, _> = DecodeOptions::new()
        .with_recursion_limit(0)
        .decode_from_slice(UNKNOWN_GROUP);
    assert!(matches!(no_depth, Err(DecodeError::RecursionLimitExceeded)));
    let admitted: M = DecodeOptions::new()
        .with_unknown_field_limit(2)
        .decode_from_slice(UNKNOWN_GROUP)?;
    assert_eq!(admitted.encode_to_vec(), UNKNOWN_GROUP);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn numeric_metadata_records_guard_unknown_bytes() -> Result<(), DecodeError> {
    check_unknown_contract::<Argon2Caps>()?;
    check_unknown_contract::<Argon2ParamsProfile>()?;
    check_unknown_contract::<MaterialPolicy>()?;
    check_unknown_contract::<OperationSecretMaterialPolicy>()
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn nested_policy_partial_unknown_group_preserves_decode_error() {
    // The known input policy starts decoding before its unknown group fails.
    let partial_child = [0x0a, 7, 0xa3, 0x06, 0x0a, 3, b'k', b'e', b'y'];
    assert!(matches!(
        OperationSecretMaterialPolicy::decode_from_slice(&partial_child),
        Err(DecodeError::UnexpectedEof)
    ));
    let wrong_child_end = [0x0a, 9, 0xa3, 0x06, 0x0a, 3, b'k', b'e', b'y', 0xac, 0x06];
    assert!(matches!(
        OperationSecretMaterialPolicy::decode_from_slice(&wrong_child_end),
        Err(DecodeError::InvalidEndGroup(101))
    ));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn metadata_records_preserve_public_field_transfers() -> Result<(), DecodeError> {
    let policy = OperationSecretMaterialPolicy::decode_from_slice(&[0x0a, 0])?;
    let input = policy.input;
    assert!(input.as_option().is_some());
    // A struct-level Drop would make these previously legal field moves fail.
    let caps = Argon2Caps::decode_from_slice(UNKNOWN_GROUP)?;
    let retained = caps.__buffa_unknown_fields;
    assert_eq!(retained.len(), 1);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn numeric_metadata_json_defaults_and_values_remain_unchanged() -> Result<(), serde_json::Error> {
    let caps: Argon2Caps =
        serde_json::from_str(r#"{"memCapKib":"32768","timeCostCap":3,"lanesCap":null}"#)?;
    assert_eq!(caps.mem_cap_kib, 32768);
    assert_eq!(caps.time_cost_cap, 3);
    assert_eq!(caps.lanes_cap, 0);
    let encoded = serde_json::to_value(&caps)?;
    let round_trip: Argon2Caps = serde_json::from_value(encoded)?;
    assert_eq!(round_trip, caps);
    let params: Argon2ParamsProfile =
        serde_json::from_str(r#"{"memKib":32768,"timeCost":"2","lanes":1,"futureNumericHint":7}"#)?;
    assert_eq!(params.mem_kib, 32768);
    assert_eq!(params.time_cost, 2);
    assert_eq!(params.lanes, 1);
    let policy: OperationSecretMaterialPolicy = serde_json::from_str(r#"{"input":{}}"#)?;
    assert!(policy.input.as_option().is_some());
    let material: MaterialPolicy = serde_json::from_str("{}")?;
    assert_eq!(serde_json::to_value(material)?, serde_json::json!({}));
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn numeric_metadata_views_keep_clone_and_json_with_redacted_debug() -> Result<(), DecodeError> {
    let owned = Argon2Caps::decode_from_slice(UNKNOWN_GROUP)?;
    let handle = Argon2CapsOwnedView::from_owned(&owned)?;
    let clone = handle.clone();
    let view = clone.view().clone();
    assert_eq!(format!("{owned:?}"), "Argon2Caps(<redacted>)");
    assert_eq!(format!("{handle:?}"), "Argon2CapsOwnedView(<redacted>)");
    assert_eq!(format!("{view:?}"), "Argon2CapsView(<redacted>)");
    let json = serde_json::to_value(&owned).expect("numeric metadata serializes");
    assert_eq!(
        serde_json::to_value(&handle).expect("owned metadata view serializes"),
        json
    );
    assert_eq!(
        serde_json::to_value(&view).expect("borrowed metadata view serializes"),
        json
    );
    let round_trip = handle.to_owned_message();
    assert_eq!(round_trip.encode_to_vec(), UNKNOWN_GROUP);
    Ok(())
}
