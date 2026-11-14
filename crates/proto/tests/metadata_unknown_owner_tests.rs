// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Clearing numeric records and full-tree admission.

#![allow(missing_docs, clippy::expect_used)]
#![cfg(feature = "generated")]

use buffa::{DecodeError, DecodeOptions, Message};
use reallyme_crypto_proto::generated::proto::reallyme::crypto::v1::{
    Argon2Caps, Argon2CapsOwnedView, Argon2ParamsProfile, MaterialPolicy,
    OperationSecretMaterialPolicy, OperationSecretMaterialPolicyView,
};
use reallyme_crypto_proto::wire::{decode_protobuf, CryptoWireError};

const UNKNOWN_GROUP: &[u8] = &[0xa3, 0x06, 0x0a, 3, b'k', b'e', b'y', 0xa4, 0x06];

fn check_unknown_contract<M>()
where
    M: Message + core::fmt::Debug + PartialEq + zeroize::ZeroizeOnDrop,
{
    assert!(core::mem::needs_drop::<M>());
    assert_eq!(
        decode_protobuf::<M>(UNKNOWN_GROUP),
        Err(CryptoWireError::malformed_protobuf())
    );
    assert!(matches!(
        DecodeOptions::new()
            .reject_unknown_fields()
            .decode_from_slice::<M>(UNKNOWN_GROUP),
        Err(DecodeError::UnknownFieldLimitExceeded)
    ));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn numeric_metadata_rejects_unknown_fields_at_admission() {
    check_unknown_contract::<Argon2Caps>();
    check_unknown_contract::<Argon2ParamsProfile>();
    check_unknown_contract::<MaterialPolicy>();
    check_unknown_contract::<OperationSecretMaterialPolicy>();
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn owned_and_eager_policy_decoders_reject_unknown_nested_fields() {
    let child = [0x0a, 3, 0xa0, 0x06, 1];
    assert_eq!(
        decode_protobuf::<OperationSecretMaterialPolicy>(&child),
        Err(CryptoWireError::malformed_protobuf())
    );
    assert!(matches!(
        DecodeOptions::new()
            .reject_unknown_fields()
            .decode_view::<OperationSecretMaterialPolicyView>(&child),
        Err(DecodeError::UnknownFieldLimitExceeded)
    ));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn numeric_cleanup_resets_all_fields_without_changing_a_clone() {
    let mut caps = Argon2Caps {
        mem_cap_kib: 32768,
        time_cost_cap: 3,
        lanes_cap: 2,
    };
    let clone = caps.clone();
    Message::clear(&mut caps);
    assert_eq!(caps, Argon2Caps::default());
    assert_eq!(clone.mem_cap_kib, 32768);
    assert_eq!(clone.time_cost_cap, 3);
    assert_eq!(clone.lanes_cap, 2);
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
        serde_json::from_str(r#"{"memKib":32768,"timeCost":"2","lanes":1}"#)?;
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
    let owned = Argon2Caps {
        mem_cap_kib: 32768,
        time_cost_cap: 912,
        lanes_cap: 2,
    };
    let handle = Argon2CapsOwnedView::from_owned(&owned)?;
    let clone = handle.clone();
    let view = clone.view().clone();
    for debug in [
        format!("{owned:?}"),
        format!("{handle:?}"),
        format!("{view:?}"),
    ] {
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("32768"));
        assert!(!debug.contains("912"));
    }
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
    assert_eq!(round_trip, owned);
    Ok(())
}
