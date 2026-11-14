// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::unwrap_used)]

use buffa::view::{LazyMessageView, MessageView};
use buffa::{DecodeError, DecodeOptions, Message, MessageField};
use buffa_descriptor::reflect::{
    InspectElement, InspectMessage, InspectValueRef, MapKeyRef, ReflectMapKey,
};
use zeroize::ZeroizeOnDrop;

use crate::{SecretBytes, SecretString};
use guarded_fixture_bindings::guarded_fixture::{
    Child, ChildLazyView, ChildView, Fixture, FixtureLazyView, FixtureView,
};

// The fixture's reflection pool is generated from a fixed, compiled schema.
#[allow(clippy::expect_used)]
#[path = "../tests/fixtures/guarded/generated/mod.rs"]
mod guarded_fixture_bindings;

// This fixture is a distinct generation. Disable its automatic custom scalar
// impls and supply the shared scalar bridges where the types are defined.
impl InspectElement for SecretBytes {
    fn as_inspect_value(&self) -> InspectValueRef<'_> {
        InspectValueRef::Bytes(self)
    }
}

impl buffa::json_helpers::ProtoElemJson for SecretBytes {
    fn serialize_proto_json<S: serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        <Self as buffa::json_helpers::ProtoBytesJson>::serialize_json(value, serializer)
    }

    fn deserialize_proto_json<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        <Self as buffa::json_helpers::ProtoBytesJson>::deserialize_json(deserializer)
    }
}

impl ReflectMapKey for SecretString {
    fn as_map_key_ref(&self) -> MapKeyRef<'_> {
        MapKeyRef::String(self)
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn guarded_collections_and_wkt_trees_round_trip_without_dynamic_snapshots() {
    fn owner<T: ZeroizeOnDrop>() {}
    owner::<Fixture>();
    owner::<buffa_types::sensitive::Timestamp>();
    owner::<buffa_types::sensitive::Duration>();
    owner::<buffa_types::sensitive::Value>();
    owner::<buffa_types::sensitive::Struct>();
    owner::<buffa_types::sensitive::ListValue>();

    let json = r#"{"embedding":[1.5,-2.25],"entries":{"key":"YQ=="},"time":"2026-01-01T00:00:00Z","interval":"1.250s","value":{"nested":["value",true,null]},"object":{"leaf":[1,2]},"list":[{"leaf":"value"}],"child":{"data":"AP8=","note":"value"}}"#;
    let mut fixture: Fixture = serde_json::from_str(json).unwrap();
    fixture
        .entries
        .insert(String::from("key").into(), vec![0, 0xff].into());
    assert_eq!(
        fixture.entries.get("key").map(SecretBytes::as_slice),
        Some([0, 0xff].as_slice())
    );
    for _ in 0..128 {
        fixture.embedding.push(3.5);
    }
    let encoded = zeroize::Zeroizing::new(fixture.encode_to_vec());
    let opts = DecodeOptions::new()
        .with_max_message_size(4096)
        .reject_unknown_fields();
    let decoded = opts.decode_from_slice::<Fixture>(&encoded).unwrap();
    assert_eq!(decoded, fixture);
    let view = opts.decode_view::<FixtureView>(&encoded).unwrap();
    assert_eq!(view.to_owned_message().unwrap(), fixture);
    let lazy = opts.decode_lazy_view::<FixtureLazyView>(&encoded).unwrap();
    assert_eq!(lazy.to_owned_message().unwrap(), fixture);
    assert!(serde_json::to_string(&view).is_err());
    assert!(serde_json::to_string(&lazy).is_err());
    assert!(serde_json::to_string(&FixtureView::default()).is_err());
    let json = serde_json::to_string(&fixture).unwrap();
    assert_eq!(serde_json::from_str::<Fixture>(&json).unwrap(), fixture);

    let handle = fixture.inspect();
    let field = handle
        .message_descriptor()
        .field_by_name("embedding")
        .unwrap();
    let values = handle.get(field).unwrap();
    assert!(matches!(&values, InspectValueRef::List(list) if list.len() == 130));
    assert!(!format!("{values:?}").contains("3.5"));
    drop(values);
    let borrowed = view.inspect();
    let field = borrowed
        .message_descriptor()
        .field_by_name("value")
        .unwrap();
    assert!(matches!(
        borrowed.get(field).unwrap(),
        InspectValueRef::Message(_)
    ));
    let clone = fixture.clone();
    fixture.clear();
    assert!(fixture.embedding.is_empty());
    assert!(fixture.entries.is_empty());
    assert_eq!(fixture.value, MessageField::none());
    assert_eq!(clone.embedding.len(), 130);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn lazy_construction_cannot_admit_unvalidated_children() {
    // Field 8 contains a child with unknown length-delimited field 100.
    let bytes = *b"\x42\x09\xa2\x06\x06marker";
    let opts = DecodeOptions::new().reject_unknown_fields();
    assert!(matches!(
        opts.decode_from_slice::<Fixture>(&bytes),
        Err(DecodeError::UnknownFieldLimitExceeded)
    ));
    assert!(matches!(
        opts.decode_view::<FixtureView>(&bytes),
        Err(DecodeError::UnknownFieldLimitExceeded)
    ));
    let pending = opts.decode_lazy_view::<FixtureLazyView>(&bytes).unwrap();
    assert!(!format!("{pending:?}").contains("marker"));
    assert!(matches!(
        pending.to_owned_message(),
        Err(DecodeError::UnknownFieldLimitExceeded)
    ));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn guarded_view_debug_hides_oneof_and_json_denies_even_empty_views() {
    let child = serde_json::from_str::<Child>(r#"{"note":"private-note-marker"}"#).unwrap();
    let bytes = crate::wire::encode_protobuf(&child).unwrap();
    let options = DecodeOptions::new().reject_unknown_fields();
    let eager = options.decode_view::<ChildView>(&bytes).unwrap();
    let lazy = options.decode_lazy_view::<ChildLazyView>(&bytes).unwrap();
    let owned = crate::GuardedOwnedView::<ChildView<'static>>::from_owned(&child).unwrap();
    assert_eq!(eager.to_owned_message().unwrap(), child);
    assert_eq!(lazy.to_owned_message().unwrap(), child);
    assert_eq!(owned.to_owned_message().unwrap(), child);
    for debug in [
        format!("{eager:?}"),
        format!("{lazy:?}"),
        format!("{owned:?}"),
        format!("{:?}", eager.selection.as_ref().unwrap()),
        format!("{:?}", lazy.selection.as_ref().unwrap()),
        format!("{:?}", owned.view().selection.as_ref().unwrap()),
    ] {
        assert!(!debug.contains("private-note-marker"));
        assert!(!debug.contains("Note"));
    }
    let empty_owned =
        crate::GuardedOwnedView::<ChildView<'static>>::from_owned(&Child::default()).unwrap();
    assert!(serde_json::to_string(&ChildView::default()).is_err());
    assert!(serde_json::to_string(&ChildLazyView::default()).is_err());
    assert!(serde_json::to_string(&empty_owned).is_err());
}
