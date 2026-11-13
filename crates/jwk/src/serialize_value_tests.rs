// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::ClearingJsonValue;
use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[test]
fn trusted_intermediate_clears_strings_and_owned_map_entries() {
    fn cleanup<T: ZeroizeOnDrop>() {}
    cleanup::<ClearingJsonValue>();
    let mut map = serde_json::Map::new();
    map.insert(
        "correlating-key".to_owned(),
        Value::Array(vec![Value::String("correlating-value".to_owned())]),
    );
    let mut owner = ClearingJsonValue(Value::Object(map));
    owner.zeroize();
    assert!(matches!(&owner.0, Value::Object(map) if map.is_empty()));
    let mut owner = ClearingJsonValue(Value::Array(vec![Value::String("value".to_owned())]));
    owner.zeroize();
    assert!(
        matches!(&owner.0, Value::Array(values) if matches!(values.first(), Some(Value::String(value)) if value.is_empty()))
    );
}
