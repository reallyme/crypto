// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Clearing ownership for trusted public-JWK serialization intermediates.

use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub(crate) struct ClearingJsonValue(pub(crate) Value);
impl Zeroize for ClearingJsonValue {
    fn zeroize(&mut self) {
        clear_value(&mut self.0);
    }
}
impl Drop for ClearingJsonValue {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for ClearingJsonValue {}
fn clear_value(value: &mut Value) {
    // Only fixed, flat public-JWK serializers produce these values. Nested
    // containers are covered so future trusted additions keep the obligation.
    match value {
        Value::String(value) => value.zeroize(),
        Value::Array(values) => {
            for value in values {
                clear_value(value);
            }
        }
        Value::Object(values) => {
            // Map keys are owned strings too; taking entries needs no allocation.
            for (mut key, mut value) in core::mem::take(values) {
                key.zeroize();
                clear_value(&mut value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[cfg(test)]
#[path = "serialize_value_tests.rs"]
mod tests;
