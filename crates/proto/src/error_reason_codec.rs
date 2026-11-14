// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error_types::CryptoErrorReason;
use buffa::{json_helpers::closed_enum, Enumeration};
use serde::{Deserializer, Serializer};

// The schema reason also serves the minimal error-types feature, which
// deliberately has no Buffa dependency. Attach wire traits only here.
impl Enumeration for CryptoErrorReason {
    fn from_i32(value: i32) -> Option<Self> {
        Self::from_code(value)
    }

    fn to_i32(&self) -> i32 {
        self.code()
    }

    fn proto_name(&self) -> &'static str {
        self.name()
    }

    fn from_proto_name(name: &str) -> Option<Self> {
        Self::VALUES
            .iter()
            .copied()
            .find(|value| value.name() == name)
    }

    fn values() -> &'static [Self] {
        Self::VALUES
    }
}

impl zeroize::Zeroize for CryptoErrorReason {
    fn zeroize(&mut self) {
        buffa::sensitive::reset_copy(self);
    }
}

impl serde::Serialize for CryptoErrorReason {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        closed_enum::serialize(self, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for CryptoErrorReason {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        closed_enum::deserialize_strict(deserializer)
    }
}

impl buffa::json_helpers::ProtoElemJson for CryptoErrorReason {
    fn serialize_proto_json<S: Serializer>(value: &Self, serializer: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(value, serializer)
    }

    fn deserialize_proto_json<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        serde::Deserialize::deserialize(deserializer)
    }
}
