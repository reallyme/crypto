// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{canonicalize_jwk, JwtError};
use serde::{ser::Error, Serialize, Serializer};

struct FailedSerializer;

impl Serialize for FailedSerializer {
    fn serialize<S: Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
        Err(S::Error::custom("public serializer fixture failure"))
    }
}

#[test]
fn trusted_serializer_failures_are_internal() {
    assert_eq!(
        canonicalize_jwk(&FailedSerializer),
        Err(JwtError::BACKEND_INTERNAL)
    );
}

#[test]
fn caller_noncharacters_are_invalid_encoding() {
    assert_eq!(
        canonicalize_jwk(&serde_json::json!({"kid":"\u{fdd0}"})),
        Err(JwtError::PRIMITIVE_INVALID_ENCODING)
    );
}
