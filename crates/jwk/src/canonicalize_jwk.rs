// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical JSON output from programmatically constructed public JWK values.

use crate::JwtError;
use codec_jcs::{canonicalize_trusted_json_value, JcsError};
use serde::Serialize;

pub(crate) fn canonicalize_jwk<T: Serialize + ?Sized>(jwk: &T) -> Result<String, JwtError> {
    // These callers serialize fixed, flat public-JWK fields. Serializer and
    // structural/number/depth failures therefore indicate a trusted invariant
    // failure, rather than malformed untrusted JSON text.
    let value = crate::serialize_value::ClearingJsonValue(
        serde_json::to_value(jwk).map_err(|_| JwtError::BACKEND_INTERNAL)?,
    );
    canonicalize_trusted_json_value(&value.0).map_err(|error| match error {
        // Optional caller metadata can carry an I-JSON-forbidden noncharacter.
        // Preserve this real input rejection instead of calling it internal.
        JcsError::Noncharacter => JwtError::PRIMITIVE_INVALID_ENCODING,
        _ => JwtError::BACKEND_INTERNAL,
    })
}

#[cfg(test)]
#[path = "canonicalize_jwk_tests.rs"]
mod tests;
