// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::ser::Error;
use zeroize::Zeroizing;

use crate::error_types::CryptoError;

pub(super) fn serialize_bytes<S: serde::Serializer>(
    value: &[u8],
    serializer: S,
    export: bool,
) -> Result<S::Ok, S::Error> {
    if !export {
        return Err(S::Error::custom(CryptoError::PROVIDER_ACCESS_DENIED));
    }
    let capacity = value
        .len()
        .checked_add(2)
        .map(|length| length / 3)
        .and_then(|length| length.checked_mul(4))
        .ok_or_else(|| S::Error::custom(CryptoError::PRIMITIVE_INVALID_LENGTH))?;
    let mut encoded = Zeroizing::new(Vec::new());
    encoded
        .try_reserve_exact(capacity)
        .map_err(|_| S::Error::custom(CryptoError::BACKEND_INTERNAL))?;
    encoded.resize(capacity, 0);
    let length = STANDARD
        .encode_slice(value, &mut encoded)
        .map_err(|_| S::Error::custom(CryptoError::BACKEND_INTERNAL))?;
    let bytes = encoded
        .get(..length)
        .ok_or_else(|| S::Error::custom(CryptoError::BACKEND_INTERNAL))?;
    let text =
        core::str::from_utf8(bytes).map_err(|_| S::Error::custom(CryptoError::BACKEND_INTERNAL))?;
    serializer.serialize_str(text)
}
