// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{bytes::Buf, DecodeError, FieldPayload, ProtoString, WirePayload};
use core::{
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
    ops::Deref,
};
use serde::de::{Error, Visitor};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error_types::CryptoError;

/// Protobuf UTF-8 storage whose allocation and spare capacity clear on release.
#[derive(Default)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Borrow text without duplicating its owner.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    fn copy(value: &str) -> Result<Self, CryptoError> {
        let mut text = Zeroizing::new(String::new());
        text.try_reserve_exact(value.len())
            .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
        text.push_str(value);
        Ok(Self(text))
    }
}
impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
}
impl Clone for SecretString {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl Deref for SecretString {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}
impl AsRef<str> for SecretString {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl core::borrow::Borrow<str> for SecretString {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}
impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}
impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.as_bytes().ct_eq(other.as_bytes()))
    }
}
impl Eq for SecretString {}
impl PartialOrd for SecretString {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for SecretString {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_str().cmp(other.as_str())
    }
}
impl Hash for SecretString {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}
impl Zeroize for SecretString {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl ZeroizeOnDrop for SecretString {}
impl ProtoString for SecretString {
    fn from_wire(payload: WirePayload<'_>) -> Result<Self, DecodeError> {
        Self::copy(payload.to_str()?).map_err(|_| DecodeError::MessageTooLarge)
    }
    fn decode_length_delimited(payload: &mut FieldPayload<impl Buf>) -> Result<Self, DecodeError> {
        let mut bytes = super::read_payload(payload)?;
        if core::str::from_utf8(&bytes).is_err() {
            return Err(DecodeError::InvalidUtf8);
        }
        match String::from_utf8(core::mem::take(&mut *bytes)) {
            Ok(text) => Ok(Self::from(text)),
            Err(error) => {
                let _rejected = Zeroizing::new(error.into_bytes());
                Err(DecodeError::InvalidUtf8)
            }
        }
    }
}
impl buffa::json_helpers::ProtoStringJson for SecretString {
    fn serialize_json<S: serde::Serializer>(value: &str, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(value)
    }
    fn deserialize_json<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        struct TextVisitor;
        impl Visitor<'_> for TextVisitor {
            type Value = SecretString;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a UTF-8 string")
            }
            fn visit_str<E: Error>(self, value: &str) -> Result<Self::Value, E> {
                SecretString::copy(value).map_err(E::custom)
            }
            fn visit_string<E: Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(value.into())
            }
            fn visit_byte_buf<E: Error>(self, value: Vec<u8>) -> Result<Self::Value, E> {
                let _value = Zeroizing::new(value);
                Err(E::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
            }
        }
        deserializer.deserialize_string(TextVisitor)
    }
}
