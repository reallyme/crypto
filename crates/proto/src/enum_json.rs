// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fixed diagnostics for the schema-owned concrete enum representations.

use core::{fmt, marker::PhantomData};
use serde::{
    de::{EnumAccess, Error, MapAccess, SeqAccess, Visitor},
    Deserializer,
};
use zeroize::Zeroizing;

use crate::error_types::CryptoError;

pub(crate) fn deserialize<'de, E, D>(deserializer: D) -> Result<E, D::Error>
where
    E: buffa::Enumeration + Default,
    D: Deserializer<'de>,
{
    struct EnumVisitor<E>(PhantomData<E>);
    impl<'de, E: buffa::Enumeration + Default> Visitor<'de> for EnumVisitor<E> {
        type Value = E;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a declared protobuf enum name, number, or null")
        }
        fn visit_str<T: Error>(self, value: &str) -> Result<E, T> {
            E::from_proto_name(value)
                .ok_or_else(|| T::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
        }
        fn visit_string<T: Error>(self, value: String) -> Result<E, T> {
            let value = Zeroizing::new(value);
            self.visit_str(&value)
        }
        fn visit_i64<T: Error>(self, value: i64) -> Result<E, T> {
            i32::try_from(value)
                .ok()
                .and_then(E::from_i32)
                .ok_or_else(|| T::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
        }
        fn visit_u64<T: Error>(self, value: u64) -> Result<E, T> {
            i32::try_from(value)
                .ok()
                .and_then(E::from_i32)
                .ok_or_else(|| T::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
        }
        fn visit_unit<T: Error>(self) -> Result<E, T> {
            Ok(E::default())
        }
        fn visit_bool<T: Error>(self, _: bool) -> Result<E, T> {
            Err(T::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
        }
        fn visit_f64<T: Error>(self, _: f64) -> Result<E, T> {
            Err(T::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
        }
        fn visit_i128<T: Error>(self, _: i128) -> Result<E, T> {
            Err(T::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
        }
        fn visit_u128<T: Error>(self, _: u128) -> Result<E, T> {
            Err(T::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
        }
        fn visit_bytes<T: Error>(self, _: &[u8]) -> Result<E, T> {
            Err(T::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
        }
        fn visit_byte_buf<T: Error>(self, value: Vec<u8>) -> Result<E, T> {
            let _value = Zeroizing::new(value);
            Err(T::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
        }
        fn visit_seq<A: SeqAccess<'de>>(self, _: A) -> Result<E, A::Error> {
            Err(A::Error::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
        }
        fn visit_map<A: MapAccess<'de>>(self, _: A) -> Result<E, A::Error> {
            Err(A::Error::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
        }
        fn visit_enum<A: EnumAccess<'de>>(self, _: A) -> Result<E, A::Error> {
            Err(A::Error::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
        }
    }
    deserializer.deserialize_any(EnumVisitor(PhantomData))
}
