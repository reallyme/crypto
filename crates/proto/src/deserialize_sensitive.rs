// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Clearing storage for protobuf JSON byte decoding.

use base64::{
    alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
    Engine,
};
use serde::de::{EnumAccess, Error as SerdeError, MapAccess, SeqAccess, Visitor};
use serde::Deserializer;
use zeroize::{Zeroize, Zeroizing};

use crate::error_types::CryptoError;

const ENCODED_QUANTUM_BYTES: usize = 4;
const DECODED_QUANTUM_BYTES: usize = 3;

// Match the pinned Buffa JSON byte helpers: both alphabets, optional padding,
// and noncanonical trailing bits remain accepted. Only storage ownership and
// fixed diagnostics change at this boundary.
const LENIENT_CONFIG: GeneralPurposeConfig = GeneralPurposeConfig::new()
    .with_decode_allow_trailing_bits(true)
    .with_decode_padding_mode(DecodePaddingMode::Indifferent);
const STANDARD_LENIENT: GeneralPurpose = GeneralPurpose::new(&alphabet::STANDARD, LENIENT_CONFIG);
const URL_SAFE_LENIENT: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, LENIENT_CONFIG);

fn decode_into(value: &str, output: &mut [u8]) -> Result<usize, CryptoError> {
    match STANDARD_LENIENT.decode_slice(value, output) {
        Ok(length) => Ok(length),
        Err(_) => {
            // A decoder can write complete quanta before rejecting a later
            // character. Wipe those bytes before trying the second alphabet.
            output.zeroize();
            match URL_SAFE_LENIENT.decode_slice(value, output) {
                Ok(length) => Ok(length),
                Err(_) => {
                    output.zeroize();
                    Err(CryptoError::PRIMITIVE_INVALID_ENCODING)
                }
            }
        }
    }
}

fn decode_bytes(value: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let full_quanta = value.len() / ENCODED_QUANTUM_BYTES;
    let has_partial = !value.len().is_multiple_of(ENCODED_QUANTUM_BYTES);
    let quanta = full_quanta
        .checked_add(usize::from(has_partial))
        .ok_or(CryptoError::PRIMITIVE_INVALID_LENGTH)?;
    let capacity = quanta
        .checked_mul(DECODED_QUANTUM_BYTES)
        .ok_or(CryptoError::PRIMITIVE_INVALID_LENGTH)?;
    let mut output = Zeroizing::new(Vec::new());
    output
        .try_reserve_exact(capacity)
        .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    output.resize(capacity, 0);
    let length = decode_into(value, output.as_mut_slice())?;
    output
        .get_mut(length..)
        .ok_or(CryptoError::PRIMITIVE_INVALID_LENGTH)?
        .zeroize();
    output.truncate(length);
    Ok(output)
}

struct BytesVisitor;

impl<'de> Visitor<'de> for BytesVisitor {
    type Value = Zeroizing<Vec<u8>>;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("a base64-encoded string, or null")
    }

    fn visit_unit<E: SerdeError>(self) -> Result<Self::Value, E> {
        Ok(Zeroizing::new(Vec::new()))
    }

    fn visit_str<E: SerdeError>(self, value: &str) -> Result<Self::Value, E> {
        decode_bytes(value).map_err(E::custom)
    }

    fn visit_string<E: SerdeError>(self, value: String) -> Result<Self::Value, E> {
        // Owned strings may contain unescaped confidential text. Borrowed
        // deserializer input remains borrowed and is not copied or modified.
        let value = Zeroizing::new(value);
        decode_bytes(value.as_str()).map_err(E::custom)
    }

    fn visit_bool<E: SerdeError>(self, _value: bool) -> Result<Self::Value, E> {
        Err(E::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
    }

    fn visit_i64<E: SerdeError>(self, _value: i64) -> Result<Self::Value, E> {
        Err(E::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
    }

    fn visit_u64<E: SerdeError>(self, _value: u64) -> Result<Self::Value, E> {
        Err(E::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
    }

    fn visit_i128<E: SerdeError>(self, _value: i128) -> Result<Self::Value, E> {
        Err(E::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
    }

    fn visit_u128<E: SerdeError>(self, _value: u128) -> Result<Self::Value, E> {
        Err(E::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
    }

    fn visit_f64<E: SerdeError>(self, _value: f64) -> Result<Self::Value, E> {
        Err(E::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
    }

    fn visit_char<E: SerdeError>(self, _value: char) -> Result<Self::Value, E> {
        Err(E::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
    }

    fn visit_bytes<E: SerdeError>(self, _value: &[u8]) -> Result<Self::Value, E> {
        Err(E::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
    }

    fn visit_byte_buf<E: SerdeError>(self, value: Vec<u8>) -> Result<Self::Value, E> {
        let _value = Zeroizing::new(value);
        Err(E::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
    }

    fn visit_none<E: SerdeError>(self) -> Result<Self::Value, E> {
        Err(E::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
    }

    fn visit_some<D: Deserializer<'de>>(self, _value: D) -> Result<Self::Value, D::Error> {
        Err(D::Error::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(
        self,
        _value: D,
    ) -> Result<Self::Value, D::Error> {
        Err(D::Error::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, _value: A) -> Result<Self::Value, A::Error> {
        Err(A::Error::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
    }

    fn visit_map<A: MapAccess<'de>>(self, _value: A) -> Result<Self::Value, A::Error> {
        Err(A::Error::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
    }

    fn visit_enum<A: EnumAccess<'de>>(self, _value: A) -> Result<Self::Value, A::Error> {
        Err(A::Error::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
    }
}

struct OptionalBytesVisitor;

impl<'de> Visitor<'de> for OptionalBytesVisitor {
    type Value = Option<Zeroizing<Vec<u8>>>;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("a base64-encoded string, or null")
    }

    fn visit_none<E: SerdeError>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_unit<E: SerdeError>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_some<D: Deserializer<'de>>(self, value: D) -> Result<Self::Value, D::Error> {
        deserialize_bytes(value).map(Some)
    }

    fn visit_bool<E: SerdeError>(self, _value: bool) -> Result<Self::Value, E> {
        Err(E::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
    }

    fn visit_i64<E: SerdeError>(self, _value: i64) -> Result<Self::Value, E> {
        Err(E::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
    }

    fn visit_u64<E: SerdeError>(self, _value: u64) -> Result<Self::Value, E> {
        Err(E::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
    }

    fn visit_i128<E: SerdeError>(self, _value: i128) -> Result<Self::Value, E> {
        Err(E::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
    }

    fn visit_u128<E: SerdeError>(self, _value: u128) -> Result<Self::Value, E> {
        Err(E::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
    }

    fn visit_f64<E: SerdeError>(self, _value: f64) -> Result<Self::Value, E> {
        Err(E::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
    }

    fn visit_char<E: SerdeError>(self, _value: char) -> Result<Self::Value, E> {
        Err(E::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
    }

    fn visit_bytes<E: SerdeError>(self, _value: &[u8]) -> Result<Self::Value, E> {
        Err(E::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
    }

    fn visit_byte_buf<E: SerdeError>(self, value: Vec<u8>) -> Result<Self::Value, E> {
        let _value = Zeroizing::new(value);
        Err(E::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(
        self,
        _value: D,
    ) -> Result<Self::Value, D::Error> {
        Err(D::Error::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, _value: A) -> Result<Self::Value, A::Error> {
        Err(A::Error::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
    }

    fn visit_map<A: MapAccess<'de>>(self, _value: A) -> Result<Self::Value, A::Error> {
        Err(A::Error::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
    }

    fn visit_enum<A: EnumAccess<'de>>(self, _value: A) -> Result<Self::Value, A::Error> {
        Err(A::Error::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
    }

    fn visit_str<E: SerdeError>(self, _value: &str) -> Result<Self::Value, E> {
        Err(E::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
    }

    fn visit_string<E: SerdeError>(self, value: String) -> Result<Self::Value, E> {
        let _value = Zeroizing::new(value);
        Err(E::custom(CryptoError::PRIMITIVE_INVALID_PARAMETER))
    }
}

pub(crate) fn deserialize_bytes<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<Vec<u8>>, D::Error> {
    deserializer.deserialize_any(BytesVisitor)
}

pub(crate) fn deserialize_optional_bytes<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Zeroizing<Vec<u8>>>, D::Error> {
    deserializer.deserialize_option(OptionalBytesVisitor)
}

#[cfg(test)]
#[path = "deserialize_sensitive_tests.rs"]
mod tests;
