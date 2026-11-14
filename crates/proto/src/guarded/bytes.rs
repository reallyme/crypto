// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{bytes::Buf, DecodeError, FieldPayload, ProtoBytes, WirePayload};
use core::{
    fmt,
    ops::{Deref, DerefMut},
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error_types::CryptoError;

// Both policies use the same audited storage operations. Their distinct Rust
// types make the private-key export refusal part of generator configuration.
macro_rules! byte_owner {
    ($name:ident, $export:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Default)]
        pub struct $name(pub(super) Zeroizing<Vec<u8>>);

        impl $name {
            /// Borrow the retained bytes without creating another owner.
            #[must_use]
            pub fn as_slice(&self) -> &[u8] {
                self.0.as_slice()
            }

            /// Mutably borrow initialized bytes without exposing Vec growth.
            pub fn as_mut_slice(&mut self) -> &mut [u8] {
                self.0.as_mut_slice()
            }

            /// Copy into storage reserved under a clearing owner.
            pub fn try_from_slice(value: &[u8]) -> Result<Self, CryptoError> {
                let mut owner = Self::default();
                owner.try_reserve_exact(value.len())?;
                owner.0.extend_from_slice(value);
                Ok(owner)
            }

            /// Reserve without freeing an unwiped previous allocation.
            pub fn try_reserve_exact(&mut self, additional: usize) -> Result<(), CryptoError> {
                let required = self
                    .0
                    .len()
                    .checked_add(additional)
                    .ok_or(CryptoError::PRIMITIVE_INVALID_LENGTH)?;
                if required > self.0.capacity() {
                    let mut next = Zeroizing::new(Vec::new());
                    next.try_reserve_exact(required)
                        .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
                    next.extend_from_slice(&self.0);
                    core::mem::swap(&mut self.0, &mut next);
                    // The displaced guard wipes live bytes and spare capacity.
                }
                Ok(())
            }

            /// Append through the guarded, fallible growth path.
            pub fn extend_from_slice(&mut self, value: &[u8]) -> Result<(), CryptoError> {
                self.try_reserve_exact(value.len())?;
                self.0.extend_from_slice(value);
                Ok(())
            }

            /// Resize while wiping removed bytes before their length disappears.
            pub fn resize(&mut self, length: usize, value: u8) -> Result<(), CryptoError> {
                if let Some(additional) = length.checked_sub(self.0.len()) {
                    self.try_reserve_exact(additional)?;
                    self.0.resize(length, value);
                } else {
                    if let Some(tail) = self.0.get_mut(length..) {
                        tail.zeroize();
                    }
                    self.0.truncate(length);
                }
                Ok(())
            }

            /// Append one byte without an unguarded reallocation.
            pub fn push(&mut self, value: u8) -> Result<(), CryptoError> {
                self.try_reserve_exact(1)?;
                self.0.push(value);
                Ok(())
            }

            /// Wipe all retained storage and leave an empty value.
            pub fn clear(&mut self) {
                self.0.zeroize();
            }

            /// Transfer ownership while preserving cleanup in the destination.
            #[must_use]
            pub fn into_zeroizing(self) -> Zeroizing<Vec<u8>> {
                self.0
            }
        }

        impl From<Vec<u8>> for $name {
            fn from(value: Vec<u8>) -> Self {
                Self(Zeroizing::new(value))
            }
        }
        impl From<Zeroizing<Vec<u8>>> for $name {
            fn from(value: Zeroizing<Vec<u8>>) -> Self {
                Self(value)
            }
        }
        // Buffa requires Clone. Each clone has its own clearing allocation;
        // transport cloning never grants native private-key export authority.
        impl Clone for $name {
            fn clone(&self) -> Self {
                Self(self.0.clone())
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
        impl Deref for $name {
            type Target = [u8];
            fn deref(&self) -> &[u8] {
                self.as_slice()
            }
        }
        impl DerefMut for $name {
            fn deref_mut(&mut self) -> &mut [u8] {
                self.as_mut_slice()
            }
        }
        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                self.as_slice()
            }
        }
        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                bool::from(self.as_slice().ct_eq(other.as_slice()))
            }
        }
        impl Eq for $name {}
        impl PartialEq<Vec<u8>> for $name {
            fn eq(&self, other: &Vec<u8>) -> bool {
                bool::from(self.as_slice().ct_eq(other))
            }
        }
        impl<const N: usize> PartialEq<[u8; N]> for $name {
            fn eq(&self, other: &[u8; N]) -> bool {
                bool::from(self.as_slice().ct_eq(other))
            }
        }
        impl PartialEq<&[u8]> for $name {
            fn eq(&self, other: &&[u8]) -> bool {
                bool::from(self.as_slice().ct_eq(other))
            }
        }
        impl<const N: usize> PartialEq<&[u8; N]> for $name {
            fn eq(&self, other: &&[u8; N]) -> bool {
                bool::from(self.as_slice().ct_eq(other.as_slice()))
            }
        }
        impl Zeroize for $name {
            fn zeroize(&mut self) {
                self.clear();
            }
        }
        // Cleanup is implemented by the owned Zeroizing<Vec<u8>> field.
        impl ZeroizeOnDrop for $name {}
        impl ProtoBytes for $name {
            fn from_wire(payload: WirePayload<'_>) -> Result<Self, DecodeError> {
                Self::try_from_slice(payload.as_slice()).map_err(|_| DecodeError::MessageTooLarge)
            }
            fn decode_length_delimited(
                payload: &mut FieldPayload<impl Buf>,
            ) -> Result<Self, DecodeError> {
                super::read_payload(payload).map(Self)
            }
        }
        impl buffa::json_helpers::ProtoBytesJson for $name {
            fn serialize_json<S: serde::Serializer>(
                value: &[u8],
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                super::json::serialize_bytes(value, serializer, $export)
            }
            fn deserialize_json<'de, D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                crate::deserialize_sensitive::deserialize_bytes(deserializer).map(Self)
            }
        }
    };
}

byte_owner!(
    SecretBytes,
    true,
    "Wipe-owning protobuf bytes with explicit guarded JSON encoding."
);
byte_owner!(
    PrivateBytes,
    false,
    "Wipe-owning private-key bytes whose native JSON policy refuses export."
);
