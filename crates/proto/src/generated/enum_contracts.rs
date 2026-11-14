// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from canonical schema descriptors by scripts/generate_proto_enums.mjs.

pub use crate::error_types::CryptoErrorReason;

/// Schema-owned identity `reallyme.crypto.v1.P256KeyContainerFormat`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum P256KeyContainerFormat {
    /// `P256_KEY_CONTAINER_FORMAT_UNSPECIFIED`.
    #[default]
    P256_KEY_CONTAINER_FORMAT_UNSPECIFIED = 0,
    /// `P256_KEY_CONTAINER_FORMAT_PKCS8_DER`.
    P256_KEY_CONTAINER_FORMAT_PKCS8_DER = 100,
    /// `P256_KEY_CONTAINER_FORMAT_SEC1_DER`.
    P256_KEY_CONTAINER_FORMAT_SEC1_DER = 110,
    /// `P256_KEY_CONTAINER_FORMAT_SPKI_DER`.
    P256_KEY_CONTAINER_FORMAT_SPKI_DER = 120,
    /// `P256_KEY_CONTAINER_FORMAT_PKCS8_PEM`.
    P256_KEY_CONTAINER_FORMAT_PKCS8_PEM = 200,
    /// `P256_KEY_CONTAINER_FORMAT_SEC1_PEM`.
    P256_KEY_CONTAINER_FORMAT_SEC1_PEM = 210,
    /// `P256_KEY_CONTAINER_FORMAT_SPKI_PEM`.
    P256_KEY_CONTAINER_FORMAT_SPKI_PEM = 220,
    /// `P256_KEY_CONTAINER_FORMAT_PRIVATE_PEM`.
    P256_KEY_CONTAINER_FORMAT_PRIVATE_PEM = 230,
}
impl P256KeyContainerFormat {
    /// Idiomatic alias for [`Self::P256_KEY_CONTAINER_FORMAT_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::P256_KEY_CONTAINER_FORMAT_UNSPECIFIED;
    /// Idiomatic alias for [`Self::P256_KEY_CONTAINER_FORMAT_PKCS8_DER`].
    #[allow(non_upper_case_globals)]
    pub const Pkcs8Der: Self = Self::P256_KEY_CONTAINER_FORMAT_PKCS8_DER;
    /// Idiomatic alias for [`Self::P256_KEY_CONTAINER_FORMAT_SEC1_DER`].
    #[allow(non_upper_case_globals)]
    pub const Sec1Der: Self = Self::P256_KEY_CONTAINER_FORMAT_SEC1_DER;
    /// Idiomatic alias for [`Self::P256_KEY_CONTAINER_FORMAT_SPKI_DER`].
    #[allow(non_upper_case_globals)]
    pub const SpkiDer: Self = Self::P256_KEY_CONTAINER_FORMAT_SPKI_DER;
    /// Idiomatic alias for [`Self::P256_KEY_CONTAINER_FORMAT_PKCS8_PEM`].
    #[allow(non_upper_case_globals)]
    pub const Pkcs8Pem: Self = Self::P256_KEY_CONTAINER_FORMAT_PKCS8_PEM;
    /// Idiomatic alias for [`Self::P256_KEY_CONTAINER_FORMAT_SEC1_PEM`].
    #[allow(non_upper_case_globals)]
    pub const Sec1Pem: Self = Self::P256_KEY_CONTAINER_FORMAT_SEC1_PEM;
    /// Idiomatic alias for [`Self::P256_KEY_CONTAINER_FORMAT_SPKI_PEM`].
    #[allow(non_upper_case_globals)]
    pub const SpkiPem: Self = Self::P256_KEY_CONTAINER_FORMAT_SPKI_PEM;
    /// Idiomatic alias for [`Self::P256_KEY_CONTAINER_FORMAT_PRIVATE_PEM`].
    #[allow(non_upper_case_globals)]
    pub const PrivatePem: Self = Self::P256_KEY_CONTAINER_FORMAT_PRIVATE_PEM;
}
impl ::buffa::Enumeration for P256KeyContainerFormat {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::P256_KEY_CONTAINER_FORMAT_UNSPECIFIED),
            100 => Some(Self::P256_KEY_CONTAINER_FORMAT_PKCS8_DER),
            110 => Some(Self::P256_KEY_CONTAINER_FORMAT_SEC1_DER),
            120 => Some(Self::P256_KEY_CONTAINER_FORMAT_SPKI_DER),
            200 => Some(Self::P256_KEY_CONTAINER_FORMAT_PKCS8_PEM),
            210 => Some(Self::P256_KEY_CONTAINER_FORMAT_SEC1_PEM),
            220 => Some(Self::P256_KEY_CONTAINER_FORMAT_SPKI_PEM),
            230 => Some(Self::P256_KEY_CONTAINER_FORMAT_PRIVATE_PEM),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::P256_KEY_CONTAINER_FORMAT_UNSPECIFIED => "P256_KEY_CONTAINER_FORMAT_UNSPECIFIED",
            Self::P256_KEY_CONTAINER_FORMAT_PKCS8_DER => "P256_KEY_CONTAINER_FORMAT_PKCS8_DER",
            Self::P256_KEY_CONTAINER_FORMAT_SEC1_DER => "P256_KEY_CONTAINER_FORMAT_SEC1_DER",
            Self::P256_KEY_CONTAINER_FORMAT_SPKI_DER => "P256_KEY_CONTAINER_FORMAT_SPKI_DER",
            Self::P256_KEY_CONTAINER_FORMAT_PKCS8_PEM => "P256_KEY_CONTAINER_FORMAT_PKCS8_PEM",
            Self::P256_KEY_CONTAINER_FORMAT_SEC1_PEM => "P256_KEY_CONTAINER_FORMAT_SEC1_PEM",
            Self::P256_KEY_CONTAINER_FORMAT_SPKI_PEM => "P256_KEY_CONTAINER_FORMAT_SPKI_PEM",
            Self::P256_KEY_CONTAINER_FORMAT_PRIVATE_PEM => "P256_KEY_CONTAINER_FORMAT_PRIVATE_PEM",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "P256_KEY_CONTAINER_FORMAT_UNSPECIFIED" => {
                Some(Self::P256_KEY_CONTAINER_FORMAT_UNSPECIFIED)
            }
            "P256_KEY_CONTAINER_FORMAT_PKCS8_DER" => {
                Some(Self::P256_KEY_CONTAINER_FORMAT_PKCS8_DER)
            }
            "P256_KEY_CONTAINER_FORMAT_SEC1_DER" => Some(Self::P256_KEY_CONTAINER_FORMAT_SEC1_DER),
            "P256_KEY_CONTAINER_FORMAT_SPKI_DER" => Some(Self::P256_KEY_CONTAINER_FORMAT_SPKI_DER),
            "P256_KEY_CONTAINER_FORMAT_PKCS8_PEM" => {
                Some(Self::P256_KEY_CONTAINER_FORMAT_PKCS8_PEM)
            }
            "P256_KEY_CONTAINER_FORMAT_SEC1_PEM" => Some(Self::P256_KEY_CONTAINER_FORMAT_SEC1_PEM),
            "P256_KEY_CONTAINER_FORMAT_SPKI_PEM" => Some(Self::P256_KEY_CONTAINER_FORMAT_SPKI_PEM),
            "P256_KEY_CONTAINER_FORMAT_PRIVATE_PEM" => {
                Some(Self::P256_KEY_CONTAINER_FORMAT_PRIVATE_PEM)
            }
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::P256_KEY_CONTAINER_FORMAT_UNSPECIFIED,
            Self::P256_KEY_CONTAINER_FORMAT_PKCS8_DER,
            Self::P256_KEY_CONTAINER_FORMAT_SEC1_DER,
            Self::P256_KEY_CONTAINER_FORMAT_SPKI_DER,
            Self::P256_KEY_CONTAINER_FORMAT_PKCS8_PEM,
            Self::P256_KEY_CONTAINER_FORMAT_SEC1_PEM,
            Self::P256_KEY_CONTAINER_FORMAT_SPKI_PEM,
            Self::P256_KEY_CONTAINER_FORMAT_PRIVATE_PEM,
        ]
    }
}
impl ::zeroize::Zeroize for P256KeyContainerFormat {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for P256KeyContainerFormat {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for P256KeyContainerFormat {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for P256KeyContainerFormat {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.PublicKeyFormatOperation`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum PublicKeyFormatOperation {
    /// `PUBLIC_KEY_FORMAT_OPERATION_UNSPECIFIED`.
    #[default]
    PUBLIC_KEY_FORMAT_OPERATION_UNSPECIFIED = 0,
    /// `PUBLIC_KEY_FORMAT_OPERATION_ENCODE`.
    PUBLIC_KEY_FORMAT_OPERATION_ENCODE = 100,
    /// `PUBLIC_KEY_FORMAT_OPERATION_DECODE`.
    PUBLIC_KEY_FORMAT_OPERATION_DECODE = 110,
    /// `PUBLIC_KEY_FORMAT_OPERATION_COMPRESS`.
    PUBLIC_KEY_FORMAT_OPERATION_COMPRESS = 200,
    /// `PUBLIC_KEY_FORMAT_OPERATION_DECOMPRESS`.
    PUBLIC_KEY_FORMAT_OPERATION_DECOMPRESS = 210,
    /// `PUBLIC_KEY_FORMAT_OPERATION_ASSERT`.
    PUBLIC_KEY_FORMAT_OPERATION_ASSERT = 300,
    /// `PUBLIC_KEY_FORMAT_OPERATION_VALIDATE_IDENTITY`.
    PUBLIC_KEY_FORMAT_OPERATION_VALIDATE_IDENTITY = 310,
    /// `PUBLIC_KEY_FORMAT_OPERATION_BIP340_ENCODE`.
    PUBLIC_KEY_FORMAT_OPERATION_BIP340_ENCODE = 400,
    /// `PUBLIC_KEY_FORMAT_OPERATION_BIP340_DECODE`.
    PUBLIC_KEY_FORMAT_OPERATION_BIP340_DECODE = 410,
}
impl PublicKeyFormatOperation {
    /// Idiomatic alias for [`Self::PUBLIC_KEY_FORMAT_OPERATION_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::PUBLIC_KEY_FORMAT_OPERATION_UNSPECIFIED;
    /// Idiomatic alias for [`Self::PUBLIC_KEY_FORMAT_OPERATION_ENCODE`].
    #[allow(non_upper_case_globals)]
    pub const Encode: Self = Self::PUBLIC_KEY_FORMAT_OPERATION_ENCODE;
    /// Idiomatic alias for [`Self::PUBLIC_KEY_FORMAT_OPERATION_DECODE`].
    #[allow(non_upper_case_globals)]
    pub const Decode: Self = Self::PUBLIC_KEY_FORMAT_OPERATION_DECODE;
    /// Idiomatic alias for [`Self::PUBLIC_KEY_FORMAT_OPERATION_COMPRESS`].
    #[allow(non_upper_case_globals)]
    pub const Compress: Self = Self::PUBLIC_KEY_FORMAT_OPERATION_COMPRESS;
    /// Idiomatic alias for [`Self::PUBLIC_KEY_FORMAT_OPERATION_DECOMPRESS`].
    #[allow(non_upper_case_globals)]
    pub const Decompress: Self = Self::PUBLIC_KEY_FORMAT_OPERATION_DECOMPRESS;
    /// Idiomatic alias for [`Self::PUBLIC_KEY_FORMAT_OPERATION_ASSERT`].
    #[allow(non_upper_case_globals)]
    pub const Assert: Self = Self::PUBLIC_KEY_FORMAT_OPERATION_ASSERT;
    /// Idiomatic alias for [`Self::PUBLIC_KEY_FORMAT_OPERATION_VALIDATE_IDENTITY`].
    #[allow(non_upper_case_globals)]
    pub const ValidateIdentity: Self = Self::PUBLIC_KEY_FORMAT_OPERATION_VALIDATE_IDENTITY;
    /// Idiomatic alias for [`Self::PUBLIC_KEY_FORMAT_OPERATION_BIP340_ENCODE`].
    #[allow(non_upper_case_globals)]
    pub const Bip340Encode: Self = Self::PUBLIC_KEY_FORMAT_OPERATION_BIP340_ENCODE;
    /// Idiomatic alias for [`Self::PUBLIC_KEY_FORMAT_OPERATION_BIP340_DECODE`].
    #[allow(non_upper_case_globals)]
    pub const Bip340Decode: Self = Self::PUBLIC_KEY_FORMAT_OPERATION_BIP340_DECODE;
}
impl ::buffa::Enumeration for PublicKeyFormatOperation {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::PUBLIC_KEY_FORMAT_OPERATION_UNSPECIFIED),
            100 => Some(Self::PUBLIC_KEY_FORMAT_OPERATION_ENCODE),
            110 => Some(Self::PUBLIC_KEY_FORMAT_OPERATION_DECODE),
            200 => Some(Self::PUBLIC_KEY_FORMAT_OPERATION_COMPRESS),
            210 => Some(Self::PUBLIC_KEY_FORMAT_OPERATION_DECOMPRESS),
            300 => Some(Self::PUBLIC_KEY_FORMAT_OPERATION_ASSERT),
            310 => Some(Self::PUBLIC_KEY_FORMAT_OPERATION_VALIDATE_IDENTITY),
            400 => Some(Self::PUBLIC_KEY_FORMAT_OPERATION_BIP340_ENCODE),
            410 => Some(Self::PUBLIC_KEY_FORMAT_OPERATION_BIP340_DECODE),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::PUBLIC_KEY_FORMAT_OPERATION_UNSPECIFIED => {
                "PUBLIC_KEY_FORMAT_OPERATION_UNSPECIFIED"
            }
            Self::PUBLIC_KEY_FORMAT_OPERATION_ENCODE => "PUBLIC_KEY_FORMAT_OPERATION_ENCODE",
            Self::PUBLIC_KEY_FORMAT_OPERATION_DECODE => "PUBLIC_KEY_FORMAT_OPERATION_DECODE",
            Self::PUBLIC_KEY_FORMAT_OPERATION_COMPRESS => "PUBLIC_KEY_FORMAT_OPERATION_COMPRESS",
            Self::PUBLIC_KEY_FORMAT_OPERATION_DECOMPRESS => {
                "PUBLIC_KEY_FORMAT_OPERATION_DECOMPRESS"
            }
            Self::PUBLIC_KEY_FORMAT_OPERATION_ASSERT => "PUBLIC_KEY_FORMAT_OPERATION_ASSERT",
            Self::PUBLIC_KEY_FORMAT_OPERATION_VALIDATE_IDENTITY => {
                "PUBLIC_KEY_FORMAT_OPERATION_VALIDATE_IDENTITY"
            }
            Self::PUBLIC_KEY_FORMAT_OPERATION_BIP340_ENCODE => {
                "PUBLIC_KEY_FORMAT_OPERATION_BIP340_ENCODE"
            }
            Self::PUBLIC_KEY_FORMAT_OPERATION_BIP340_DECODE => {
                "PUBLIC_KEY_FORMAT_OPERATION_BIP340_DECODE"
            }
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "PUBLIC_KEY_FORMAT_OPERATION_UNSPECIFIED" => {
                Some(Self::PUBLIC_KEY_FORMAT_OPERATION_UNSPECIFIED)
            }
            "PUBLIC_KEY_FORMAT_OPERATION_ENCODE" => Some(Self::PUBLIC_KEY_FORMAT_OPERATION_ENCODE),
            "PUBLIC_KEY_FORMAT_OPERATION_DECODE" => Some(Self::PUBLIC_KEY_FORMAT_OPERATION_DECODE),
            "PUBLIC_KEY_FORMAT_OPERATION_COMPRESS" => {
                Some(Self::PUBLIC_KEY_FORMAT_OPERATION_COMPRESS)
            }
            "PUBLIC_KEY_FORMAT_OPERATION_DECOMPRESS" => {
                Some(Self::PUBLIC_KEY_FORMAT_OPERATION_DECOMPRESS)
            }
            "PUBLIC_KEY_FORMAT_OPERATION_ASSERT" => Some(Self::PUBLIC_KEY_FORMAT_OPERATION_ASSERT),
            "PUBLIC_KEY_FORMAT_OPERATION_VALIDATE_IDENTITY" => {
                Some(Self::PUBLIC_KEY_FORMAT_OPERATION_VALIDATE_IDENTITY)
            }
            "PUBLIC_KEY_FORMAT_OPERATION_BIP340_ENCODE" => {
                Some(Self::PUBLIC_KEY_FORMAT_OPERATION_BIP340_ENCODE)
            }
            "PUBLIC_KEY_FORMAT_OPERATION_BIP340_DECODE" => {
                Some(Self::PUBLIC_KEY_FORMAT_OPERATION_BIP340_DECODE)
            }
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::PUBLIC_KEY_FORMAT_OPERATION_UNSPECIFIED,
            Self::PUBLIC_KEY_FORMAT_OPERATION_ENCODE,
            Self::PUBLIC_KEY_FORMAT_OPERATION_DECODE,
            Self::PUBLIC_KEY_FORMAT_OPERATION_COMPRESS,
            Self::PUBLIC_KEY_FORMAT_OPERATION_DECOMPRESS,
            Self::PUBLIC_KEY_FORMAT_OPERATION_ASSERT,
            Self::PUBLIC_KEY_FORMAT_OPERATION_VALIDATE_IDENTITY,
            Self::PUBLIC_KEY_FORMAT_OPERATION_BIP340_ENCODE,
            Self::PUBLIC_KEY_FORMAT_OPERATION_BIP340_DECODE,
        ]
    }
}
impl ::zeroize::Zeroize for PublicKeyFormatOperation {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for PublicKeyFormatOperation {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for PublicKeyFormatOperation {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for PublicKeyFormatOperation {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.Argon2PlatformClass`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum Argon2PlatformClass {
    /// `ARGON2_PLATFORM_CLASS_UNSPECIFIED`.
    #[default]
    ARGON2_PLATFORM_CLASS_UNSPECIFIED = 0,
    /// `ARGON2_PLATFORM_CLASS_MOBILE_MODERN`.
    ARGON2_PLATFORM_CLASS_MOBILE_MODERN = 100,
    /// `ARGON2_PLATFORM_CLASS_DESKTOP_MODERN`.
    ARGON2_PLATFORM_CLASS_DESKTOP_MODERN = 200,
}
impl Argon2PlatformClass {
    /// Idiomatic alias for [`Self::ARGON2_PLATFORM_CLASS_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::ARGON2_PLATFORM_CLASS_UNSPECIFIED;
    /// Idiomatic alias for [`Self::ARGON2_PLATFORM_CLASS_MOBILE_MODERN`].
    #[allow(non_upper_case_globals)]
    pub const MobileModern: Self = Self::ARGON2_PLATFORM_CLASS_MOBILE_MODERN;
    /// Idiomatic alias for [`Self::ARGON2_PLATFORM_CLASS_DESKTOP_MODERN`].
    #[allow(non_upper_case_globals)]
    pub const DesktopModern: Self = Self::ARGON2_PLATFORM_CLASS_DESKTOP_MODERN;
}
impl ::buffa::Enumeration for Argon2PlatformClass {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::ARGON2_PLATFORM_CLASS_UNSPECIFIED),
            100 => Some(Self::ARGON2_PLATFORM_CLASS_MOBILE_MODERN),
            200 => Some(Self::ARGON2_PLATFORM_CLASS_DESKTOP_MODERN),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::ARGON2_PLATFORM_CLASS_UNSPECIFIED => "ARGON2_PLATFORM_CLASS_UNSPECIFIED",
            Self::ARGON2_PLATFORM_CLASS_MOBILE_MODERN => "ARGON2_PLATFORM_CLASS_MOBILE_MODERN",
            Self::ARGON2_PLATFORM_CLASS_DESKTOP_MODERN => "ARGON2_PLATFORM_CLASS_DESKTOP_MODERN",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "ARGON2_PLATFORM_CLASS_UNSPECIFIED" => Some(Self::ARGON2_PLATFORM_CLASS_UNSPECIFIED),
            "ARGON2_PLATFORM_CLASS_MOBILE_MODERN" => {
                Some(Self::ARGON2_PLATFORM_CLASS_MOBILE_MODERN)
            }
            "ARGON2_PLATFORM_CLASS_DESKTOP_MODERN" => {
                Some(Self::ARGON2_PLATFORM_CLASS_DESKTOP_MODERN)
            }
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::ARGON2_PLATFORM_CLASS_UNSPECIFIED,
            Self::ARGON2_PLATFORM_CLASS_MOBILE_MODERN,
            Self::ARGON2_PLATFORM_CLASS_DESKTOP_MODERN,
        ]
    }
}
impl ::zeroize::Zeroize for Argon2PlatformClass {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for Argon2PlatformClass {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for Argon2PlatformClass {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for Argon2PlatformClass {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.HkdfDomainKeyPurpose`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum HkdfDomainKeyPurpose {
    /// `HKDF_DOMAIN_KEY_PURPOSE_UNSPECIFIED`.
    #[default]
    HKDF_DOMAIN_KEY_PURPOSE_UNSPECIFIED = 0,
    /// `HKDF_DOMAIN_KEY_PURPOSE_AEAD_CONTENT_KEY`.
    HKDF_DOMAIN_KEY_PURPOSE_AEAD_CONTENT_KEY = 100,
    /// `HKDF_DOMAIN_KEY_PURPOSE_AEAD_WRAP_KEY`.
    HKDF_DOMAIN_KEY_PURPOSE_AEAD_WRAP_KEY = 200,
    /// `HKDF_DOMAIN_KEY_PURPOSE_AUTH_PROOF_KEY`.
    HKDF_DOMAIN_KEY_PURPOSE_AUTH_PROOF_KEY = 300,
    /// `HKDF_DOMAIN_KEY_PURPOSE_MANIFEST_COMMITMENT_KEY`.
    HKDF_DOMAIN_KEY_PURPOSE_MANIFEST_COMMITMENT_KEY = 400,
}
impl HkdfDomainKeyPurpose {
    /// Idiomatic alias for [`Self::HKDF_DOMAIN_KEY_PURPOSE_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::HKDF_DOMAIN_KEY_PURPOSE_UNSPECIFIED;
    /// Idiomatic alias for [`Self::HKDF_DOMAIN_KEY_PURPOSE_AEAD_CONTENT_KEY`].
    #[allow(non_upper_case_globals)]
    pub const AeadContentKey: Self = Self::HKDF_DOMAIN_KEY_PURPOSE_AEAD_CONTENT_KEY;
    /// Idiomatic alias for [`Self::HKDF_DOMAIN_KEY_PURPOSE_AEAD_WRAP_KEY`].
    #[allow(non_upper_case_globals)]
    pub const AeadWrapKey: Self = Self::HKDF_DOMAIN_KEY_PURPOSE_AEAD_WRAP_KEY;
    /// Idiomatic alias for [`Self::HKDF_DOMAIN_KEY_PURPOSE_AUTH_PROOF_KEY`].
    #[allow(non_upper_case_globals)]
    pub const AuthProofKey: Self = Self::HKDF_DOMAIN_KEY_PURPOSE_AUTH_PROOF_KEY;
    /// Idiomatic alias for [`Self::HKDF_DOMAIN_KEY_PURPOSE_MANIFEST_COMMITMENT_KEY`].
    #[allow(non_upper_case_globals)]
    pub const ManifestCommitmentKey: Self = Self::HKDF_DOMAIN_KEY_PURPOSE_MANIFEST_COMMITMENT_KEY;
}
impl ::buffa::Enumeration for HkdfDomainKeyPurpose {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::HKDF_DOMAIN_KEY_PURPOSE_UNSPECIFIED),
            100 => Some(Self::HKDF_DOMAIN_KEY_PURPOSE_AEAD_CONTENT_KEY),
            200 => Some(Self::HKDF_DOMAIN_KEY_PURPOSE_AEAD_WRAP_KEY),
            300 => Some(Self::HKDF_DOMAIN_KEY_PURPOSE_AUTH_PROOF_KEY),
            400 => Some(Self::HKDF_DOMAIN_KEY_PURPOSE_MANIFEST_COMMITMENT_KEY),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::HKDF_DOMAIN_KEY_PURPOSE_UNSPECIFIED => "HKDF_DOMAIN_KEY_PURPOSE_UNSPECIFIED",
            Self::HKDF_DOMAIN_KEY_PURPOSE_AEAD_CONTENT_KEY => {
                "HKDF_DOMAIN_KEY_PURPOSE_AEAD_CONTENT_KEY"
            }
            Self::HKDF_DOMAIN_KEY_PURPOSE_AEAD_WRAP_KEY => "HKDF_DOMAIN_KEY_PURPOSE_AEAD_WRAP_KEY",
            Self::HKDF_DOMAIN_KEY_PURPOSE_AUTH_PROOF_KEY => {
                "HKDF_DOMAIN_KEY_PURPOSE_AUTH_PROOF_KEY"
            }
            Self::HKDF_DOMAIN_KEY_PURPOSE_MANIFEST_COMMITMENT_KEY => {
                "HKDF_DOMAIN_KEY_PURPOSE_MANIFEST_COMMITMENT_KEY"
            }
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "HKDF_DOMAIN_KEY_PURPOSE_UNSPECIFIED" => {
                Some(Self::HKDF_DOMAIN_KEY_PURPOSE_UNSPECIFIED)
            }
            "HKDF_DOMAIN_KEY_PURPOSE_AEAD_CONTENT_KEY" => {
                Some(Self::HKDF_DOMAIN_KEY_PURPOSE_AEAD_CONTENT_KEY)
            }
            "HKDF_DOMAIN_KEY_PURPOSE_AEAD_WRAP_KEY" => {
                Some(Self::HKDF_DOMAIN_KEY_PURPOSE_AEAD_WRAP_KEY)
            }
            "HKDF_DOMAIN_KEY_PURPOSE_AUTH_PROOF_KEY" => {
                Some(Self::HKDF_DOMAIN_KEY_PURPOSE_AUTH_PROOF_KEY)
            }
            "HKDF_DOMAIN_KEY_PURPOSE_MANIFEST_COMMITMENT_KEY" => {
                Some(Self::HKDF_DOMAIN_KEY_PURPOSE_MANIFEST_COMMITMENT_KEY)
            }
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::HKDF_DOMAIN_KEY_PURPOSE_UNSPECIFIED,
            Self::HKDF_DOMAIN_KEY_PURPOSE_AEAD_CONTENT_KEY,
            Self::HKDF_DOMAIN_KEY_PURPOSE_AEAD_WRAP_KEY,
            Self::HKDF_DOMAIN_KEY_PURPOSE_AUTH_PROOF_KEY,
            Self::HKDF_DOMAIN_KEY_PURPOSE_MANIFEST_COMMITMENT_KEY,
        ]
    }
}
impl ::zeroize::Zeroize for HkdfDomainKeyPurpose {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for HkdfDomainKeyPurpose {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for HkdfDomainKeyPurpose {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for HkdfDomainKeyPurpose {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.EcdsaEncoding`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum EcdsaEncoding {
    /// `ECDSA_ENCODING_UNSPECIFIED`.
    #[default]
    ECDSA_ENCODING_UNSPECIFIED = 0,
    /// `ECDSA_ENCODING_DER`.
    ECDSA_ENCODING_DER = 100,
    /// `ECDSA_ENCODING_FIXED_WIDTH`.
    ECDSA_ENCODING_FIXED_WIDTH = 110,
}
impl EcdsaEncoding {
    /// Idiomatic alias for [`Self::ECDSA_ENCODING_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::ECDSA_ENCODING_UNSPECIFIED;
    /// Idiomatic alias for [`Self::ECDSA_ENCODING_DER`].
    #[allow(non_upper_case_globals)]
    pub const Der: Self = Self::ECDSA_ENCODING_DER;
    /// Idiomatic alias for [`Self::ECDSA_ENCODING_FIXED_WIDTH`].
    #[allow(non_upper_case_globals)]
    pub const FixedWidth: Self = Self::ECDSA_ENCODING_FIXED_WIDTH;
}
impl ::buffa::Enumeration for EcdsaEncoding {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::ECDSA_ENCODING_UNSPECIFIED),
            100 => Some(Self::ECDSA_ENCODING_DER),
            110 => Some(Self::ECDSA_ENCODING_FIXED_WIDTH),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::ECDSA_ENCODING_UNSPECIFIED => "ECDSA_ENCODING_UNSPECIFIED",
            Self::ECDSA_ENCODING_DER => "ECDSA_ENCODING_DER",
            Self::ECDSA_ENCODING_FIXED_WIDTH => "ECDSA_ENCODING_FIXED_WIDTH",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "ECDSA_ENCODING_UNSPECIFIED" => Some(Self::ECDSA_ENCODING_UNSPECIFIED),
            "ECDSA_ENCODING_DER" => Some(Self::ECDSA_ENCODING_DER),
            "ECDSA_ENCODING_FIXED_WIDTH" => Some(Self::ECDSA_ENCODING_FIXED_WIDTH),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::ECDSA_ENCODING_UNSPECIFIED,
            Self::ECDSA_ENCODING_DER,
            Self::ECDSA_ENCODING_FIXED_WIDTH,
        ]
    }
}
impl ::zeroize::Zeroize for EcdsaEncoding {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for EcdsaEncoding {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for EcdsaEncoding {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for EcdsaEncoding {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.Ed448Operation`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum Ed448Operation {
    /// `ED448_OPERATION_UNSPECIFIED`.
    #[default]
    ED448_OPERATION_UNSPECIFIED = 0,
    /// `ED448_OPERATION_VERIFY`.
    ED448_OPERATION_VERIFY = 100,
    /// `ED448_OPERATION_OPAQUE_SIGN`.
    ED448_OPERATION_OPAQUE_SIGN = 200,
    /// `ED448_OPERATION_SOFTWARE_KEY_GENERATION`.
    ED448_OPERATION_SOFTWARE_KEY_GENERATION = 300,
    /// `ED448_OPERATION_SOFTWARE_KEY_IMPORT`.
    ED448_OPERATION_SOFTWARE_KEY_IMPORT = 310,
}
impl Ed448Operation {
    /// Idiomatic alias for [`Self::ED448_OPERATION_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::ED448_OPERATION_UNSPECIFIED;
    /// Idiomatic alias for [`Self::ED448_OPERATION_VERIFY`].
    #[allow(non_upper_case_globals)]
    pub const Verify: Self = Self::ED448_OPERATION_VERIFY;
    /// Idiomatic alias for [`Self::ED448_OPERATION_OPAQUE_SIGN`].
    #[allow(non_upper_case_globals)]
    pub const OpaqueSign: Self = Self::ED448_OPERATION_OPAQUE_SIGN;
    /// Idiomatic alias for [`Self::ED448_OPERATION_SOFTWARE_KEY_GENERATION`].
    #[allow(non_upper_case_globals)]
    pub const SoftwareKeyGeneration: Self = Self::ED448_OPERATION_SOFTWARE_KEY_GENERATION;
    /// Idiomatic alias for [`Self::ED448_OPERATION_SOFTWARE_KEY_IMPORT`].
    #[allow(non_upper_case_globals)]
    pub const SoftwareKeyImport: Self = Self::ED448_OPERATION_SOFTWARE_KEY_IMPORT;
}
impl ::buffa::Enumeration for Ed448Operation {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::ED448_OPERATION_UNSPECIFIED),
            100 => Some(Self::ED448_OPERATION_VERIFY),
            200 => Some(Self::ED448_OPERATION_OPAQUE_SIGN),
            300 => Some(Self::ED448_OPERATION_SOFTWARE_KEY_GENERATION),
            310 => Some(Self::ED448_OPERATION_SOFTWARE_KEY_IMPORT),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::ED448_OPERATION_UNSPECIFIED => "ED448_OPERATION_UNSPECIFIED",
            Self::ED448_OPERATION_VERIFY => "ED448_OPERATION_VERIFY",
            Self::ED448_OPERATION_OPAQUE_SIGN => "ED448_OPERATION_OPAQUE_SIGN",
            Self::ED448_OPERATION_SOFTWARE_KEY_GENERATION => {
                "ED448_OPERATION_SOFTWARE_KEY_GENERATION"
            }
            Self::ED448_OPERATION_SOFTWARE_KEY_IMPORT => "ED448_OPERATION_SOFTWARE_KEY_IMPORT",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "ED448_OPERATION_UNSPECIFIED" => Some(Self::ED448_OPERATION_UNSPECIFIED),
            "ED448_OPERATION_VERIFY" => Some(Self::ED448_OPERATION_VERIFY),
            "ED448_OPERATION_OPAQUE_SIGN" => Some(Self::ED448_OPERATION_OPAQUE_SIGN),
            "ED448_OPERATION_SOFTWARE_KEY_GENERATION" => {
                Some(Self::ED448_OPERATION_SOFTWARE_KEY_GENERATION)
            }
            "ED448_OPERATION_SOFTWARE_KEY_IMPORT" => {
                Some(Self::ED448_OPERATION_SOFTWARE_KEY_IMPORT)
            }
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::ED448_OPERATION_UNSPECIFIED,
            Self::ED448_OPERATION_VERIFY,
            Self::ED448_OPERATION_OPAQUE_SIGN,
            Self::ED448_OPERATION_SOFTWARE_KEY_GENERATION,
            Self::ED448_OPERATION_SOFTWARE_KEY_IMPORT,
        ]
    }
}
impl ::zeroize::Zeroize for Ed448Operation {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for Ed448Operation {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for Ed448Operation {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for Ed448Operation {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.NativeKeySource`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum NativeKeySource {
    /// `NATIVE_KEY_SOURCE_UNSPECIFIED`.
    #[default]
    NATIVE_KEY_SOURCE_UNSPECIFIED = 0,
    /// `NATIVE_KEY_SOURCE_SOFTWARE_OWNER`.
    NATIVE_KEY_SOURCE_SOFTWARE_OWNER = 100,
    /// `NATIVE_KEY_SOURCE_OPAQUE_SIGNER`.
    NATIVE_KEY_SOURCE_OPAQUE_SIGNER = 200,
}
impl NativeKeySource {
    /// Idiomatic alias for [`Self::NATIVE_KEY_SOURCE_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::NATIVE_KEY_SOURCE_UNSPECIFIED;
    /// Idiomatic alias for [`Self::NATIVE_KEY_SOURCE_SOFTWARE_OWNER`].
    #[allow(non_upper_case_globals)]
    pub const SoftwareOwner: Self = Self::NATIVE_KEY_SOURCE_SOFTWARE_OWNER;
    /// Idiomatic alias for [`Self::NATIVE_KEY_SOURCE_OPAQUE_SIGNER`].
    #[allow(non_upper_case_globals)]
    pub const OpaqueSigner: Self = Self::NATIVE_KEY_SOURCE_OPAQUE_SIGNER;
}
impl ::buffa::Enumeration for NativeKeySource {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::NATIVE_KEY_SOURCE_UNSPECIFIED),
            100 => Some(Self::NATIVE_KEY_SOURCE_SOFTWARE_OWNER),
            200 => Some(Self::NATIVE_KEY_SOURCE_OPAQUE_SIGNER),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::NATIVE_KEY_SOURCE_UNSPECIFIED => "NATIVE_KEY_SOURCE_UNSPECIFIED",
            Self::NATIVE_KEY_SOURCE_SOFTWARE_OWNER => "NATIVE_KEY_SOURCE_SOFTWARE_OWNER",
            Self::NATIVE_KEY_SOURCE_OPAQUE_SIGNER => "NATIVE_KEY_SOURCE_OPAQUE_SIGNER",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "NATIVE_KEY_SOURCE_UNSPECIFIED" => Some(Self::NATIVE_KEY_SOURCE_UNSPECIFIED),
            "NATIVE_KEY_SOURCE_SOFTWARE_OWNER" => Some(Self::NATIVE_KEY_SOURCE_SOFTWARE_OWNER),
            "NATIVE_KEY_SOURCE_OPAQUE_SIGNER" => Some(Self::NATIVE_KEY_SOURCE_OPAQUE_SIGNER),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::NATIVE_KEY_SOURCE_UNSPECIFIED,
            Self::NATIVE_KEY_SOURCE_SOFTWARE_OWNER,
            Self::NATIVE_KEY_SOURCE_OPAQUE_SIGNER,
        ]
    }
}
impl ::zeroize::Zeroize for NativeKeySource {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for NativeKeySource {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for NativeKeySource {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for NativeKeySource {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.HpkeComponentSupport`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum HpkeComponentSupport {
    /// `HPKE_COMPONENT_SUPPORT_UNSPECIFIED`.
    #[default]
    HPKE_COMPONENT_SUPPORT_UNSPECIFIED = 0,
    /// `HPKE_COMPONENT_SUPPORT_EXECUTABLE`.
    HPKE_COMPONENT_SUPPORT_EXECUTABLE = 100,
    /// `HPKE_COMPONENT_SUPPORT_REGISTERED_UNAVAILABLE`.
    HPKE_COMPONENT_SUPPORT_REGISTERED_UNAVAILABLE = 200,
}
impl HpkeComponentSupport {
    /// Idiomatic alias for [`Self::HPKE_COMPONENT_SUPPORT_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::HPKE_COMPONENT_SUPPORT_UNSPECIFIED;
    /// Idiomatic alias for [`Self::HPKE_COMPONENT_SUPPORT_EXECUTABLE`].
    #[allow(non_upper_case_globals)]
    pub const Executable: Self = Self::HPKE_COMPONENT_SUPPORT_EXECUTABLE;
    /// Idiomatic alias for [`Self::HPKE_COMPONENT_SUPPORT_REGISTERED_UNAVAILABLE`].
    #[allow(non_upper_case_globals)]
    pub const RegisteredUnavailable: Self = Self::HPKE_COMPONENT_SUPPORT_REGISTERED_UNAVAILABLE;
}
impl ::buffa::Enumeration for HpkeComponentSupport {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::HPKE_COMPONENT_SUPPORT_UNSPECIFIED),
            100 => Some(Self::HPKE_COMPONENT_SUPPORT_EXECUTABLE),
            200 => Some(Self::HPKE_COMPONENT_SUPPORT_REGISTERED_UNAVAILABLE),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::HPKE_COMPONENT_SUPPORT_UNSPECIFIED => "HPKE_COMPONENT_SUPPORT_UNSPECIFIED",
            Self::HPKE_COMPONENT_SUPPORT_EXECUTABLE => "HPKE_COMPONENT_SUPPORT_EXECUTABLE",
            Self::HPKE_COMPONENT_SUPPORT_REGISTERED_UNAVAILABLE => {
                "HPKE_COMPONENT_SUPPORT_REGISTERED_UNAVAILABLE"
            }
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "HPKE_COMPONENT_SUPPORT_UNSPECIFIED" => Some(Self::HPKE_COMPONENT_SUPPORT_UNSPECIFIED),
            "HPKE_COMPONENT_SUPPORT_EXECUTABLE" => Some(Self::HPKE_COMPONENT_SUPPORT_EXECUTABLE),
            "HPKE_COMPONENT_SUPPORT_REGISTERED_UNAVAILABLE" => {
                Some(Self::HPKE_COMPONENT_SUPPORT_REGISTERED_UNAVAILABLE)
            }
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::HPKE_COMPONENT_SUPPORT_UNSPECIFIED,
            Self::HPKE_COMPONENT_SUPPORT_EXECUTABLE,
            Self::HPKE_COMPONENT_SUPPORT_REGISTERED_UNAVAILABLE,
        ]
    }
}
impl ::zeroize::Zeroize for HpkeComponentSupport {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for HpkeComponentSupport {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for HpkeComponentSupport {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for HpkeComponentSupport {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.ProviderOperation`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum ProviderOperation {
    /// `PROVIDER_OPERATION_UNSPECIFIED`.
    #[default]
    PROVIDER_OPERATION_UNSPECIFIED = 0,
    /// `PROVIDER_OPERATION_GENERATE_KEY_PAIR`.
    PROVIDER_OPERATION_GENERATE_KEY_PAIR = 100,
    /// `PROVIDER_OPERATION_DERIVE_KEY_PAIR`.
    PROVIDER_OPERATION_DERIVE_KEY_PAIR = 110,
    /// `PROVIDER_OPERATION_SIGN`.
    PROVIDER_OPERATION_SIGN = 200,
    /// `PROVIDER_OPERATION_VERIFY`.
    PROVIDER_OPERATION_VERIFY = 210,
    /// `PROVIDER_OPERATION_DERIVE_SHARED_SECRET`.
    PROVIDER_OPERATION_DERIVE_SHARED_SECRET = 300,
    /// `PROVIDER_OPERATION_KEM_ENCAPSULATE`.
    PROVIDER_OPERATION_KEM_ENCAPSULATE = 400,
    /// `PROVIDER_OPERATION_KEM_DECAPSULATE`.
    PROVIDER_OPERATION_KEM_DECAPSULATE = 410,
}
impl ProviderOperation {
    /// Idiomatic alias for [`Self::PROVIDER_OPERATION_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::PROVIDER_OPERATION_UNSPECIFIED;
    /// Idiomatic alias for [`Self::PROVIDER_OPERATION_GENERATE_KEY_PAIR`].
    #[allow(non_upper_case_globals)]
    pub const GenerateKeyPair: Self = Self::PROVIDER_OPERATION_GENERATE_KEY_PAIR;
    /// Idiomatic alias for [`Self::PROVIDER_OPERATION_DERIVE_KEY_PAIR`].
    #[allow(non_upper_case_globals)]
    pub const DeriveKeyPair: Self = Self::PROVIDER_OPERATION_DERIVE_KEY_PAIR;
    /// Idiomatic alias for [`Self::PROVIDER_OPERATION_SIGN`].
    #[allow(non_upper_case_globals)]
    pub const Sign: Self = Self::PROVIDER_OPERATION_SIGN;
    /// Idiomatic alias for [`Self::PROVIDER_OPERATION_VERIFY`].
    #[allow(non_upper_case_globals)]
    pub const Verify: Self = Self::PROVIDER_OPERATION_VERIFY;
    /// Idiomatic alias for [`Self::PROVIDER_OPERATION_DERIVE_SHARED_SECRET`].
    #[allow(non_upper_case_globals)]
    pub const DeriveSharedSecret: Self = Self::PROVIDER_OPERATION_DERIVE_SHARED_SECRET;
    /// Idiomatic alias for [`Self::PROVIDER_OPERATION_KEM_ENCAPSULATE`].
    #[allow(non_upper_case_globals)]
    pub const KemEncapsulate: Self = Self::PROVIDER_OPERATION_KEM_ENCAPSULATE;
    /// Idiomatic alias for [`Self::PROVIDER_OPERATION_KEM_DECAPSULATE`].
    #[allow(non_upper_case_globals)]
    pub const KemDecapsulate: Self = Self::PROVIDER_OPERATION_KEM_DECAPSULATE;
}
impl ::buffa::Enumeration for ProviderOperation {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::PROVIDER_OPERATION_UNSPECIFIED),
            100 => Some(Self::PROVIDER_OPERATION_GENERATE_KEY_PAIR),
            110 => Some(Self::PROVIDER_OPERATION_DERIVE_KEY_PAIR),
            200 => Some(Self::PROVIDER_OPERATION_SIGN),
            210 => Some(Self::PROVIDER_OPERATION_VERIFY),
            300 => Some(Self::PROVIDER_OPERATION_DERIVE_SHARED_SECRET),
            400 => Some(Self::PROVIDER_OPERATION_KEM_ENCAPSULATE),
            410 => Some(Self::PROVIDER_OPERATION_KEM_DECAPSULATE),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::PROVIDER_OPERATION_UNSPECIFIED => "PROVIDER_OPERATION_UNSPECIFIED",
            Self::PROVIDER_OPERATION_GENERATE_KEY_PAIR => "PROVIDER_OPERATION_GENERATE_KEY_PAIR",
            Self::PROVIDER_OPERATION_DERIVE_KEY_PAIR => "PROVIDER_OPERATION_DERIVE_KEY_PAIR",
            Self::PROVIDER_OPERATION_SIGN => "PROVIDER_OPERATION_SIGN",
            Self::PROVIDER_OPERATION_VERIFY => "PROVIDER_OPERATION_VERIFY",
            Self::PROVIDER_OPERATION_DERIVE_SHARED_SECRET => {
                "PROVIDER_OPERATION_DERIVE_SHARED_SECRET"
            }
            Self::PROVIDER_OPERATION_KEM_ENCAPSULATE => "PROVIDER_OPERATION_KEM_ENCAPSULATE",
            Self::PROVIDER_OPERATION_KEM_DECAPSULATE => "PROVIDER_OPERATION_KEM_DECAPSULATE",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "PROVIDER_OPERATION_UNSPECIFIED" => Some(Self::PROVIDER_OPERATION_UNSPECIFIED),
            "PROVIDER_OPERATION_GENERATE_KEY_PAIR" => {
                Some(Self::PROVIDER_OPERATION_GENERATE_KEY_PAIR)
            }
            "PROVIDER_OPERATION_DERIVE_KEY_PAIR" => Some(Self::PROVIDER_OPERATION_DERIVE_KEY_PAIR),
            "PROVIDER_OPERATION_SIGN" => Some(Self::PROVIDER_OPERATION_SIGN),
            "PROVIDER_OPERATION_VERIFY" => Some(Self::PROVIDER_OPERATION_VERIFY),
            "PROVIDER_OPERATION_DERIVE_SHARED_SECRET" => {
                Some(Self::PROVIDER_OPERATION_DERIVE_SHARED_SECRET)
            }
            "PROVIDER_OPERATION_KEM_ENCAPSULATE" => Some(Self::PROVIDER_OPERATION_KEM_ENCAPSULATE),
            "PROVIDER_OPERATION_KEM_DECAPSULATE" => Some(Self::PROVIDER_OPERATION_KEM_DECAPSULATE),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::PROVIDER_OPERATION_UNSPECIFIED,
            Self::PROVIDER_OPERATION_GENERATE_KEY_PAIR,
            Self::PROVIDER_OPERATION_DERIVE_KEY_PAIR,
            Self::PROVIDER_OPERATION_SIGN,
            Self::PROVIDER_OPERATION_VERIFY,
            Self::PROVIDER_OPERATION_DERIVE_SHARED_SECRET,
            Self::PROVIDER_OPERATION_KEM_ENCAPSULATE,
            Self::PROVIDER_OPERATION_KEM_DECAPSULATE,
        ]
    }
}
impl ::zeroize::Zeroize for ProviderOperation {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for ProviderOperation {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for ProviderOperation {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for ProviderOperation {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.ProviderKind`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum ProviderKind {
    /// `PROVIDER_KIND_UNSPECIFIED`.
    #[default]
    PROVIDER_KIND_UNSPECIFIED = 0,
    /// `PROVIDER_KIND_PACKAGE_OWNED_RUST`.
    PROVIDER_KIND_PACKAGE_OWNED_RUST = 100,
}
impl ProviderKind {
    /// Idiomatic alias for [`Self::PROVIDER_KIND_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::PROVIDER_KIND_UNSPECIFIED;
    /// Idiomatic alias for [`Self::PROVIDER_KIND_PACKAGE_OWNED_RUST`].
    #[allow(non_upper_case_globals)]
    pub const PackageOwnedRust: Self = Self::PROVIDER_KIND_PACKAGE_OWNED_RUST;
}
impl ::buffa::Enumeration for ProviderKind {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::PROVIDER_KIND_UNSPECIFIED),
            100 => Some(Self::PROVIDER_KIND_PACKAGE_OWNED_RUST),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::PROVIDER_KIND_UNSPECIFIED => "PROVIDER_KIND_UNSPECIFIED",
            Self::PROVIDER_KIND_PACKAGE_OWNED_RUST => "PROVIDER_KIND_PACKAGE_OWNED_RUST",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "PROVIDER_KIND_UNSPECIFIED" => Some(Self::PROVIDER_KIND_UNSPECIFIED),
            "PROVIDER_KIND_PACKAGE_OWNED_RUST" => Some(Self::PROVIDER_KIND_PACKAGE_OWNED_RUST),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::PROVIDER_KIND_UNSPECIFIED,
            Self::PROVIDER_KIND_PACKAGE_OWNED_RUST,
        ]
    }
}
impl ::zeroize::Zeroize for ProviderKind {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for ProviderKind {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for ProviderKind {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for ProviderKind {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.ProviderLane`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum ProviderLane {
    /// `PROVIDER_LANE_UNSPECIFIED`.
    #[default]
    PROVIDER_LANE_UNSPECIFIED = 0,
    /// `PROVIDER_LANE_NATIVE`.
    PROVIDER_LANE_NATIVE = 100,
    /// `PROVIDER_LANE_WASM`.
    PROVIDER_LANE_WASM = 200,
}
impl ProviderLane {
    /// Idiomatic alias for [`Self::PROVIDER_LANE_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::PROVIDER_LANE_UNSPECIFIED;
    /// Idiomatic alias for [`Self::PROVIDER_LANE_NATIVE`].
    #[allow(non_upper_case_globals)]
    pub const Native: Self = Self::PROVIDER_LANE_NATIVE;
    /// Idiomatic alias for [`Self::PROVIDER_LANE_WASM`].
    #[allow(non_upper_case_globals)]
    pub const Wasm: Self = Self::PROVIDER_LANE_WASM;
}
impl ::buffa::Enumeration for ProviderLane {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::PROVIDER_LANE_UNSPECIFIED),
            100 => Some(Self::PROVIDER_LANE_NATIVE),
            200 => Some(Self::PROVIDER_LANE_WASM),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::PROVIDER_LANE_UNSPECIFIED => "PROVIDER_LANE_UNSPECIFIED",
            Self::PROVIDER_LANE_NATIVE => "PROVIDER_LANE_NATIVE",
            Self::PROVIDER_LANE_WASM => "PROVIDER_LANE_WASM",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "PROVIDER_LANE_UNSPECIFIED" => Some(Self::PROVIDER_LANE_UNSPECIFIED),
            "PROVIDER_LANE_NATIVE" => Some(Self::PROVIDER_LANE_NATIVE),
            "PROVIDER_LANE_WASM" => Some(Self::PROVIDER_LANE_WASM),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::PROVIDER_LANE_UNSPECIFIED,
            Self::PROVIDER_LANE_NATIVE,
            Self::PROVIDER_LANE_WASM,
        ]
    }
}
impl ::zeroize::Zeroize for ProviderLane {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for ProviderLane {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for ProviderLane {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for ProviderLane {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.KeyResidency`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum KeyResidency {
    /// `KEY_RESIDENCY_UNSPECIFIED`.
    #[default]
    KEY_RESIDENCY_UNSPECIFIED = 0,
    /// `KEY_RESIDENCY_PROCESS_MEMORY`.
    KEY_RESIDENCY_PROCESS_MEMORY = 100,
}
impl KeyResidency {
    /// Idiomatic alias for [`Self::KEY_RESIDENCY_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::KEY_RESIDENCY_UNSPECIFIED;
    /// Idiomatic alias for [`Self::KEY_RESIDENCY_PROCESS_MEMORY`].
    #[allow(non_upper_case_globals)]
    pub const ProcessMemory: Self = Self::KEY_RESIDENCY_PROCESS_MEMORY;
}
impl ::buffa::Enumeration for KeyResidency {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::KEY_RESIDENCY_UNSPECIFIED),
            100 => Some(Self::KEY_RESIDENCY_PROCESS_MEMORY),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::KEY_RESIDENCY_UNSPECIFIED => "KEY_RESIDENCY_UNSPECIFIED",
            Self::KEY_RESIDENCY_PROCESS_MEMORY => "KEY_RESIDENCY_PROCESS_MEMORY",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "KEY_RESIDENCY_UNSPECIFIED" => Some(Self::KEY_RESIDENCY_UNSPECIFIED),
            "KEY_RESIDENCY_PROCESS_MEMORY" => Some(Self::KEY_RESIDENCY_PROCESS_MEMORY),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::KEY_RESIDENCY_UNSPECIFIED,
            Self::KEY_RESIDENCY_PROCESS_MEMORY,
        ]
    }
}
impl ::zeroize::Zeroize for KeyResidency {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for KeyResidency {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for KeyResidency {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for KeyResidency {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.KeyCopyBoundary`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum KeyCopyBoundary {
    /// `KEY_COPY_BOUNDARY_UNSPECIFIED`.
    #[default]
    KEY_COPY_BOUNDARY_UNSPECIFIED = 0,
    /// `KEY_COPY_BOUNDARY_NO_SECRET_INPUT`.
    KEY_COPY_BOUNDARY_NO_SECRET_INPUT = 100,
    /// `KEY_COPY_BOUNDARY_BORROWED_CALLER_SECRET`.
    KEY_COPY_BOUNDARY_BORROWED_CALLER_SECRET = 200,
    /// `KEY_COPY_BOUNDARY_PROVIDER_CREATES_SECRET`.
    KEY_COPY_BOUNDARY_PROVIDER_CREATES_SECRET = 300,
}
impl KeyCopyBoundary {
    /// Idiomatic alias for [`Self::KEY_COPY_BOUNDARY_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::KEY_COPY_BOUNDARY_UNSPECIFIED;
    /// Idiomatic alias for [`Self::KEY_COPY_BOUNDARY_NO_SECRET_INPUT`].
    #[allow(non_upper_case_globals)]
    pub const NoSecretInput: Self = Self::KEY_COPY_BOUNDARY_NO_SECRET_INPUT;
    /// Idiomatic alias for [`Self::KEY_COPY_BOUNDARY_BORROWED_CALLER_SECRET`].
    #[allow(non_upper_case_globals)]
    pub const BorrowedCallerSecret: Self = Self::KEY_COPY_BOUNDARY_BORROWED_CALLER_SECRET;
    /// Idiomatic alias for [`Self::KEY_COPY_BOUNDARY_PROVIDER_CREATES_SECRET`].
    #[allow(non_upper_case_globals)]
    pub const ProviderCreatesSecret: Self = Self::KEY_COPY_BOUNDARY_PROVIDER_CREATES_SECRET;
}
impl ::buffa::Enumeration for KeyCopyBoundary {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::KEY_COPY_BOUNDARY_UNSPECIFIED),
            100 => Some(Self::KEY_COPY_BOUNDARY_NO_SECRET_INPUT),
            200 => Some(Self::KEY_COPY_BOUNDARY_BORROWED_CALLER_SECRET),
            300 => Some(Self::KEY_COPY_BOUNDARY_PROVIDER_CREATES_SECRET),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::KEY_COPY_BOUNDARY_UNSPECIFIED => "KEY_COPY_BOUNDARY_UNSPECIFIED",
            Self::KEY_COPY_BOUNDARY_NO_SECRET_INPUT => "KEY_COPY_BOUNDARY_NO_SECRET_INPUT",
            Self::KEY_COPY_BOUNDARY_BORROWED_CALLER_SECRET => {
                "KEY_COPY_BOUNDARY_BORROWED_CALLER_SECRET"
            }
            Self::KEY_COPY_BOUNDARY_PROVIDER_CREATES_SECRET => {
                "KEY_COPY_BOUNDARY_PROVIDER_CREATES_SECRET"
            }
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "KEY_COPY_BOUNDARY_UNSPECIFIED" => Some(Self::KEY_COPY_BOUNDARY_UNSPECIFIED),
            "KEY_COPY_BOUNDARY_NO_SECRET_INPUT" => Some(Self::KEY_COPY_BOUNDARY_NO_SECRET_INPUT),
            "KEY_COPY_BOUNDARY_BORROWED_CALLER_SECRET" => {
                Some(Self::KEY_COPY_BOUNDARY_BORROWED_CALLER_SECRET)
            }
            "KEY_COPY_BOUNDARY_PROVIDER_CREATES_SECRET" => {
                Some(Self::KEY_COPY_BOUNDARY_PROVIDER_CREATES_SECRET)
            }
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::KEY_COPY_BOUNDARY_UNSPECIFIED,
            Self::KEY_COPY_BOUNDARY_NO_SECRET_INPUT,
            Self::KEY_COPY_BOUNDARY_BORROWED_CALLER_SECRET,
            Self::KEY_COPY_BOUNDARY_PROVIDER_CREATES_SECRET,
        ]
    }
}
impl ::zeroize::Zeroize for KeyCopyBoundary {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for KeyCopyBoundary {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for KeyCopyBoundary {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for KeyCopyBoundary {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.ProviderOutputPolicy`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum ProviderOutputPolicy {
    /// `PROVIDER_OUTPUT_POLICY_UNSPECIFIED`.
    #[default]
    PROVIDER_OUTPUT_POLICY_UNSPECIFIED = 0,
    /// `PROVIDER_OUTPUT_POLICY_PUBLIC_ONLY`.
    PROVIDER_OUTPUT_POLICY_PUBLIC_ONLY = 100,
    /// `PROVIDER_OUTPUT_POLICY_ZEROIZING_SECRET`.
    PROVIDER_OUTPUT_POLICY_ZEROIZING_SECRET = 200,
}
impl ProviderOutputPolicy {
    /// Idiomatic alias for [`Self::PROVIDER_OUTPUT_POLICY_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::PROVIDER_OUTPUT_POLICY_UNSPECIFIED;
    /// Idiomatic alias for [`Self::PROVIDER_OUTPUT_POLICY_PUBLIC_ONLY`].
    #[allow(non_upper_case_globals)]
    pub const PublicOnly: Self = Self::PROVIDER_OUTPUT_POLICY_PUBLIC_ONLY;
    /// Idiomatic alias for [`Self::PROVIDER_OUTPUT_POLICY_ZEROIZING_SECRET`].
    #[allow(non_upper_case_globals)]
    pub const ZeroizingSecret: Self = Self::PROVIDER_OUTPUT_POLICY_ZEROIZING_SECRET;
}
impl ::buffa::Enumeration for ProviderOutputPolicy {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::PROVIDER_OUTPUT_POLICY_UNSPECIFIED),
            100 => Some(Self::PROVIDER_OUTPUT_POLICY_PUBLIC_ONLY),
            200 => Some(Self::PROVIDER_OUTPUT_POLICY_ZEROIZING_SECRET),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::PROVIDER_OUTPUT_POLICY_UNSPECIFIED => "PROVIDER_OUTPUT_POLICY_UNSPECIFIED",
            Self::PROVIDER_OUTPUT_POLICY_PUBLIC_ONLY => "PROVIDER_OUTPUT_POLICY_PUBLIC_ONLY",
            Self::PROVIDER_OUTPUT_POLICY_ZEROIZING_SECRET => {
                "PROVIDER_OUTPUT_POLICY_ZEROIZING_SECRET"
            }
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "PROVIDER_OUTPUT_POLICY_UNSPECIFIED" => Some(Self::PROVIDER_OUTPUT_POLICY_UNSPECIFIED),
            "PROVIDER_OUTPUT_POLICY_PUBLIC_ONLY" => Some(Self::PROVIDER_OUTPUT_POLICY_PUBLIC_ONLY),
            "PROVIDER_OUTPUT_POLICY_ZEROIZING_SECRET" => {
                Some(Self::PROVIDER_OUTPUT_POLICY_ZEROIZING_SECRET)
            }
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::PROVIDER_OUTPUT_POLICY_UNSPECIFIED,
            Self::PROVIDER_OUTPUT_POLICY_PUBLIC_ONLY,
            Self::PROVIDER_OUTPUT_POLICY_ZEROIZING_SECRET,
        ]
    }
}
impl ::zeroize::Zeroize for ProviderOutputPolicy {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for ProviderOutputPolicy {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for ProviderOutputPolicy {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for ProviderOutputPolicy {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.ProviderPolicyReason`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum ProviderPolicyReason {
    /// `PROVIDER_POLICY_REASON_UNSPECIFIED`.
    #[default]
    PROVIDER_POLICY_REASON_UNSPECIFIED = 0,
    /// `PROVIDER_POLICY_REASON_SELECTED_COMPILED_IMPLEMENTATION`.
    PROVIDER_POLICY_REASON_SELECTED_COMPILED_IMPLEMENTATION = 100,
    /// `PROVIDER_POLICY_REASON_REJECTED_OPERATION_MISMATCH`.
    PROVIDER_POLICY_REASON_REJECTED_OPERATION_MISMATCH = 200,
    /// `PROVIDER_POLICY_REASON_REJECTED_FEATURE_DISABLED`.
    PROVIDER_POLICY_REASON_REJECTED_FEATURE_DISABLED = 210,
}
impl ProviderPolicyReason {
    /// Idiomatic alias for [`Self::PROVIDER_POLICY_REASON_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::PROVIDER_POLICY_REASON_UNSPECIFIED;
    /// Idiomatic alias for [`Self::PROVIDER_POLICY_REASON_SELECTED_COMPILED_IMPLEMENTATION`].
    #[allow(non_upper_case_globals)]
    pub const SelectedCompiledImplementation: Self =
        Self::PROVIDER_POLICY_REASON_SELECTED_COMPILED_IMPLEMENTATION;
    /// Idiomatic alias for [`Self::PROVIDER_POLICY_REASON_REJECTED_OPERATION_MISMATCH`].
    #[allow(non_upper_case_globals)]
    pub const RejectedOperationMismatch: Self =
        Self::PROVIDER_POLICY_REASON_REJECTED_OPERATION_MISMATCH;
    /// Idiomatic alias for [`Self::PROVIDER_POLICY_REASON_REJECTED_FEATURE_DISABLED`].
    #[allow(non_upper_case_globals)]
    pub const RejectedFeatureDisabled: Self =
        Self::PROVIDER_POLICY_REASON_REJECTED_FEATURE_DISABLED;
}
impl ::buffa::Enumeration for ProviderPolicyReason {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::PROVIDER_POLICY_REASON_UNSPECIFIED),
            100 => Some(Self::PROVIDER_POLICY_REASON_SELECTED_COMPILED_IMPLEMENTATION),
            200 => Some(Self::PROVIDER_POLICY_REASON_REJECTED_OPERATION_MISMATCH),
            210 => Some(Self::PROVIDER_POLICY_REASON_REJECTED_FEATURE_DISABLED),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::PROVIDER_POLICY_REASON_UNSPECIFIED => "PROVIDER_POLICY_REASON_UNSPECIFIED",
            Self::PROVIDER_POLICY_REASON_SELECTED_COMPILED_IMPLEMENTATION => {
                "PROVIDER_POLICY_REASON_SELECTED_COMPILED_IMPLEMENTATION"
            }
            Self::PROVIDER_POLICY_REASON_REJECTED_OPERATION_MISMATCH => {
                "PROVIDER_POLICY_REASON_REJECTED_OPERATION_MISMATCH"
            }
            Self::PROVIDER_POLICY_REASON_REJECTED_FEATURE_DISABLED => {
                "PROVIDER_POLICY_REASON_REJECTED_FEATURE_DISABLED"
            }
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "PROVIDER_POLICY_REASON_UNSPECIFIED" => Some(Self::PROVIDER_POLICY_REASON_UNSPECIFIED),
            "PROVIDER_POLICY_REASON_SELECTED_COMPILED_IMPLEMENTATION" => {
                Some(Self::PROVIDER_POLICY_REASON_SELECTED_COMPILED_IMPLEMENTATION)
            }
            "PROVIDER_POLICY_REASON_REJECTED_OPERATION_MISMATCH" => {
                Some(Self::PROVIDER_POLICY_REASON_REJECTED_OPERATION_MISMATCH)
            }
            "PROVIDER_POLICY_REASON_REJECTED_FEATURE_DISABLED" => {
                Some(Self::PROVIDER_POLICY_REASON_REJECTED_FEATURE_DISABLED)
            }
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::PROVIDER_POLICY_REASON_UNSPECIFIED,
            Self::PROVIDER_POLICY_REASON_SELECTED_COMPILED_IMPLEMENTATION,
            Self::PROVIDER_POLICY_REASON_REJECTED_OPERATION_MISMATCH,
            Self::PROVIDER_POLICY_REASON_REJECTED_FEATURE_DISABLED,
        ]
    }
}
impl ::zeroize::Zeroize for ProviderPolicyReason {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for ProviderPolicyReason {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for ProviderPolicyReason {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for ProviderPolicyReason {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.ProviderDisposition`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum ProviderDisposition {
    /// `PROVIDER_DISPOSITION_UNSPECIFIED`.
    #[default]
    PROVIDER_DISPOSITION_UNSPECIFIED = 0,
    /// `PROVIDER_DISPOSITION_SELECTED`.
    PROVIDER_DISPOSITION_SELECTED = 100,
    /// `PROVIDER_DISPOSITION_REJECTED`.
    PROVIDER_DISPOSITION_REJECTED = 200,
}
impl ProviderDisposition {
    /// Idiomatic alias for [`Self::PROVIDER_DISPOSITION_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::PROVIDER_DISPOSITION_UNSPECIFIED;
    /// Idiomatic alias for [`Self::PROVIDER_DISPOSITION_SELECTED`].
    #[allow(non_upper_case_globals)]
    pub const Selected: Self = Self::PROVIDER_DISPOSITION_SELECTED;
    /// Idiomatic alias for [`Self::PROVIDER_DISPOSITION_REJECTED`].
    #[allow(non_upper_case_globals)]
    pub const Rejected: Self = Self::PROVIDER_DISPOSITION_REJECTED;
}
impl ::buffa::Enumeration for ProviderDisposition {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::PROVIDER_DISPOSITION_UNSPECIFIED),
            100 => Some(Self::PROVIDER_DISPOSITION_SELECTED),
            200 => Some(Self::PROVIDER_DISPOSITION_REJECTED),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::PROVIDER_DISPOSITION_UNSPECIFIED => "PROVIDER_DISPOSITION_UNSPECIFIED",
            Self::PROVIDER_DISPOSITION_SELECTED => "PROVIDER_DISPOSITION_SELECTED",
            Self::PROVIDER_DISPOSITION_REJECTED => "PROVIDER_DISPOSITION_REJECTED",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "PROVIDER_DISPOSITION_UNSPECIFIED" => Some(Self::PROVIDER_DISPOSITION_UNSPECIFIED),
            "PROVIDER_DISPOSITION_SELECTED" => Some(Self::PROVIDER_DISPOSITION_SELECTED),
            "PROVIDER_DISPOSITION_REJECTED" => Some(Self::PROVIDER_DISPOSITION_REJECTED),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::PROVIDER_DISPOSITION_UNSPECIFIED,
            Self::PROVIDER_DISPOSITION_SELECTED,
            Self::PROVIDER_DISPOSITION_REJECTED,
        ]
    }
}
impl ::zeroize::Zeroize for ProviderDisposition {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for ProviderDisposition {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for ProviderDisposition {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for ProviderDisposition {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.FallbackPolicy`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum FallbackPolicy {
    /// `FALLBACK_POLICY_UNSPECIFIED`.
    #[default]
    FALLBACK_POLICY_UNSPECIFIED = 0,
    /// `FALLBACK_POLICY_PROHIBITED`.
    FALLBACK_POLICY_PROHIBITED = 100,
}
impl FallbackPolicy {
    /// Idiomatic alias for [`Self::FALLBACK_POLICY_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::FALLBACK_POLICY_UNSPECIFIED;
    /// Idiomatic alias for [`Self::FALLBACK_POLICY_PROHIBITED`].
    #[allow(non_upper_case_globals)]
    pub const Prohibited: Self = Self::FALLBACK_POLICY_PROHIBITED;
}
impl ::buffa::Enumeration for FallbackPolicy {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::FALLBACK_POLICY_UNSPECIFIED),
            100 => Some(Self::FALLBACK_POLICY_PROHIBITED),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::FALLBACK_POLICY_UNSPECIFIED => "FALLBACK_POLICY_UNSPECIFIED",
            Self::FALLBACK_POLICY_PROHIBITED => "FALLBACK_POLICY_PROHIBITED",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "FALLBACK_POLICY_UNSPECIFIED" => Some(Self::FALLBACK_POLICY_UNSPECIFIED),
            "FALLBACK_POLICY_PROHIBITED" => Some(Self::FALLBACK_POLICY_PROHIBITED),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::FALLBACK_POLICY_UNSPECIFIED,
            Self::FALLBACK_POLICY_PROHIBITED,
        ]
    }
}
impl ::zeroize::Zeroize for FallbackPolicy {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for FallbackPolicy {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for FallbackPolicy {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for FallbackPolicy {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.BufferOwner`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum BufferOwner {
    /// `BUFFER_OWNER_UNSPECIFIED`.
    #[default]
    BUFFER_OWNER_UNSPECIFIED = 0,
    /// `BUFFER_OWNER_CALLER`.
    BUFFER_OWNER_CALLER = 100,
    /// `BUFFER_OWNER_OPERATION_LAYER`.
    BUFFER_OWNER_OPERATION_LAYER = 200,
    /// `BUFFER_OWNER_OPERATION_CONTRACT`.
    BUFFER_OWNER_OPERATION_CONTRACT = 300,
    /// `BUFFER_OWNER_NATIVE_ADAPTER`.
    BUFFER_OWNER_NATIVE_ADAPTER = 400,
    /// `BUFFER_OWNER_MANAGED_RUNTIME`.
    BUFFER_OWNER_MANAGED_RUNTIME = 500,
    /// `BUFFER_OWNER_PLATFORM_PROVIDER`.
    BUFFER_OWNER_PLATFORM_PROVIDER = 600,
}
impl BufferOwner {
    /// Idiomatic alias for [`Self::BUFFER_OWNER_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::BUFFER_OWNER_UNSPECIFIED;
    /// Idiomatic alias for [`Self::BUFFER_OWNER_CALLER`].
    #[allow(non_upper_case_globals)]
    pub const Caller: Self = Self::BUFFER_OWNER_CALLER;
    /// Idiomatic alias for [`Self::BUFFER_OWNER_OPERATION_LAYER`].
    #[allow(non_upper_case_globals)]
    pub const OperationLayer: Self = Self::BUFFER_OWNER_OPERATION_LAYER;
    /// Idiomatic alias for [`Self::BUFFER_OWNER_OPERATION_CONTRACT`].
    #[allow(non_upper_case_globals)]
    pub const OperationContract: Self = Self::BUFFER_OWNER_OPERATION_CONTRACT;
    /// Idiomatic alias for [`Self::BUFFER_OWNER_NATIVE_ADAPTER`].
    #[allow(non_upper_case_globals)]
    pub const NativeAdapter: Self = Self::BUFFER_OWNER_NATIVE_ADAPTER;
    /// Idiomatic alias for [`Self::BUFFER_OWNER_MANAGED_RUNTIME`].
    #[allow(non_upper_case_globals)]
    pub const ManagedRuntime: Self = Self::BUFFER_OWNER_MANAGED_RUNTIME;
    /// Idiomatic alias for [`Self::BUFFER_OWNER_PLATFORM_PROVIDER`].
    #[allow(non_upper_case_globals)]
    pub const PlatformProvider: Self = Self::BUFFER_OWNER_PLATFORM_PROVIDER;
}
impl ::buffa::Enumeration for BufferOwner {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::BUFFER_OWNER_UNSPECIFIED),
            100 => Some(Self::BUFFER_OWNER_CALLER),
            200 => Some(Self::BUFFER_OWNER_OPERATION_LAYER),
            300 => Some(Self::BUFFER_OWNER_OPERATION_CONTRACT),
            400 => Some(Self::BUFFER_OWNER_NATIVE_ADAPTER),
            500 => Some(Self::BUFFER_OWNER_MANAGED_RUNTIME),
            600 => Some(Self::BUFFER_OWNER_PLATFORM_PROVIDER),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::BUFFER_OWNER_UNSPECIFIED => "BUFFER_OWNER_UNSPECIFIED",
            Self::BUFFER_OWNER_CALLER => "BUFFER_OWNER_CALLER",
            Self::BUFFER_OWNER_OPERATION_LAYER => "BUFFER_OWNER_OPERATION_LAYER",
            Self::BUFFER_OWNER_OPERATION_CONTRACT => "BUFFER_OWNER_OPERATION_CONTRACT",
            Self::BUFFER_OWNER_NATIVE_ADAPTER => "BUFFER_OWNER_NATIVE_ADAPTER",
            Self::BUFFER_OWNER_MANAGED_RUNTIME => "BUFFER_OWNER_MANAGED_RUNTIME",
            Self::BUFFER_OWNER_PLATFORM_PROVIDER => "BUFFER_OWNER_PLATFORM_PROVIDER",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "BUFFER_OWNER_UNSPECIFIED" => Some(Self::BUFFER_OWNER_UNSPECIFIED),
            "BUFFER_OWNER_CALLER" => Some(Self::BUFFER_OWNER_CALLER),
            "BUFFER_OWNER_OPERATION_LAYER" => Some(Self::BUFFER_OWNER_OPERATION_LAYER),
            "BUFFER_OWNER_OPERATION_CONTRACT" => Some(Self::BUFFER_OWNER_OPERATION_CONTRACT),
            "BUFFER_OWNER_NATIVE_ADAPTER" => Some(Self::BUFFER_OWNER_NATIVE_ADAPTER),
            "BUFFER_OWNER_MANAGED_RUNTIME" => Some(Self::BUFFER_OWNER_MANAGED_RUNTIME),
            "BUFFER_OWNER_PLATFORM_PROVIDER" => Some(Self::BUFFER_OWNER_PLATFORM_PROVIDER),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::BUFFER_OWNER_UNSPECIFIED,
            Self::BUFFER_OWNER_CALLER,
            Self::BUFFER_OWNER_OPERATION_LAYER,
            Self::BUFFER_OWNER_OPERATION_CONTRACT,
            Self::BUFFER_OWNER_NATIVE_ADAPTER,
            Self::BUFFER_OWNER_MANAGED_RUNTIME,
            Self::BUFFER_OWNER_PLATFORM_PROVIDER,
        ]
    }
}
impl ::zeroize::Zeroize for BufferOwner {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for BufferOwner {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for BufferOwner {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for BufferOwner {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.SecretSensitivity`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum SecretSensitivity {
    /// `SECRET_SENSITIVITY_UNSPECIFIED`.
    #[default]
    SECRET_SENSITIVITY_UNSPECIFIED = 0,
    /// `SECRET_SENSITIVITY_PUBLIC`.
    SECRET_SENSITIVITY_PUBLIC = 100,
    /// `SECRET_SENSITIVITY_SENSITIVE`.
    SECRET_SENSITIVITY_SENSITIVE = 200,
    /// `SECRET_SENSITIVITY_SECRET`.
    SECRET_SENSITIVITY_SECRET = 300,
}
impl SecretSensitivity {
    /// Idiomatic alias for [`Self::SECRET_SENSITIVITY_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::SECRET_SENSITIVITY_UNSPECIFIED;
    /// Idiomatic alias for [`Self::SECRET_SENSITIVITY_PUBLIC`].
    #[allow(non_upper_case_globals)]
    pub const Public: Self = Self::SECRET_SENSITIVITY_PUBLIC;
    /// Idiomatic alias for [`Self::SECRET_SENSITIVITY_SENSITIVE`].
    #[allow(non_upper_case_globals)]
    pub const Sensitive: Self = Self::SECRET_SENSITIVITY_SENSITIVE;
    /// Idiomatic alias for [`Self::SECRET_SENSITIVITY_SECRET`].
    #[allow(non_upper_case_globals)]
    pub const Secret: Self = Self::SECRET_SENSITIVITY_SECRET;
}
impl ::buffa::Enumeration for SecretSensitivity {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::SECRET_SENSITIVITY_UNSPECIFIED),
            100 => Some(Self::SECRET_SENSITIVITY_PUBLIC),
            200 => Some(Self::SECRET_SENSITIVITY_SENSITIVE),
            300 => Some(Self::SECRET_SENSITIVITY_SECRET),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::SECRET_SENSITIVITY_UNSPECIFIED => "SECRET_SENSITIVITY_UNSPECIFIED",
            Self::SECRET_SENSITIVITY_PUBLIC => "SECRET_SENSITIVITY_PUBLIC",
            Self::SECRET_SENSITIVITY_SENSITIVE => "SECRET_SENSITIVITY_SENSITIVE",
            Self::SECRET_SENSITIVITY_SECRET => "SECRET_SENSITIVITY_SECRET",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "SECRET_SENSITIVITY_UNSPECIFIED" => Some(Self::SECRET_SENSITIVITY_UNSPECIFIED),
            "SECRET_SENSITIVITY_PUBLIC" => Some(Self::SECRET_SENSITIVITY_PUBLIC),
            "SECRET_SENSITIVITY_SENSITIVE" => Some(Self::SECRET_SENSITIVITY_SENSITIVE),
            "SECRET_SENSITIVITY_SECRET" => Some(Self::SECRET_SENSITIVITY_SECRET),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::SECRET_SENSITIVITY_UNSPECIFIED,
            Self::SECRET_SENSITIVITY_PUBLIC,
            Self::SECRET_SENSITIVITY_SENSITIVE,
            Self::SECRET_SENSITIVITY_SECRET,
        ]
    }
}
impl ::zeroize::Zeroize for SecretSensitivity {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for SecretSensitivity {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for SecretSensitivity {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for SecretSensitivity {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.OutputMaterial`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum OutputMaterial {
    /// `OUTPUT_MATERIAL_UNSPECIFIED`.
    #[default]
    OUTPUT_MATERIAL_UNSPECIFIED = 0,
    /// `OUTPUT_MATERIAL_PUBLIC`.
    OUTPUT_MATERIAL_PUBLIC = 100,
    /// `OUTPUT_MATERIAL_SENSITIVE_PUBLIC`.
    OUTPUT_MATERIAL_SENSITIVE_PUBLIC = 200,
    /// `OUTPUT_MATERIAL_SECRET`.
    OUTPUT_MATERIAL_SECRET = 300,
    /// `OUTPUT_MATERIAL_MIXED`.
    OUTPUT_MATERIAL_MIXED = 400,
}
impl OutputMaterial {
    /// Idiomatic alias for [`Self::OUTPUT_MATERIAL_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::OUTPUT_MATERIAL_UNSPECIFIED;
    /// Idiomatic alias for [`Self::OUTPUT_MATERIAL_PUBLIC`].
    #[allow(non_upper_case_globals)]
    pub const Public: Self = Self::OUTPUT_MATERIAL_PUBLIC;
    /// Idiomatic alias for [`Self::OUTPUT_MATERIAL_SENSITIVE_PUBLIC`].
    #[allow(non_upper_case_globals)]
    pub const SensitivePublic: Self = Self::OUTPUT_MATERIAL_SENSITIVE_PUBLIC;
    /// Idiomatic alias for [`Self::OUTPUT_MATERIAL_SECRET`].
    #[allow(non_upper_case_globals)]
    pub const Secret: Self = Self::OUTPUT_MATERIAL_SECRET;
    /// Idiomatic alias for [`Self::OUTPUT_MATERIAL_MIXED`].
    #[allow(non_upper_case_globals)]
    pub const Mixed: Self = Self::OUTPUT_MATERIAL_MIXED;
}
impl ::buffa::Enumeration for OutputMaterial {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::OUTPUT_MATERIAL_UNSPECIFIED),
            100 => Some(Self::OUTPUT_MATERIAL_PUBLIC),
            200 => Some(Self::OUTPUT_MATERIAL_SENSITIVE_PUBLIC),
            300 => Some(Self::OUTPUT_MATERIAL_SECRET),
            400 => Some(Self::OUTPUT_MATERIAL_MIXED),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::OUTPUT_MATERIAL_UNSPECIFIED => "OUTPUT_MATERIAL_UNSPECIFIED",
            Self::OUTPUT_MATERIAL_PUBLIC => "OUTPUT_MATERIAL_PUBLIC",
            Self::OUTPUT_MATERIAL_SENSITIVE_PUBLIC => "OUTPUT_MATERIAL_SENSITIVE_PUBLIC",
            Self::OUTPUT_MATERIAL_SECRET => "OUTPUT_MATERIAL_SECRET",
            Self::OUTPUT_MATERIAL_MIXED => "OUTPUT_MATERIAL_MIXED",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "OUTPUT_MATERIAL_UNSPECIFIED" => Some(Self::OUTPUT_MATERIAL_UNSPECIFIED),
            "OUTPUT_MATERIAL_PUBLIC" => Some(Self::OUTPUT_MATERIAL_PUBLIC),
            "OUTPUT_MATERIAL_SENSITIVE_PUBLIC" => Some(Self::OUTPUT_MATERIAL_SENSITIVE_PUBLIC),
            "OUTPUT_MATERIAL_SECRET" => Some(Self::OUTPUT_MATERIAL_SECRET),
            "OUTPUT_MATERIAL_MIXED" => Some(Self::OUTPUT_MATERIAL_MIXED),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::OUTPUT_MATERIAL_UNSPECIFIED,
            Self::OUTPUT_MATERIAL_PUBLIC,
            Self::OUTPUT_MATERIAL_SENSITIVE_PUBLIC,
            Self::OUTPUT_MATERIAL_SECRET,
            Self::OUTPUT_MATERIAL_MIXED,
        ]
    }
}
impl ::zeroize::Zeroize for OutputMaterial {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for OutputMaterial {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for OutputMaterial {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for OutputMaterial {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.RetentionPolicy`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum RetentionPolicy {
    /// `RETENTION_POLICY_UNSPECIFIED`.
    #[default]
    RETENTION_POLICY_UNSPECIFIED = 0,
    /// `RETENTION_POLICY_BORROWED_FOR_CALL`.
    RETENTION_POLICY_BORROWED_FOR_CALL = 100,
    /// `RETENTION_POLICY_OPERATION_TEMPORARY`.
    RETENTION_POLICY_OPERATION_TEMPORARY = 200,
    /// `RETENTION_POLICY_RESULT_LIFETIME`.
    RETENTION_POLICY_RESULT_LIFETIME = 300,
    /// `RETENTION_POLICY_PROVIDER_MANAGED`.
    RETENTION_POLICY_PROVIDER_MANAGED = 400,
}
impl RetentionPolicy {
    /// Idiomatic alias for [`Self::RETENTION_POLICY_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::RETENTION_POLICY_UNSPECIFIED;
    /// Idiomatic alias for [`Self::RETENTION_POLICY_BORROWED_FOR_CALL`].
    #[allow(non_upper_case_globals)]
    pub const BorrowedForCall: Self = Self::RETENTION_POLICY_BORROWED_FOR_CALL;
    /// Idiomatic alias for [`Self::RETENTION_POLICY_OPERATION_TEMPORARY`].
    #[allow(non_upper_case_globals)]
    pub const OperationTemporary: Self = Self::RETENTION_POLICY_OPERATION_TEMPORARY;
    /// Idiomatic alias for [`Self::RETENTION_POLICY_RESULT_LIFETIME`].
    #[allow(non_upper_case_globals)]
    pub const ResultLifetime: Self = Self::RETENTION_POLICY_RESULT_LIFETIME;
    /// Idiomatic alias for [`Self::RETENTION_POLICY_PROVIDER_MANAGED`].
    #[allow(non_upper_case_globals)]
    pub const ProviderManaged: Self = Self::RETENTION_POLICY_PROVIDER_MANAGED;
}
impl ::buffa::Enumeration for RetentionPolicy {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::RETENTION_POLICY_UNSPECIFIED),
            100 => Some(Self::RETENTION_POLICY_BORROWED_FOR_CALL),
            200 => Some(Self::RETENTION_POLICY_OPERATION_TEMPORARY),
            300 => Some(Self::RETENTION_POLICY_RESULT_LIFETIME),
            400 => Some(Self::RETENTION_POLICY_PROVIDER_MANAGED),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::RETENTION_POLICY_UNSPECIFIED => "RETENTION_POLICY_UNSPECIFIED",
            Self::RETENTION_POLICY_BORROWED_FOR_CALL => "RETENTION_POLICY_BORROWED_FOR_CALL",
            Self::RETENTION_POLICY_OPERATION_TEMPORARY => "RETENTION_POLICY_OPERATION_TEMPORARY",
            Self::RETENTION_POLICY_RESULT_LIFETIME => "RETENTION_POLICY_RESULT_LIFETIME",
            Self::RETENTION_POLICY_PROVIDER_MANAGED => "RETENTION_POLICY_PROVIDER_MANAGED",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "RETENTION_POLICY_UNSPECIFIED" => Some(Self::RETENTION_POLICY_UNSPECIFIED),
            "RETENTION_POLICY_BORROWED_FOR_CALL" => Some(Self::RETENTION_POLICY_BORROWED_FOR_CALL),
            "RETENTION_POLICY_OPERATION_TEMPORARY" => {
                Some(Self::RETENTION_POLICY_OPERATION_TEMPORARY)
            }
            "RETENTION_POLICY_RESULT_LIFETIME" => Some(Self::RETENTION_POLICY_RESULT_LIFETIME),
            "RETENTION_POLICY_PROVIDER_MANAGED" => Some(Self::RETENTION_POLICY_PROVIDER_MANAGED),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::RETENTION_POLICY_UNSPECIFIED,
            Self::RETENTION_POLICY_BORROWED_FOR_CALL,
            Self::RETENTION_POLICY_OPERATION_TEMPORARY,
            Self::RETENTION_POLICY_RESULT_LIFETIME,
            Self::RETENTION_POLICY_PROVIDER_MANAGED,
        ]
    }
}
impl ::zeroize::Zeroize for RetentionPolicy {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for RetentionPolicy {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for RetentionPolicy {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for RetentionPolicy {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.ExportPolicy`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum ExportPolicy {
    /// `EXPORT_POLICY_UNSPECIFIED`.
    #[default]
    EXPORT_POLICY_UNSPECIFIED = 0,
    /// `EXPORT_POLICY_PUBLIC`.
    EXPORT_POLICY_PUBLIC = 100,
    /// `EXPORT_POLICY_SECRET_OWNER_REQUIRED`.
    EXPORT_POLICY_SECRET_OWNER_REQUIRED = 200,
    /// `EXPORT_POLICY_NON_EXPORTABLE`.
    EXPORT_POLICY_NON_EXPORTABLE = 300,
}
impl ExportPolicy {
    /// Idiomatic alias for [`Self::EXPORT_POLICY_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::EXPORT_POLICY_UNSPECIFIED;
    /// Idiomatic alias for [`Self::EXPORT_POLICY_PUBLIC`].
    #[allow(non_upper_case_globals)]
    pub const Public: Self = Self::EXPORT_POLICY_PUBLIC;
    /// Idiomatic alias for [`Self::EXPORT_POLICY_SECRET_OWNER_REQUIRED`].
    #[allow(non_upper_case_globals)]
    pub const SecretOwnerRequired: Self = Self::EXPORT_POLICY_SECRET_OWNER_REQUIRED;
    /// Idiomatic alias for [`Self::EXPORT_POLICY_NON_EXPORTABLE`].
    #[allow(non_upper_case_globals)]
    pub const NonExportable: Self = Self::EXPORT_POLICY_NON_EXPORTABLE;
}
impl ::buffa::Enumeration for ExportPolicy {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::EXPORT_POLICY_UNSPECIFIED),
            100 => Some(Self::EXPORT_POLICY_PUBLIC),
            200 => Some(Self::EXPORT_POLICY_SECRET_OWNER_REQUIRED),
            300 => Some(Self::EXPORT_POLICY_NON_EXPORTABLE),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::EXPORT_POLICY_UNSPECIFIED => "EXPORT_POLICY_UNSPECIFIED",
            Self::EXPORT_POLICY_PUBLIC => "EXPORT_POLICY_PUBLIC",
            Self::EXPORT_POLICY_SECRET_OWNER_REQUIRED => "EXPORT_POLICY_SECRET_OWNER_REQUIRED",
            Self::EXPORT_POLICY_NON_EXPORTABLE => "EXPORT_POLICY_NON_EXPORTABLE",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "EXPORT_POLICY_UNSPECIFIED" => Some(Self::EXPORT_POLICY_UNSPECIFIED),
            "EXPORT_POLICY_PUBLIC" => Some(Self::EXPORT_POLICY_PUBLIC),
            "EXPORT_POLICY_SECRET_OWNER_REQUIRED" => {
                Some(Self::EXPORT_POLICY_SECRET_OWNER_REQUIRED)
            }
            "EXPORT_POLICY_NON_EXPORTABLE" => Some(Self::EXPORT_POLICY_NON_EXPORTABLE),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::EXPORT_POLICY_UNSPECIFIED,
            Self::EXPORT_POLICY_PUBLIC,
            Self::EXPORT_POLICY_SECRET_OWNER_REQUIRED,
            Self::EXPORT_POLICY_NON_EXPORTABLE,
        ]
    }
}
impl ::zeroize::Zeroize for ExportPolicy {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for ExportPolicy {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for ExportPolicy {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for ExportPolicy {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.ZeroizationPolicy`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum ZeroizationPolicy {
    /// `ZEROIZATION_POLICY_UNSPECIFIED`.
    #[default]
    ZEROIZATION_POLICY_UNSPECIFIED = 0,
    /// `ZEROIZATION_POLICY_NOT_REQUIRED`.
    ZEROIZATION_POLICY_NOT_REQUIRED = 100,
    /// `ZEROIZATION_POLICY_OWNER_ZEROIZES_ON_DROP`.
    ZEROIZATION_POLICY_OWNER_ZEROIZES_ON_DROP = 200,
    /// `ZEROIZATION_POLICY_CALLER_RETAINS_RESPONSIBILITY`.
    ZEROIZATION_POLICY_CALLER_RETAINS_RESPONSIBILITY = 300,
    /// `ZEROIZATION_POLICY_MANAGED_RUNTIME_BEST_EFFORT`.
    ZEROIZATION_POLICY_MANAGED_RUNTIME_BEST_EFFORT = 400,
}
impl ZeroizationPolicy {
    /// Idiomatic alias for [`Self::ZEROIZATION_POLICY_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::ZEROIZATION_POLICY_UNSPECIFIED;
    /// Idiomatic alias for [`Self::ZEROIZATION_POLICY_NOT_REQUIRED`].
    #[allow(non_upper_case_globals)]
    pub const NotRequired: Self = Self::ZEROIZATION_POLICY_NOT_REQUIRED;
    /// Idiomatic alias for [`Self::ZEROIZATION_POLICY_OWNER_ZEROIZES_ON_DROP`].
    #[allow(non_upper_case_globals)]
    pub const OwnerZeroizesOnDrop: Self = Self::ZEROIZATION_POLICY_OWNER_ZEROIZES_ON_DROP;
    /// Idiomatic alias for [`Self::ZEROIZATION_POLICY_CALLER_RETAINS_RESPONSIBILITY`].
    #[allow(non_upper_case_globals)]
    pub const CallerRetainsResponsibility: Self =
        Self::ZEROIZATION_POLICY_CALLER_RETAINS_RESPONSIBILITY;
    /// Idiomatic alias for [`Self::ZEROIZATION_POLICY_MANAGED_RUNTIME_BEST_EFFORT`].
    #[allow(non_upper_case_globals)]
    pub const ManagedRuntimeBestEffort: Self = Self::ZEROIZATION_POLICY_MANAGED_RUNTIME_BEST_EFFORT;
}
impl ::buffa::Enumeration for ZeroizationPolicy {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::ZEROIZATION_POLICY_UNSPECIFIED),
            100 => Some(Self::ZEROIZATION_POLICY_NOT_REQUIRED),
            200 => Some(Self::ZEROIZATION_POLICY_OWNER_ZEROIZES_ON_DROP),
            300 => Some(Self::ZEROIZATION_POLICY_CALLER_RETAINS_RESPONSIBILITY),
            400 => Some(Self::ZEROIZATION_POLICY_MANAGED_RUNTIME_BEST_EFFORT),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::ZEROIZATION_POLICY_UNSPECIFIED => "ZEROIZATION_POLICY_UNSPECIFIED",
            Self::ZEROIZATION_POLICY_NOT_REQUIRED => "ZEROIZATION_POLICY_NOT_REQUIRED",
            Self::ZEROIZATION_POLICY_OWNER_ZEROIZES_ON_DROP => {
                "ZEROIZATION_POLICY_OWNER_ZEROIZES_ON_DROP"
            }
            Self::ZEROIZATION_POLICY_CALLER_RETAINS_RESPONSIBILITY => {
                "ZEROIZATION_POLICY_CALLER_RETAINS_RESPONSIBILITY"
            }
            Self::ZEROIZATION_POLICY_MANAGED_RUNTIME_BEST_EFFORT => {
                "ZEROIZATION_POLICY_MANAGED_RUNTIME_BEST_EFFORT"
            }
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "ZEROIZATION_POLICY_UNSPECIFIED" => Some(Self::ZEROIZATION_POLICY_UNSPECIFIED),
            "ZEROIZATION_POLICY_NOT_REQUIRED" => Some(Self::ZEROIZATION_POLICY_NOT_REQUIRED),
            "ZEROIZATION_POLICY_OWNER_ZEROIZES_ON_DROP" => {
                Some(Self::ZEROIZATION_POLICY_OWNER_ZEROIZES_ON_DROP)
            }
            "ZEROIZATION_POLICY_CALLER_RETAINS_RESPONSIBILITY" => {
                Some(Self::ZEROIZATION_POLICY_CALLER_RETAINS_RESPONSIBILITY)
            }
            "ZEROIZATION_POLICY_MANAGED_RUNTIME_BEST_EFFORT" => {
                Some(Self::ZEROIZATION_POLICY_MANAGED_RUNTIME_BEST_EFFORT)
            }
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::ZEROIZATION_POLICY_UNSPECIFIED,
            Self::ZEROIZATION_POLICY_NOT_REQUIRED,
            Self::ZEROIZATION_POLICY_OWNER_ZEROIZES_ON_DROP,
            Self::ZEROIZATION_POLICY_CALLER_RETAINS_RESPONSIBILITY,
            Self::ZEROIZATION_POLICY_MANAGED_RUNTIME_BEST_EFFORT,
        ]
    }
}
impl ::zeroize::Zeroize for ZeroizationPolicy {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for ZeroizationPolicy {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for ZeroizationPolicy {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for ZeroizationPolicy {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.DestructionPolicy`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum DestructionPolicy {
    /// `DESTRUCTION_POLICY_UNSPECIFIED`.
    #[default]
    DESTRUCTION_POLICY_UNSPECIFIED = 0,
    /// `DESTRUCTION_POLICY_NONE_REQUIRED`.
    DESTRUCTION_POLICY_NONE_REQUIRED = 100,
    /// `DESTRUCTION_POLICY_ZEROIZE_ON_DROP`.
    DESTRUCTION_POLICY_ZEROIZE_ON_DROP = 200,
    /// `DESTRUCTION_POLICY_CALLER_CONTROLLED`.
    DESTRUCTION_POLICY_CALLER_CONTROLLED = 300,
    /// `DESTRUCTION_POLICY_MANAGED_RUNTIME_BEST_EFFORT`.
    DESTRUCTION_POLICY_MANAGED_RUNTIME_BEST_EFFORT = 400,
}
impl DestructionPolicy {
    /// Idiomatic alias for [`Self::DESTRUCTION_POLICY_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::DESTRUCTION_POLICY_UNSPECIFIED;
    /// Idiomatic alias for [`Self::DESTRUCTION_POLICY_NONE_REQUIRED`].
    #[allow(non_upper_case_globals)]
    pub const NoneRequired: Self = Self::DESTRUCTION_POLICY_NONE_REQUIRED;
    /// Idiomatic alias for [`Self::DESTRUCTION_POLICY_ZEROIZE_ON_DROP`].
    #[allow(non_upper_case_globals)]
    pub const ZeroizeOnDrop: Self = Self::DESTRUCTION_POLICY_ZEROIZE_ON_DROP;
    /// Idiomatic alias for [`Self::DESTRUCTION_POLICY_CALLER_CONTROLLED`].
    #[allow(non_upper_case_globals)]
    pub const CallerControlled: Self = Self::DESTRUCTION_POLICY_CALLER_CONTROLLED;
    /// Idiomatic alias for [`Self::DESTRUCTION_POLICY_MANAGED_RUNTIME_BEST_EFFORT`].
    #[allow(non_upper_case_globals)]
    pub const ManagedRuntimeBestEffort: Self = Self::DESTRUCTION_POLICY_MANAGED_RUNTIME_BEST_EFFORT;
}
impl ::buffa::Enumeration for DestructionPolicy {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::DESTRUCTION_POLICY_UNSPECIFIED),
            100 => Some(Self::DESTRUCTION_POLICY_NONE_REQUIRED),
            200 => Some(Self::DESTRUCTION_POLICY_ZEROIZE_ON_DROP),
            300 => Some(Self::DESTRUCTION_POLICY_CALLER_CONTROLLED),
            400 => Some(Self::DESTRUCTION_POLICY_MANAGED_RUNTIME_BEST_EFFORT),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::DESTRUCTION_POLICY_UNSPECIFIED => "DESTRUCTION_POLICY_UNSPECIFIED",
            Self::DESTRUCTION_POLICY_NONE_REQUIRED => "DESTRUCTION_POLICY_NONE_REQUIRED",
            Self::DESTRUCTION_POLICY_ZEROIZE_ON_DROP => "DESTRUCTION_POLICY_ZEROIZE_ON_DROP",
            Self::DESTRUCTION_POLICY_CALLER_CONTROLLED => "DESTRUCTION_POLICY_CALLER_CONTROLLED",
            Self::DESTRUCTION_POLICY_MANAGED_RUNTIME_BEST_EFFORT => {
                "DESTRUCTION_POLICY_MANAGED_RUNTIME_BEST_EFFORT"
            }
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "DESTRUCTION_POLICY_UNSPECIFIED" => Some(Self::DESTRUCTION_POLICY_UNSPECIFIED),
            "DESTRUCTION_POLICY_NONE_REQUIRED" => Some(Self::DESTRUCTION_POLICY_NONE_REQUIRED),
            "DESTRUCTION_POLICY_ZEROIZE_ON_DROP" => Some(Self::DESTRUCTION_POLICY_ZEROIZE_ON_DROP),
            "DESTRUCTION_POLICY_CALLER_CONTROLLED" => {
                Some(Self::DESTRUCTION_POLICY_CALLER_CONTROLLED)
            }
            "DESTRUCTION_POLICY_MANAGED_RUNTIME_BEST_EFFORT" => {
                Some(Self::DESTRUCTION_POLICY_MANAGED_RUNTIME_BEST_EFFORT)
            }
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::DESTRUCTION_POLICY_UNSPECIFIED,
            Self::DESTRUCTION_POLICY_NONE_REQUIRED,
            Self::DESTRUCTION_POLICY_ZEROIZE_ON_DROP,
            Self::DESTRUCTION_POLICY_CALLER_CONTROLLED,
            Self::DESTRUCTION_POLICY_MANAGED_RUNTIME_BEST_EFFORT,
        ]
    }
}
impl ::zeroize::Zeroize for DestructionPolicy {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for DestructionPolicy {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for DestructionPolicy {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for DestructionPolicy {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.SecretMaterialOperation`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum SecretMaterialOperation {
    /// `SECRET_MATERIAL_OPERATION_UNSPECIFIED`.
    #[default]
    SECRET_MATERIAL_OPERATION_UNSPECIFIED = 0,
    /// `SECRET_MATERIAL_OPERATION_AEAD_SEAL`.
    SECRET_MATERIAL_OPERATION_AEAD_SEAL = 100,
    /// `SECRET_MATERIAL_OPERATION_AEAD_OPEN`.
    SECRET_MATERIAL_OPERATION_AEAD_OPEN = 110,
    /// `SECRET_MATERIAL_OPERATION_CONSTANT_TIME_COMPARE`.
    SECRET_MATERIAL_OPERATION_CONSTANT_TIME_COMPARE = 200,
    /// `SECRET_MATERIAL_OPERATION_HASH`.
    SECRET_MATERIAL_OPERATION_HASH = 300,
    /// `SECRET_MATERIAL_OPERATION_MAC_AUTHENTICATE`.
    SECRET_MATERIAL_OPERATION_MAC_AUTHENTICATE = 400,
    /// `SECRET_MATERIAL_OPERATION_MAC_VERIFY`.
    SECRET_MATERIAL_OPERATION_MAC_VERIFY = 410,
    /// `SECRET_MATERIAL_OPERATION_KEY_DERIVATION`.
    SECRET_MATERIAL_OPERATION_KEY_DERIVATION = 500,
    /// `SECRET_MATERIAL_OPERATION_KEY_WRAP`.
    SECRET_MATERIAL_OPERATION_KEY_WRAP = 600,
    /// `SECRET_MATERIAL_OPERATION_KEY_UNWRAP`.
    SECRET_MATERIAL_OPERATION_KEY_UNWRAP = 610,
    /// `SECRET_MATERIAL_OPERATION_SIGNATURE_KEY_GENERATION`.
    SECRET_MATERIAL_OPERATION_SIGNATURE_KEY_GENERATION = 700,
    /// `SECRET_MATERIAL_OPERATION_SIGNATURE_KEY_DERIVATION`.
    SECRET_MATERIAL_OPERATION_SIGNATURE_KEY_DERIVATION = 710,
    /// `SECRET_MATERIAL_OPERATION_SIGNATURE_SIGN`.
    SECRET_MATERIAL_OPERATION_SIGNATURE_SIGN = 720,
    /// `SECRET_MATERIAL_OPERATION_SIGNATURE_VERIFY`.
    SECRET_MATERIAL_OPERATION_SIGNATURE_VERIFY = 730,
    /// `SECRET_MATERIAL_OPERATION_SIGNATURE_ENCODING`.
    SECRET_MATERIAL_OPERATION_SIGNATURE_ENCODING = 740,
    /// `SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_KEY_GENERATION`.
    SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_KEY_GENERATION = 800,
    /// `SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_KEY_DERIVATION`.
    SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_KEY_DERIVATION = 810,
    /// `SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_SHARED_SECRET`.
    SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_SHARED_SECRET = 820,
    /// `SECRET_MATERIAL_OPERATION_KEM_KEY_GENERATION`.
    SECRET_MATERIAL_OPERATION_KEM_KEY_GENERATION = 900,
    /// `SECRET_MATERIAL_OPERATION_KEM_KEY_DERIVATION`.
    SECRET_MATERIAL_OPERATION_KEM_KEY_DERIVATION = 910,
    /// `SECRET_MATERIAL_OPERATION_KEM_ENCAPSULATE`.
    SECRET_MATERIAL_OPERATION_KEM_ENCAPSULATE = 920,
    /// `SECRET_MATERIAL_OPERATION_KEM_DECAPSULATE`.
    SECRET_MATERIAL_OPERATION_KEM_DECAPSULATE = 930,
    /// `SECRET_MATERIAL_OPERATION_HPKE_KEY_GENERATION`.
    SECRET_MATERIAL_OPERATION_HPKE_KEY_GENERATION = 1000,
    /// `SECRET_MATERIAL_OPERATION_HPKE_KEY_DERIVATION`.
    SECRET_MATERIAL_OPERATION_HPKE_KEY_DERIVATION = 1010,
    /// `SECRET_MATERIAL_OPERATION_HPKE_SENDER_SETUP`.
    SECRET_MATERIAL_OPERATION_HPKE_SENDER_SETUP = 1020,
    /// `SECRET_MATERIAL_OPERATION_HPKE_RECEIVER_SETUP`.
    SECRET_MATERIAL_OPERATION_HPKE_RECEIVER_SETUP = 1030,
    /// `SECRET_MATERIAL_OPERATION_HPKE_SEAL`.
    SECRET_MATERIAL_OPERATION_HPKE_SEAL = 1040,
    /// `SECRET_MATERIAL_OPERATION_HPKE_OPEN`.
    SECRET_MATERIAL_OPERATION_HPKE_OPEN = 1050,
    /// `SECRET_MATERIAL_OPERATION_HPKE_EXPORT`.
    SECRET_MATERIAL_OPERATION_HPKE_EXPORT = 1060,
    /// `SECRET_MATERIAL_OPERATION_RANDOM_FILL`.
    SECRET_MATERIAL_OPERATION_RANDOM_FILL = 1100,
    /// `SECRET_MATERIAL_OPERATION_RANDOM_NONCE`.
    SECRET_MATERIAL_OPERATION_RANDOM_NONCE = 1110,
    /// `SECRET_MATERIAL_OPERATION_RANDOM_SALT`.
    SECRET_MATERIAL_OPERATION_RANDOM_SALT = 1120,
    /// `SECRET_MATERIAL_OPERATION_PUBLIC_KEY_ENCODING`.
    SECRET_MATERIAL_OPERATION_PUBLIC_KEY_ENCODING = 1200,
}
impl SecretMaterialOperation {
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::SECRET_MATERIAL_OPERATION_UNSPECIFIED;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_AEAD_SEAL`].
    #[allow(non_upper_case_globals)]
    pub const AeadSeal: Self = Self::SECRET_MATERIAL_OPERATION_AEAD_SEAL;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_AEAD_OPEN`].
    #[allow(non_upper_case_globals)]
    pub const AeadOpen: Self = Self::SECRET_MATERIAL_OPERATION_AEAD_OPEN;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_CONSTANT_TIME_COMPARE`].
    #[allow(non_upper_case_globals)]
    pub const ConstantTimeCompare: Self = Self::SECRET_MATERIAL_OPERATION_CONSTANT_TIME_COMPARE;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_HASH`].
    #[allow(non_upper_case_globals)]
    pub const Hash: Self = Self::SECRET_MATERIAL_OPERATION_HASH;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_MAC_AUTHENTICATE`].
    #[allow(non_upper_case_globals)]
    pub const MacAuthenticate: Self = Self::SECRET_MATERIAL_OPERATION_MAC_AUTHENTICATE;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_MAC_VERIFY`].
    #[allow(non_upper_case_globals)]
    pub const MacVerify: Self = Self::SECRET_MATERIAL_OPERATION_MAC_VERIFY;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_KEY_DERIVATION`].
    #[allow(non_upper_case_globals)]
    pub const KeyDerivation: Self = Self::SECRET_MATERIAL_OPERATION_KEY_DERIVATION;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_KEY_WRAP`].
    #[allow(non_upper_case_globals)]
    pub const KeyWrap: Self = Self::SECRET_MATERIAL_OPERATION_KEY_WRAP;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_KEY_UNWRAP`].
    #[allow(non_upper_case_globals)]
    pub const KeyUnwrap: Self = Self::SECRET_MATERIAL_OPERATION_KEY_UNWRAP;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_SIGNATURE_KEY_GENERATION`].
    #[allow(non_upper_case_globals)]
    pub const SignatureKeyGeneration: Self =
        Self::SECRET_MATERIAL_OPERATION_SIGNATURE_KEY_GENERATION;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_SIGNATURE_KEY_DERIVATION`].
    #[allow(non_upper_case_globals)]
    pub const SignatureKeyDerivation: Self =
        Self::SECRET_MATERIAL_OPERATION_SIGNATURE_KEY_DERIVATION;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_SIGNATURE_SIGN`].
    #[allow(non_upper_case_globals)]
    pub const SignatureSign: Self = Self::SECRET_MATERIAL_OPERATION_SIGNATURE_SIGN;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_SIGNATURE_VERIFY`].
    #[allow(non_upper_case_globals)]
    pub const SignatureVerify: Self = Self::SECRET_MATERIAL_OPERATION_SIGNATURE_VERIFY;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_SIGNATURE_ENCODING`].
    #[allow(non_upper_case_globals)]
    pub const SignatureEncoding: Self = Self::SECRET_MATERIAL_OPERATION_SIGNATURE_ENCODING;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_KEY_GENERATION`].
    #[allow(non_upper_case_globals)]
    pub const KeyAgreementKeyGeneration: Self =
        Self::SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_KEY_GENERATION;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_KEY_DERIVATION`].
    #[allow(non_upper_case_globals)]
    pub const KeyAgreementKeyDerivation: Self =
        Self::SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_KEY_DERIVATION;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_SHARED_SECRET`].
    #[allow(non_upper_case_globals)]
    pub const KeyAgreementSharedSecret: Self =
        Self::SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_SHARED_SECRET;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_KEM_KEY_GENERATION`].
    #[allow(non_upper_case_globals)]
    pub const KemKeyGeneration: Self = Self::SECRET_MATERIAL_OPERATION_KEM_KEY_GENERATION;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_KEM_KEY_DERIVATION`].
    #[allow(non_upper_case_globals)]
    pub const KemKeyDerivation: Self = Self::SECRET_MATERIAL_OPERATION_KEM_KEY_DERIVATION;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_KEM_ENCAPSULATE`].
    #[allow(non_upper_case_globals)]
    pub const KemEncapsulate: Self = Self::SECRET_MATERIAL_OPERATION_KEM_ENCAPSULATE;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_KEM_DECAPSULATE`].
    #[allow(non_upper_case_globals)]
    pub const KemDecapsulate: Self = Self::SECRET_MATERIAL_OPERATION_KEM_DECAPSULATE;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_HPKE_KEY_GENERATION`].
    #[allow(non_upper_case_globals)]
    pub const HpkeKeyGeneration: Self = Self::SECRET_MATERIAL_OPERATION_HPKE_KEY_GENERATION;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_HPKE_KEY_DERIVATION`].
    #[allow(non_upper_case_globals)]
    pub const HpkeKeyDerivation: Self = Self::SECRET_MATERIAL_OPERATION_HPKE_KEY_DERIVATION;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_HPKE_SENDER_SETUP`].
    #[allow(non_upper_case_globals)]
    pub const HpkeSenderSetup: Self = Self::SECRET_MATERIAL_OPERATION_HPKE_SENDER_SETUP;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_HPKE_RECEIVER_SETUP`].
    #[allow(non_upper_case_globals)]
    pub const HpkeReceiverSetup: Self = Self::SECRET_MATERIAL_OPERATION_HPKE_RECEIVER_SETUP;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_HPKE_SEAL`].
    #[allow(non_upper_case_globals)]
    pub const HpkeSeal: Self = Self::SECRET_MATERIAL_OPERATION_HPKE_SEAL;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_HPKE_OPEN`].
    #[allow(non_upper_case_globals)]
    pub const HpkeOpen: Self = Self::SECRET_MATERIAL_OPERATION_HPKE_OPEN;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_HPKE_EXPORT`].
    #[allow(non_upper_case_globals)]
    pub const HpkeExport: Self = Self::SECRET_MATERIAL_OPERATION_HPKE_EXPORT;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_RANDOM_FILL`].
    #[allow(non_upper_case_globals)]
    pub const RandomFill: Self = Self::SECRET_MATERIAL_OPERATION_RANDOM_FILL;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_RANDOM_NONCE`].
    #[allow(non_upper_case_globals)]
    pub const RandomNonce: Self = Self::SECRET_MATERIAL_OPERATION_RANDOM_NONCE;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_RANDOM_SALT`].
    #[allow(non_upper_case_globals)]
    pub const RandomSalt: Self = Self::SECRET_MATERIAL_OPERATION_RANDOM_SALT;
    /// Idiomatic alias for [`Self::SECRET_MATERIAL_OPERATION_PUBLIC_KEY_ENCODING`].
    #[allow(non_upper_case_globals)]
    pub const PublicKeyEncoding: Self = Self::SECRET_MATERIAL_OPERATION_PUBLIC_KEY_ENCODING;
}
impl ::buffa::Enumeration for SecretMaterialOperation {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::SECRET_MATERIAL_OPERATION_UNSPECIFIED),
            100 => Some(Self::SECRET_MATERIAL_OPERATION_AEAD_SEAL),
            110 => Some(Self::SECRET_MATERIAL_OPERATION_AEAD_OPEN),
            200 => Some(Self::SECRET_MATERIAL_OPERATION_CONSTANT_TIME_COMPARE),
            300 => Some(Self::SECRET_MATERIAL_OPERATION_HASH),
            400 => Some(Self::SECRET_MATERIAL_OPERATION_MAC_AUTHENTICATE),
            410 => Some(Self::SECRET_MATERIAL_OPERATION_MAC_VERIFY),
            500 => Some(Self::SECRET_MATERIAL_OPERATION_KEY_DERIVATION),
            600 => Some(Self::SECRET_MATERIAL_OPERATION_KEY_WRAP),
            610 => Some(Self::SECRET_MATERIAL_OPERATION_KEY_UNWRAP),
            700 => Some(Self::SECRET_MATERIAL_OPERATION_SIGNATURE_KEY_GENERATION),
            710 => Some(Self::SECRET_MATERIAL_OPERATION_SIGNATURE_KEY_DERIVATION),
            720 => Some(Self::SECRET_MATERIAL_OPERATION_SIGNATURE_SIGN),
            730 => Some(Self::SECRET_MATERIAL_OPERATION_SIGNATURE_VERIFY),
            740 => Some(Self::SECRET_MATERIAL_OPERATION_SIGNATURE_ENCODING),
            800 => Some(Self::SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_KEY_GENERATION),
            810 => Some(Self::SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_KEY_DERIVATION),
            820 => Some(Self::SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_SHARED_SECRET),
            900 => Some(Self::SECRET_MATERIAL_OPERATION_KEM_KEY_GENERATION),
            910 => Some(Self::SECRET_MATERIAL_OPERATION_KEM_KEY_DERIVATION),
            920 => Some(Self::SECRET_MATERIAL_OPERATION_KEM_ENCAPSULATE),
            930 => Some(Self::SECRET_MATERIAL_OPERATION_KEM_DECAPSULATE),
            1000 => Some(Self::SECRET_MATERIAL_OPERATION_HPKE_KEY_GENERATION),
            1010 => Some(Self::SECRET_MATERIAL_OPERATION_HPKE_KEY_DERIVATION),
            1020 => Some(Self::SECRET_MATERIAL_OPERATION_HPKE_SENDER_SETUP),
            1030 => Some(Self::SECRET_MATERIAL_OPERATION_HPKE_RECEIVER_SETUP),
            1040 => Some(Self::SECRET_MATERIAL_OPERATION_HPKE_SEAL),
            1050 => Some(Self::SECRET_MATERIAL_OPERATION_HPKE_OPEN),
            1060 => Some(Self::SECRET_MATERIAL_OPERATION_HPKE_EXPORT),
            1100 => Some(Self::SECRET_MATERIAL_OPERATION_RANDOM_FILL),
            1110 => Some(Self::SECRET_MATERIAL_OPERATION_RANDOM_NONCE),
            1120 => Some(Self::SECRET_MATERIAL_OPERATION_RANDOM_SALT),
            1200 => Some(Self::SECRET_MATERIAL_OPERATION_PUBLIC_KEY_ENCODING),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::SECRET_MATERIAL_OPERATION_UNSPECIFIED => "SECRET_MATERIAL_OPERATION_UNSPECIFIED",
            Self::SECRET_MATERIAL_OPERATION_AEAD_SEAL => "SECRET_MATERIAL_OPERATION_AEAD_SEAL",
            Self::SECRET_MATERIAL_OPERATION_AEAD_OPEN => "SECRET_MATERIAL_OPERATION_AEAD_OPEN",
            Self::SECRET_MATERIAL_OPERATION_CONSTANT_TIME_COMPARE => {
                "SECRET_MATERIAL_OPERATION_CONSTANT_TIME_COMPARE"
            }
            Self::SECRET_MATERIAL_OPERATION_HASH => "SECRET_MATERIAL_OPERATION_HASH",
            Self::SECRET_MATERIAL_OPERATION_MAC_AUTHENTICATE => {
                "SECRET_MATERIAL_OPERATION_MAC_AUTHENTICATE"
            }
            Self::SECRET_MATERIAL_OPERATION_MAC_VERIFY => "SECRET_MATERIAL_OPERATION_MAC_VERIFY",
            Self::SECRET_MATERIAL_OPERATION_KEY_DERIVATION => {
                "SECRET_MATERIAL_OPERATION_KEY_DERIVATION"
            }
            Self::SECRET_MATERIAL_OPERATION_KEY_WRAP => "SECRET_MATERIAL_OPERATION_KEY_WRAP",
            Self::SECRET_MATERIAL_OPERATION_KEY_UNWRAP => "SECRET_MATERIAL_OPERATION_KEY_UNWRAP",
            Self::SECRET_MATERIAL_OPERATION_SIGNATURE_KEY_GENERATION => {
                "SECRET_MATERIAL_OPERATION_SIGNATURE_KEY_GENERATION"
            }
            Self::SECRET_MATERIAL_OPERATION_SIGNATURE_KEY_DERIVATION => {
                "SECRET_MATERIAL_OPERATION_SIGNATURE_KEY_DERIVATION"
            }
            Self::SECRET_MATERIAL_OPERATION_SIGNATURE_SIGN => {
                "SECRET_MATERIAL_OPERATION_SIGNATURE_SIGN"
            }
            Self::SECRET_MATERIAL_OPERATION_SIGNATURE_VERIFY => {
                "SECRET_MATERIAL_OPERATION_SIGNATURE_VERIFY"
            }
            Self::SECRET_MATERIAL_OPERATION_SIGNATURE_ENCODING => {
                "SECRET_MATERIAL_OPERATION_SIGNATURE_ENCODING"
            }
            Self::SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_KEY_GENERATION => {
                "SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_KEY_GENERATION"
            }
            Self::SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_KEY_DERIVATION => {
                "SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_KEY_DERIVATION"
            }
            Self::SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_SHARED_SECRET => {
                "SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_SHARED_SECRET"
            }
            Self::SECRET_MATERIAL_OPERATION_KEM_KEY_GENERATION => {
                "SECRET_MATERIAL_OPERATION_KEM_KEY_GENERATION"
            }
            Self::SECRET_MATERIAL_OPERATION_KEM_KEY_DERIVATION => {
                "SECRET_MATERIAL_OPERATION_KEM_KEY_DERIVATION"
            }
            Self::SECRET_MATERIAL_OPERATION_KEM_ENCAPSULATE => {
                "SECRET_MATERIAL_OPERATION_KEM_ENCAPSULATE"
            }
            Self::SECRET_MATERIAL_OPERATION_KEM_DECAPSULATE => {
                "SECRET_MATERIAL_OPERATION_KEM_DECAPSULATE"
            }
            Self::SECRET_MATERIAL_OPERATION_HPKE_KEY_GENERATION => {
                "SECRET_MATERIAL_OPERATION_HPKE_KEY_GENERATION"
            }
            Self::SECRET_MATERIAL_OPERATION_HPKE_KEY_DERIVATION => {
                "SECRET_MATERIAL_OPERATION_HPKE_KEY_DERIVATION"
            }
            Self::SECRET_MATERIAL_OPERATION_HPKE_SENDER_SETUP => {
                "SECRET_MATERIAL_OPERATION_HPKE_SENDER_SETUP"
            }
            Self::SECRET_MATERIAL_OPERATION_HPKE_RECEIVER_SETUP => {
                "SECRET_MATERIAL_OPERATION_HPKE_RECEIVER_SETUP"
            }
            Self::SECRET_MATERIAL_OPERATION_HPKE_SEAL => "SECRET_MATERIAL_OPERATION_HPKE_SEAL",
            Self::SECRET_MATERIAL_OPERATION_HPKE_OPEN => "SECRET_MATERIAL_OPERATION_HPKE_OPEN",
            Self::SECRET_MATERIAL_OPERATION_HPKE_EXPORT => "SECRET_MATERIAL_OPERATION_HPKE_EXPORT",
            Self::SECRET_MATERIAL_OPERATION_RANDOM_FILL => "SECRET_MATERIAL_OPERATION_RANDOM_FILL",
            Self::SECRET_MATERIAL_OPERATION_RANDOM_NONCE => {
                "SECRET_MATERIAL_OPERATION_RANDOM_NONCE"
            }
            Self::SECRET_MATERIAL_OPERATION_RANDOM_SALT => "SECRET_MATERIAL_OPERATION_RANDOM_SALT",
            Self::SECRET_MATERIAL_OPERATION_PUBLIC_KEY_ENCODING => {
                "SECRET_MATERIAL_OPERATION_PUBLIC_KEY_ENCODING"
            }
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "SECRET_MATERIAL_OPERATION_UNSPECIFIED" => {
                Some(Self::SECRET_MATERIAL_OPERATION_UNSPECIFIED)
            }
            "SECRET_MATERIAL_OPERATION_AEAD_SEAL" => {
                Some(Self::SECRET_MATERIAL_OPERATION_AEAD_SEAL)
            }
            "SECRET_MATERIAL_OPERATION_AEAD_OPEN" => {
                Some(Self::SECRET_MATERIAL_OPERATION_AEAD_OPEN)
            }
            "SECRET_MATERIAL_OPERATION_CONSTANT_TIME_COMPARE" => {
                Some(Self::SECRET_MATERIAL_OPERATION_CONSTANT_TIME_COMPARE)
            }
            "SECRET_MATERIAL_OPERATION_HASH" => Some(Self::SECRET_MATERIAL_OPERATION_HASH),
            "SECRET_MATERIAL_OPERATION_MAC_AUTHENTICATE" => {
                Some(Self::SECRET_MATERIAL_OPERATION_MAC_AUTHENTICATE)
            }
            "SECRET_MATERIAL_OPERATION_MAC_VERIFY" => {
                Some(Self::SECRET_MATERIAL_OPERATION_MAC_VERIFY)
            }
            "SECRET_MATERIAL_OPERATION_KEY_DERIVATION" => {
                Some(Self::SECRET_MATERIAL_OPERATION_KEY_DERIVATION)
            }
            "SECRET_MATERIAL_OPERATION_KEY_WRAP" => Some(Self::SECRET_MATERIAL_OPERATION_KEY_WRAP),
            "SECRET_MATERIAL_OPERATION_KEY_UNWRAP" => {
                Some(Self::SECRET_MATERIAL_OPERATION_KEY_UNWRAP)
            }
            "SECRET_MATERIAL_OPERATION_SIGNATURE_KEY_GENERATION" => {
                Some(Self::SECRET_MATERIAL_OPERATION_SIGNATURE_KEY_GENERATION)
            }
            "SECRET_MATERIAL_OPERATION_SIGNATURE_KEY_DERIVATION" => {
                Some(Self::SECRET_MATERIAL_OPERATION_SIGNATURE_KEY_DERIVATION)
            }
            "SECRET_MATERIAL_OPERATION_SIGNATURE_SIGN" => {
                Some(Self::SECRET_MATERIAL_OPERATION_SIGNATURE_SIGN)
            }
            "SECRET_MATERIAL_OPERATION_SIGNATURE_VERIFY" => {
                Some(Self::SECRET_MATERIAL_OPERATION_SIGNATURE_VERIFY)
            }
            "SECRET_MATERIAL_OPERATION_SIGNATURE_ENCODING" => {
                Some(Self::SECRET_MATERIAL_OPERATION_SIGNATURE_ENCODING)
            }
            "SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_KEY_GENERATION" => {
                Some(Self::SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_KEY_GENERATION)
            }
            "SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_KEY_DERIVATION" => {
                Some(Self::SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_KEY_DERIVATION)
            }
            "SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_SHARED_SECRET" => {
                Some(Self::SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_SHARED_SECRET)
            }
            "SECRET_MATERIAL_OPERATION_KEM_KEY_GENERATION" => {
                Some(Self::SECRET_MATERIAL_OPERATION_KEM_KEY_GENERATION)
            }
            "SECRET_MATERIAL_OPERATION_KEM_KEY_DERIVATION" => {
                Some(Self::SECRET_MATERIAL_OPERATION_KEM_KEY_DERIVATION)
            }
            "SECRET_MATERIAL_OPERATION_KEM_ENCAPSULATE" => {
                Some(Self::SECRET_MATERIAL_OPERATION_KEM_ENCAPSULATE)
            }
            "SECRET_MATERIAL_OPERATION_KEM_DECAPSULATE" => {
                Some(Self::SECRET_MATERIAL_OPERATION_KEM_DECAPSULATE)
            }
            "SECRET_MATERIAL_OPERATION_HPKE_KEY_GENERATION" => {
                Some(Self::SECRET_MATERIAL_OPERATION_HPKE_KEY_GENERATION)
            }
            "SECRET_MATERIAL_OPERATION_HPKE_KEY_DERIVATION" => {
                Some(Self::SECRET_MATERIAL_OPERATION_HPKE_KEY_DERIVATION)
            }
            "SECRET_MATERIAL_OPERATION_HPKE_SENDER_SETUP" => {
                Some(Self::SECRET_MATERIAL_OPERATION_HPKE_SENDER_SETUP)
            }
            "SECRET_MATERIAL_OPERATION_HPKE_RECEIVER_SETUP" => {
                Some(Self::SECRET_MATERIAL_OPERATION_HPKE_RECEIVER_SETUP)
            }
            "SECRET_MATERIAL_OPERATION_HPKE_SEAL" => {
                Some(Self::SECRET_MATERIAL_OPERATION_HPKE_SEAL)
            }
            "SECRET_MATERIAL_OPERATION_HPKE_OPEN" => {
                Some(Self::SECRET_MATERIAL_OPERATION_HPKE_OPEN)
            }
            "SECRET_MATERIAL_OPERATION_HPKE_EXPORT" => {
                Some(Self::SECRET_MATERIAL_OPERATION_HPKE_EXPORT)
            }
            "SECRET_MATERIAL_OPERATION_RANDOM_FILL" => {
                Some(Self::SECRET_MATERIAL_OPERATION_RANDOM_FILL)
            }
            "SECRET_MATERIAL_OPERATION_RANDOM_NONCE" => {
                Some(Self::SECRET_MATERIAL_OPERATION_RANDOM_NONCE)
            }
            "SECRET_MATERIAL_OPERATION_RANDOM_SALT" => {
                Some(Self::SECRET_MATERIAL_OPERATION_RANDOM_SALT)
            }
            "SECRET_MATERIAL_OPERATION_PUBLIC_KEY_ENCODING" => {
                Some(Self::SECRET_MATERIAL_OPERATION_PUBLIC_KEY_ENCODING)
            }
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::SECRET_MATERIAL_OPERATION_UNSPECIFIED,
            Self::SECRET_MATERIAL_OPERATION_AEAD_SEAL,
            Self::SECRET_MATERIAL_OPERATION_AEAD_OPEN,
            Self::SECRET_MATERIAL_OPERATION_CONSTANT_TIME_COMPARE,
            Self::SECRET_MATERIAL_OPERATION_HASH,
            Self::SECRET_MATERIAL_OPERATION_MAC_AUTHENTICATE,
            Self::SECRET_MATERIAL_OPERATION_MAC_VERIFY,
            Self::SECRET_MATERIAL_OPERATION_KEY_DERIVATION,
            Self::SECRET_MATERIAL_OPERATION_KEY_WRAP,
            Self::SECRET_MATERIAL_OPERATION_KEY_UNWRAP,
            Self::SECRET_MATERIAL_OPERATION_SIGNATURE_KEY_GENERATION,
            Self::SECRET_MATERIAL_OPERATION_SIGNATURE_KEY_DERIVATION,
            Self::SECRET_MATERIAL_OPERATION_SIGNATURE_SIGN,
            Self::SECRET_MATERIAL_OPERATION_SIGNATURE_VERIFY,
            Self::SECRET_MATERIAL_OPERATION_SIGNATURE_ENCODING,
            Self::SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_KEY_GENERATION,
            Self::SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_KEY_DERIVATION,
            Self::SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_SHARED_SECRET,
            Self::SECRET_MATERIAL_OPERATION_KEM_KEY_GENERATION,
            Self::SECRET_MATERIAL_OPERATION_KEM_KEY_DERIVATION,
            Self::SECRET_MATERIAL_OPERATION_KEM_ENCAPSULATE,
            Self::SECRET_MATERIAL_OPERATION_KEM_DECAPSULATE,
            Self::SECRET_MATERIAL_OPERATION_HPKE_KEY_GENERATION,
            Self::SECRET_MATERIAL_OPERATION_HPKE_KEY_DERIVATION,
            Self::SECRET_MATERIAL_OPERATION_HPKE_SENDER_SETUP,
            Self::SECRET_MATERIAL_OPERATION_HPKE_RECEIVER_SETUP,
            Self::SECRET_MATERIAL_OPERATION_HPKE_SEAL,
            Self::SECRET_MATERIAL_OPERATION_HPKE_OPEN,
            Self::SECRET_MATERIAL_OPERATION_HPKE_EXPORT,
            Self::SECRET_MATERIAL_OPERATION_RANDOM_FILL,
            Self::SECRET_MATERIAL_OPERATION_RANDOM_NONCE,
            Self::SECRET_MATERIAL_OPERATION_RANDOM_SALT,
            Self::SECRET_MATERIAL_OPERATION_PUBLIC_KEY_ENCODING,
        ]
    }
}
impl ::zeroize::Zeroize for SecretMaterialOperation {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for SecretMaterialOperation {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for SecretMaterialOperation {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for SecretMaterialOperation {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.RngOutputKind`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum RngOutputKind {
    /// `RNG_OUTPUT_KIND_UNSPECIFIED`.
    #[default]
    RNG_OUTPUT_KIND_UNSPECIFIED = 0,
    /// `RNG_OUTPUT_KIND_GENERIC`.
    RNG_OUTPUT_KIND_GENERIC = 100,
    /// `RNG_OUTPUT_KIND_AEAD_NONCE_12`.
    RNG_OUTPUT_KIND_AEAD_NONCE_12 = 200,
    /// `RNG_OUTPUT_KIND_ARGON2_SALT_16`.
    RNG_OUTPUT_KIND_ARGON2_SALT_16 = 300,
    /// `RNG_OUTPUT_KIND_ARGON2_SALT_32`.
    RNG_OUTPUT_KIND_ARGON2_SALT_32 = 310,
    /// `RNG_OUTPUT_KIND_AES_256_GCM_KEY`.
    RNG_OUTPUT_KIND_AES_256_GCM_KEY = 400,
    /// `RNG_OUTPUT_KIND_ML_KEM_1024_SEED`.
    RNG_OUTPUT_KIND_ML_KEM_1024_SEED = 1000,
    /// `RNG_OUTPUT_KIND_ML_DSA_87_SEED`.
    RNG_OUTPUT_KIND_ML_DSA_87_SEED = 1100,
    /// `RNG_OUTPUT_KIND_ED25519_SEED`.
    RNG_OUTPUT_KIND_ED25519_SEED = 500,
    /// `RNG_OUTPUT_KIND_SLH_DSA_SHA2_128S_SEED`.
    RNG_OUTPUT_KIND_SLH_DSA_SHA2_128S_SEED = 1110,
}
impl RngOutputKind {
    /// Idiomatic alias for [`Self::RNG_OUTPUT_KIND_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::RNG_OUTPUT_KIND_UNSPECIFIED;
    /// Idiomatic alias for [`Self::RNG_OUTPUT_KIND_GENERIC`].
    #[allow(non_upper_case_globals)]
    pub const Generic: Self = Self::RNG_OUTPUT_KIND_GENERIC;
    /// Idiomatic alias for [`Self::RNG_OUTPUT_KIND_AEAD_NONCE_12`].
    #[allow(non_upper_case_globals)]
    pub const AeadNonce12: Self = Self::RNG_OUTPUT_KIND_AEAD_NONCE_12;
    /// Idiomatic alias for [`Self::RNG_OUTPUT_KIND_ARGON2_SALT_16`].
    #[allow(non_upper_case_globals)]
    pub const Argon2Salt16: Self = Self::RNG_OUTPUT_KIND_ARGON2_SALT_16;
    /// Idiomatic alias for [`Self::RNG_OUTPUT_KIND_ARGON2_SALT_32`].
    #[allow(non_upper_case_globals)]
    pub const Argon2Salt32: Self = Self::RNG_OUTPUT_KIND_ARGON2_SALT_32;
    /// Idiomatic alias for [`Self::RNG_OUTPUT_KIND_AES_256_GCM_KEY`].
    #[allow(non_upper_case_globals)]
    pub const Aes256GcmKey: Self = Self::RNG_OUTPUT_KIND_AES_256_GCM_KEY;
    /// Idiomatic alias for [`Self::RNG_OUTPUT_KIND_ML_KEM_1024_SEED`].
    #[allow(non_upper_case_globals)]
    pub const MlKem1024Seed: Self = Self::RNG_OUTPUT_KIND_ML_KEM_1024_SEED;
    /// Idiomatic alias for [`Self::RNG_OUTPUT_KIND_ML_DSA_87_SEED`].
    #[allow(non_upper_case_globals)]
    pub const MlDsa87Seed: Self = Self::RNG_OUTPUT_KIND_ML_DSA_87_SEED;
    /// Idiomatic alias for [`Self::RNG_OUTPUT_KIND_ED25519_SEED`].
    #[allow(non_upper_case_globals)]
    pub const Ed25519Seed: Self = Self::RNG_OUTPUT_KIND_ED25519_SEED;
    /// Idiomatic alias for [`Self::RNG_OUTPUT_KIND_SLH_DSA_SHA2_128S_SEED`].
    #[allow(non_upper_case_globals)]
    pub const SlhDsaSha2128sSeed: Self = Self::RNG_OUTPUT_KIND_SLH_DSA_SHA2_128S_SEED;
}
impl ::buffa::Enumeration for RngOutputKind {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::RNG_OUTPUT_KIND_UNSPECIFIED),
            100 => Some(Self::RNG_OUTPUT_KIND_GENERIC),
            200 => Some(Self::RNG_OUTPUT_KIND_AEAD_NONCE_12),
            300 => Some(Self::RNG_OUTPUT_KIND_ARGON2_SALT_16),
            310 => Some(Self::RNG_OUTPUT_KIND_ARGON2_SALT_32),
            400 => Some(Self::RNG_OUTPUT_KIND_AES_256_GCM_KEY),
            1000 => Some(Self::RNG_OUTPUT_KIND_ML_KEM_1024_SEED),
            1100 => Some(Self::RNG_OUTPUT_KIND_ML_DSA_87_SEED),
            500 => Some(Self::RNG_OUTPUT_KIND_ED25519_SEED),
            1110 => Some(Self::RNG_OUTPUT_KIND_SLH_DSA_SHA2_128S_SEED),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::RNG_OUTPUT_KIND_UNSPECIFIED => "RNG_OUTPUT_KIND_UNSPECIFIED",
            Self::RNG_OUTPUT_KIND_GENERIC => "RNG_OUTPUT_KIND_GENERIC",
            Self::RNG_OUTPUT_KIND_AEAD_NONCE_12 => "RNG_OUTPUT_KIND_AEAD_NONCE_12",
            Self::RNG_OUTPUT_KIND_ARGON2_SALT_16 => "RNG_OUTPUT_KIND_ARGON2_SALT_16",
            Self::RNG_OUTPUT_KIND_ARGON2_SALT_32 => "RNG_OUTPUT_KIND_ARGON2_SALT_32",
            Self::RNG_OUTPUT_KIND_AES_256_GCM_KEY => "RNG_OUTPUT_KIND_AES_256_GCM_KEY",
            Self::RNG_OUTPUT_KIND_ML_KEM_1024_SEED => "RNG_OUTPUT_KIND_ML_KEM_1024_SEED",
            Self::RNG_OUTPUT_KIND_ML_DSA_87_SEED => "RNG_OUTPUT_KIND_ML_DSA_87_SEED",
            Self::RNG_OUTPUT_KIND_ED25519_SEED => "RNG_OUTPUT_KIND_ED25519_SEED",
            Self::RNG_OUTPUT_KIND_SLH_DSA_SHA2_128S_SEED => {
                "RNG_OUTPUT_KIND_SLH_DSA_SHA2_128S_SEED"
            }
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "RNG_OUTPUT_KIND_UNSPECIFIED" => Some(Self::RNG_OUTPUT_KIND_UNSPECIFIED),
            "RNG_OUTPUT_KIND_GENERIC" => Some(Self::RNG_OUTPUT_KIND_GENERIC),
            "RNG_OUTPUT_KIND_AEAD_NONCE_12" => Some(Self::RNG_OUTPUT_KIND_AEAD_NONCE_12),
            "RNG_OUTPUT_KIND_ARGON2_SALT_16" => Some(Self::RNG_OUTPUT_KIND_ARGON2_SALT_16),
            "RNG_OUTPUT_KIND_ARGON2_SALT_32" => Some(Self::RNG_OUTPUT_KIND_ARGON2_SALT_32),
            "RNG_OUTPUT_KIND_AES_256_GCM_KEY" => Some(Self::RNG_OUTPUT_KIND_AES_256_GCM_KEY),
            "RNG_OUTPUT_KIND_ML_KEM_1024_SEED" => Some(Self::RNG_OUTPUT_KIND_ML_KEM_1024_SEED),
            "RNG_OUTPUT_KIND_ML_DSA_87_SEED" => Some(Self::RNG_OUTPUT_KIND_ML_DSA_87_SEED),
            "RNG_OUTPUT_KIND_ED25519_SEED" => Some(Self::RNG_OUTPUT_KIND_ED25519_SEED),
            "RNG_OUTPUT_KIND_SLH_DSA_SHA2_128S_SEED" => {
                Some(Self::RNG_OUTPUT_KIND_SLH_DSA_SHA2_128S_SEED)
            }
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::RNG_OUTPUT_KIND_UNSPECIFIED,
            Self::RNG_OUTPUT_KIND_GENERIC,
            Self::RNG_OUTPUT_KIND_AEAD_NONCE_12,
            Self::RNG_OUTPUT_KIND_ARGON2_SALT_16,
            Self::RNG_OUTPUT_KIND_ARGON2_SALT_32,
            Self::RNG_OUTPUT_KIND_AES_256_GCM_KEY,
            Self::RNG_OUTPUT_KIND_ML_KEM_1024_SEED,
            Self::RNG_OUTPUT_KIND_ML_DSA_87_SEED,
            Self::RNG_OUTPUT_KIND_ED25519_SEED,
            Self::RNG_OUTPUT_KIND_SLH_DSA_SHA2_128S_SEED,
        ]
    }
}
impl ::zeroize::Zeroize for RngOutputKind {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for RngOutputKind {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for RngOutputKind {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for RngOutputKind {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.PlatformKeyOperation`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum PlatformKeyOperation {
    /// `PLATFORM_KEY_OPERATION_UNSPECIFIED`.
    #[default]
    PLATFORM_KEY_OPERATION_UNSPECIFIED = 0,
    /// `PLATFORM_KEY_OPERATION_GENERATE`.
    PLATFORM_KEY_OPERATION_GENERATE = 100,
    /// `PLATFORM_KEY_OPERATION_GET_PUBLIC_KEY`.
    PLATFORM_KEY_OPERATION_GET_PUBLIC_KEY = 110,
    /// `PLATFORM_KEY_OPERATION_SIGN`.
    PLATFORM_KEY_OPERATION_SIGN = 200,
    /// `PLATFORM_KEY_OPERATION_VERIFY`.
    PLATFORM_KEY_OPERATION_VERIFY = 210,
    /// `PLATFORM_KEY_OPERATION_DERIVE_SHARED_SECRET`.
    PLATFORM_KEY_OPERATION_DERIVE_SHARED_SECRET = 300,
    /// `PLATFORM_KEY_OPERATION_DELETE`.
    PLATFORM_KEY_OPERATION_DELETE = 120,
    /// `PLATFORM_KEY_OPERATION_ATTEST`.
    PLATFORM_KEY_OPERATION_ATTEST = 400,
}
impl PlatformKeyOperation {
    /// Idiomatic alias for [`Self::PLATFORM_KEY_OPERATION_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::PLATFORM_KEY_OPERATION_UNSPECIFIED;
    /// Idiomatic alias for [`Self::PLATFORM_KEY_OPERATION_GENERATE`].
    #[allow(non_upper_case_globals)]
    pub const Generate: Self = Self::PLATFORM_KEY_OPERATION_GENERATE;
    /// Idiomatic alias for [`Self::PLATFORM_KEY_OPERATION_GET_PUBLIC_KEY`].
    #[allow(non_upper_case_globals)]
    pub const GetPublicKey: Self = Self::PLATFORM_KEY_OPERATION_GET_PUBLIC_KEY;
    /// Idiomatic alias for [`Self::PLATFORM_KEY_OPERATION_SIGN`].
    #[allow(non_upper_case_globals)]
    pub const Sign: Self = Self::PLATFORM_KEY_OPERATION_SIGN;
    /// Idiomatic alias for [`Self::PLATFORM_KEY_OPERATION_VERIFY`].
    #[allow(non_upper_case_globals)]
    pub const Verify: Self = Self::PLATFORM_KEY_OPERATION_VERIFY;
    /// Idiomatic alias for [`Self::PLATFORM_KEY_OPERATION_DERIVE_SHARED_SECRET`].
    #[allow(non_upper_case_globals)]
    pub const DeriveSharedSecret: Self = Self::PLATFORM_KEY_OPERATION_DERIVE_SHARED_SECRET;
    /// Idiomatic alias for [`Self::PLATFORM_KEY_OPERATION_DELETE`].
    #[allow(non_upper_case_globals)]
    pub const Delete: Self = Self::PLATFORM_KEY_OPERATION_DELETE;
    /// Idiomatic alias for [`Self::PLATFORM_KEY_OPERATION_ATTEST`].
    #[allow(non_upper_case_globals)]
    pub const Attest: Self = Self::PLATFORM_KEY_OPERATION_ATTEST;
}
impl ::buffa::Enumeration for PlatformKeyOperation {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::PLATFORM_KEY_OPERATION_UNSPECIFIED),
            100 => Some(Self::PLATFORM_KEY_OPERATION_GENERATE),
            110 => Some(Self::PLATFORM_KEY_OPERATION_GET_PUBLIC_KEY),
            200 => Some(Self::PLATFORM_KEY_OPERATION_SIGN),
            210 => Some(Self::PLATFORM_KEY_OPERATION_VERIFY),
            300 => Some(Self::PLATFORM_KEY_OPERATION_DERIVE_SHARED_SECRET),
            120 => Some(Self::PLATFORM_KEY_OPERATION_DELETE),
            400 => Some(Self::PLATFORM_KEY_OPERATION_ATTEST),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::PLATFORM_KEY_OPERATION_UNSPECIFIED => "PLATFORM_KEY_OPERATION_UNSPECIFIED",
            Self::PLATFORM_KEY_OPERATION_GENERATE => "PLATFORM_KEY_OPERATION_GENERATE",
            Self::PLATFORM_KEY_OPERATION_GET_PUBLIC_KEY => "PLATFORM_KEY_OPERATION_GET_PUBLIC_KEY",
            Self::PLATFORM_KEY_OPERATION_SIGN => "PLATFORM_KEY_OPERATION_SIGN",
            Self::PLATFORM_KEY_OPERATION_VERIFY => "PLATFORM_KEY_OPERATION_VERIFY",
            Self::PLATFORM_KEY_OPERATION_DERIVE_SHARED_SECRET => {
                "PLATFORM_KEY_OPERATION_DERIVE_SHARED_SECRET"
            }
            Self::PLATFORM_KEY_OPERATION_DELETE => "PLATFORM_KEY_OPERATION_DELETE",
            Self::PLATFORM_KEY_OPERATION_ATTEST => "PLATFORM_KEY_OPERATION_ATTEST",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "PLATFORM_KEY_OPERATION_UNSPECIFIED" => Some(Self::PLATFORM_KEY_OPERATION_UNSPECIFIED),
            "PLATFORM_KEY_OPERATION_GENERATE" => Some(Self::PLATFORM_KEY_OPERATION_GENERATE),
            "PLATFORM_KEY_OPERATION_GET_PUBLIC_KEY" => {
                Some(Self::PLATFORM_KEY_OPERATION_GET_PUBLIC_KEY)
            }
            "PLATFORM_KEY_OPERATION_SIGN" => Some(Self::PLATFORM_KEY_OPERATION_SIGN),
            "PLATFORM_KEY_OPERATION_VERIFY" => Some(Self::PLATFORM_KEY_OPERATION_VERIFY),
            "PLATFORM_KEY_OPERATION_DERIVE_SHARED_SECRET" => {
                Some(Self::PLATFORM_KEY_OPERATION_DERIVE_SHARED_SECRET)
            }
            "PLATFORM_KEY_OPERATION_DELETE" => Some(Self::PLATFORM_KEY_OPERATION_DELETE),
            "PLATFORM_KEY_OPERATION_ATTEST" => Some(Self::PLATFORM_KEY_OPERATION_ATTEST),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::PLATFORM_KEY_OPERATION_UNSPECIFIED,
            Self::PLATFORM_KEY_OPERATION_GENERATE,
            Self::PLATFORM_KEY_OPERATION_GET_PUBLIC_KEY,
            Self::PLATFORM_KEY_OPERATION_SIGN,
            Self::PLATFORM_KEY_OPERATION_VERIFY,
            Self::PLATFORM_KEY_OPERATION_DERIVE_SHARED_SECRET,
            Self::PLATFORM_KEY_OPERATION_DELETE,
            Self::PLATFORM_KEY_OPERATION_ATTEST,
        ]
    }
}
impl ::zeroize::Zeroize for PlatformKeyOperation {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for PlatformKeyOperation {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for PlatformKeyOperation {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for PlatformKeyOperation {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

impl ::buffa::Enumeration for CryptoErrorReason {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::CRYPTO_ERROR_REASON_UNSPECIFIED),
            100 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER),
            101 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH),
            102 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY),
            103 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PUBLIC_KEY),
            104 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PRIVATE_KEY),
            105 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_NONCE),
            106 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SALT),
            107 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PASSWORD),
            108 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_ENCODING),
            120 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SIGNATURE),
            121 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_VERIFICATION_FAILED),
            122 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED),
            123 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_CIPHERTEXT),
            124 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_TAG),
            125 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SHARED_SECRET),
            130 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF),
            131 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_JSON),
            132 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED),
            133 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_MISSING_OPERATION),
            200 => Some(Self::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM),
            201 => Some(Self::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_BACKEND),
            202 => Some(Self::CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE),
            203 => Some(Self::CRYPTO_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE),
            204 => Some(Self::CRYPTO_ERROR_REASON_PROVIDER_KEY_EXISTS),
            205 => Some(Self::CRYPTO_ERROR_REASON_PROVIDER_KEY_NOT_FOUND),
            206 => Some(Self::CRYPTO_ERROR_REASON_PROVIDER_ACCESS_DENIED),
            207 => Some(Self::CRYPTO_ERROR_REASON_PROVIDER_USER_AUTHENTICATION_REQUIRED),
            208 => Some(Self::CRYPTO_ERROR_REASON_PROVIDER_USER_CANCELED),
            209 => Some(Self::CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_UNAVAILABLE),
            210 => Some(Self::CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_REJECTED_KEY),
            300 => Some(Self::CRYPTO_ERROR_REASON_BACKEND_INVALID_STATE),
            301 => Some(Self::CRYPTO_ERROR_REASON_BACKEND_INTERNAL),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::CRYPTO_ERROR_REASON_UNSPECIFIED => "CRYPTO_ERROR_REASON_UNSPECIFIED",
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PUBLIC_KEY => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PUBLIC_KEY"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PRIVATE_KEY => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PRIVATE_KEY"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_NONCE => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_NONCE"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SALT => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SALT"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PASSWORD => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PASSWORD"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_ENCODING => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_ENCODING"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SIGNATURE => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SIGNATURE"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_VERIFICATION_FAILED => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_VERIFICATION_FAILED"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_CIPHERTEXT => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_CIPHERTEXT"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_TAG => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_TAG"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SHARED_SECRET => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SHARED_SECRET"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_JSON => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_JSON"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_MISSING_OPERATION => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_MISSING_OPERATION"
            }
            Self::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM => {
                "CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM"
            }
            Self::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_BACKEND => {
                "CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_BACKEND"
            }
            Self::CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE => {
                "CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE"
            }
            Self::CRYPTO_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE => {
                "CRYPTO_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE"
            }
            Self::CRYPTO_ERROR_REASON_PROVIDER_KEY_EXISTS => {
                "CRYPTO_ERROR_REASON_PROVIDER_KEY_EXISTS"
            }
            Self::CRYPTO_ERROR_REASON_PROVIDER_KEY_NOT_FOUND => {
                "CRYPTO_ERROR_REASON_PROVIDER_KEY_NOT_FOUND"
            }
            Self::CRYPTO_ERROR_REASON_PROVIDER_ACCESS_DENIED => {
                "CRYPTO_ERROR_REASON_PROVIDER_ACCESS_DENIED"
            }
            Self::CRYPTO_ERROR_REASON_PROVIDER_USER_AUTHENTICATION_REQUIRED => {
                "CRYPTO_ERROR_REASON_PROVIDER_USER_AUTHENTICATION_REQUIRED"
            }
            Self::CRYPTO_ERROR_REASON_PROVIDER_USER_CANCELED => {
                "CRYPTO_ERROR_REASON_PROVIDER_USER_CANCELED"
            }
            Self::CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_UNAVAILABLE => {
                "CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_UNAVAILABLE"
            }
            Self::CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_REJECTED_KEY => {
                "CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_REJECTED_KEY"
            }
            Self::CRYPTO_ERROR_REASON_BACKEND_INVALID_STATE => {
                "CRYPTO_ERROR_REASON_BACKEND_INVALID_STATE"
            }
            Self::CRYPTO_ERROR_REASON_BACKEND_INTERNAL => "CRYPTO_ERROR_REASON_BACKEND_INTERNAL",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "CRYPTO_ERROR_REASON_UNSPECIFIED" => Some(Self::CRYPTO_ERROR_REASON_UNSPECIFIED),
            "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER" => {
                Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER)
            }
            "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH" => {
                Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH)
            }
            "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY" => {
                Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY)
            }
            "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PUBLIC_KEY" => {
                Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PUBLIC_KEY)
            }
            "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PRIVATE_KEY" => {
                Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PRIVATE_KEY)
            }
            "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_NONCE" => {
                Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_NONCE)
            }
            "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SALT" => {
                Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SALT)
            }
            "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PASSWORD" => {
                Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PASSWORD)
            }
            "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_ENCODING" => {
                Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_ENCODING)
            }
            "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SIGNATURE" => {
                Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SIGNATURE)
            }
            "CRYPTO_ERROR_REASON_PRIMITIVE_VERIFICATION_FAILED" => {
                Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_VERIFICATION_FAILED)
            }
            "CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED" => {
                Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED)
            }
            "CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_CIPHERTEXT" => {
                Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_CIPHERTEXT)
            }
            "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_TAG" => {
                Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_TAG)
            }
            "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SHARED_SECRET" => {
                Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SHARED_SECRET)
            }
            "CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF" => {
                Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF)
            }
            "CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_JSON" => {
                Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_JSON)
            }
            "CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED" => {
                Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED)
            }
            "CRYPTO_ERROR_REASON_PRIMITIVE_MISSING_OPERATION" => {
                Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_MISSING_OPERATION)
            }
            "CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM" => {
                Some(Self::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM)
            }
            "CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_BACKEND" => {
                Some(Self::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_BACKEND)
            }
            "CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE" => {
                Some(Self::CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE)
            }
            "CRYPTO_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE" => {
                Some(Self::CRYPTO_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE)
            }
            "CRYPTO_ERROR_REASON_PROVIDER_KEY_EXISTS" => {
                Some(Self::CRYPTO_ERROR_REASON_PROVIDER_KEY_EXISTS)
            }
            "CRYPTO_ERROR_REASON_PROVIDER_KEY_NOT_FOUND" => {
                Some(Self::CRYPTO_ERROR_REASON_PROVIDER_KEY_NOT_FOUND)
            }
            "CRYPTO_ERROR_REASON_PROVIDER_ACCESS_DENIED" => {
                Some(Self::CRYPTO_ERROR_REASON_PROVIDER_ACCESS_DENIED)
            }
            "CRYPTO_ERROR_REASON_PROVIDER_USER_AUTHENTICATION_REQUIRED" => {
                Some(Self::CRYPTO_ERROR_REASON_PROVIDER_USER_AUTHENTICATION_REQUIRED)
            }
            "CRYPTO_ERROR_REASON_PROVIDER_USER_CANCELED" => {
                Some(Self::CRYPTO_ERROR_REASON_PROVIDER_USER_CANCELED)
            }
            "CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_UNAVAILABLE" => {
                Some(Self::CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_UNAVAILABLE)
            }
            "CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_REJECTED_KEY" => {
                Some(Self::CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_REJECTED_KEY)
            }
            "CRYPTO_ERROR_REASON_BACKEND_INVALID_STATE" => {
                Some(Self::CRYPTO_ERROR_REASON_BACKEND_INVALID_STATE)
            }
            "CRYPTO_ERROR_REASON_BACKEND_INTERNAL" => {
                Some(Self::CRYPTO_ERROR_REASON_BACKEND_INTERNAL)
            }
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::CRYPTO_ERROR_REASON_UNSPECIFIED,
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER,
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH,
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PUBLIC_KEY,
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PRIVATE_KEY,
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_NONCE,
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SALT,
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PASSWORD,
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_ENCODING,
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SIGNATURE,
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_VERIFICATION_FAILED,
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED,
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_CIPHERTEXT,
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_TAG,
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SHARED_SECRET,
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF,
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_JSON,
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED,
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_MISSING_OPERATION,
            Self::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM,
            Self::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_BACKEND,
            Self::CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE,
            Self::CRYPTO_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE,
            Self::CRYPTO_ERROR_REASON_PROVIDER_KEY_EXISTS,
            Self::CRYPTO_ERROR_REASON_PROVIDER_KEY_NOT_FOUND,
            Self::CRYPTO_ERROR_REASON_PROVIDER_ACCESS_DENIED,
            Self::CRYPTO_ERROR_REASON_PROVIDER_USER_AUTHENTICATION_REQUIRED,
            Self::CRYPTO_ERROR_REASON_PROVIDER_USER_CANCELED,
            Self::CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_UNAVAILABLE,
            Self::CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_REJECTED_KEY,
            Self::CRYPTO_ERROR_REASON_BACKEND_INVALID_STATE,
            Self::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ]
    }
}
impl ::zeroize::Zeroize for CryptoErrorReason {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for CryptoErrorReason {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for CryptoErrorReason {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for CryptoErrorReason {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.CryptoAlgorithmFamily`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum CryptoAlgorithmFamily {
    /// `CRYPTO_ALGORITHM_FAMILY_UNSPECIFIED`.
    #[default]
    CRYPTO_ALGORITHM_FAMILY_UNSPECIFIED = 0,
    /// `CRYPTO_ALGORITHM_FAMILY_SIGNATURE`.
    CRYPTO_ALGORITHM_FAMILY_SIGNATURE = 1,
    /// `CRYPTO_ALGORITHM_FAMILY_KEY_AGREEMENT`.
    CRYPTO_ALGORITHM_FAMILY_KEY_AGREEMENT = 2,
    /// `CRYPTO_ALGORITHM_FAMILY_KEM`.
    CRYPTO_ALGORITHM_FAMILY_KEM = 3,
    /// `CRYPTO_ALGORITHM_FAMILY_AEAD`.
    CRYPTO_ALGORITHM_FAMILY_AEAD = 4,
    /// `CRYPTO_ALGORITHM_FAMILY_HASH`.
    CRYPTO_ALGORITHM_FAMILY_HASH = 5,
    /// `CRYPTO_ALGORITHM_FAMILY_MAC`.
    CRYPTO_ALGORITHM_FAMILY_MAC = 6,
    /// `CRYPTO_ALGORITHM_FAMILY_KDF`.
    CRYPTO_ALGORITHM_FAMILY_KDF = 7,
    /// `CRYPTO_ALGORITHM_FAMILY_KEY_WRAP`.
    CRYPTO_ALGORITHM_FAMILY_KEY_WRAP = 8,
    /// `CRYPTO_ALGORITHM_FAMILY_HPKE`.
    CRYPTO_ALGORITHM_FAMILY_HPKE = 9,
    /// `CRYPTO_ALGORITHM_FAMILY_CONSTANT_TIME`.
    CRYPTO_ALGORITHM_FAMILY_CONSTANT_TIME = 10,
    /// `CRYPTO_ALGORITHM_FAMILY_PLATFORM_KEY`.
    CRYPTO_ALGORITHM_FAMILY_PLATFORM_KEY = 11,
}
impl CryptoAlgorithmFamily {
    /// Idiomatic alias for [`Self::CRYPTO_ALGORITHM_FAMILY_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::CRYPTO_ALGORITHM_FAMILY_UNSPECIFIED;
    /// Idiomatic alias for [`Self::CRYPTO_ALGORITHM_FAMILY_SIGNATURE`].
    #[allow(non_upper_case_globals)]
    pub const Signature: Self = Self::CRYPTO_ALGORITHM_FAMILY_SIGNATURE;
    /// Idiomatic alias for [`Self::CRYPTO_ALGORITHM_FAMILY_KEY_AGREEMENT`].
    #[allow(non_upper_case_globals)]
    pub const KeyAgreement: Self = Self::CRYPTO_ALGORITHM_FAMILY_KEY_AGREEMENT;
    /// Idiomatic alias for [`Self::CRYPTO_ALGORITHM_FAMILY_KEM`].
    #[allow(non_upper_case_globals)]
    pub const Kem: Self = Self::CRYPTO_ALGORITHM_FAMILY_KEM;
    /// Idiomatic alias for [`Self::CRYPTO_ALGORITHM_FAMILY_AEAD`].
    #[allow(non_upper_case_globals)]
    pub const Aead: Self = Self::CRYPTO_ALGORITHM_FAMILY_AEAD;
    /// Idiomatic alias for [`Self::CRYPTO_ALGORITHM_FAMILY_HASH`].
    #[allow(non_upper_case_globals)]
    pub const Hash: Self = Self::CRYPTO_ALGORITHM_FAMILY_HASH;
    /// Idiomatic alias for [`Self::CRYPTO_ALGORITHM_FAMILY_MAC`].
    #[allow(non_upper_case_globals)]
    pub const Mac: Self = Self::CRYPTO_ALGORITHM_FAMILY_MAC;
    /// Idiomatic alias for [`Self::CRYPTO_ALGORITHM_FAMILY_KDF`].
    #[allow(non_upper_case_globals)]
    pub const Kdf: Self = Self::CRYPTO_ALGORITHM_FAMILY_KDF;
    /// Idiomatic alias for [`Self::CRYPTO_ALGORITHM_FAMILY_KEY_WRAP`].
    #[allow(non_upper_case_globals)]
    pub const KeyWrap: Self = Self::CRYPTO_ALGORITHM_FAMILY_KEY_WRAP;
    /// Idiomatic alias for [`Self::CRYPTO_ALGORITHM_FAMILY_HPKE`].
    #[allow(non_upper_case_globals)]
    pub const Hpke: Self = Self::CRYPTO_ALGORITHM_FAMILY_HPKE;
    /// Idiomatic alias for [`Self::CRYPTO_ALGORITHM_FAMILY_CONSTANT_TIME`].
    #[allow(non_upper_case_globals)]
    pub const ConstantTime: Self = Self::CRYPTO_ALGORITHM_FAMILY_CONSTANT_TIME;
    /// Idiomatic alias for [`Self::CRYPTO_ALGORITHM_FAMILY_PLATFORM_KEY`].
    #[allow(non_upper_case_globals)]
    pub const PlatformKey: Self = Self::CRYPTO_ALGORITHM_FAMILY_PLATFORM_KEY;
}
impl ::buffa::Enumeration for CryptoAlgorithmFamily {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::CRYPTO_ALGORITHM_FAMILY_UNSPECIFIED),
            1 => Some(Self::CRYPTO_ALGORITHM_FAMILY_SIGNATURE),
            2 => Some(Self::CRYPTO_ALGORITHM_FAMILY_KEY_AGREEMENT),
            3 => Some(Self::CRYPTO_ALGORITHM_FAMILY_KEM),
            4 => Some(Self::CRYPTO_ALGORITHM_FAMILY_AEAD),
            5 => Some(Self::CRYPTO_ALGORITHM_FAMILY_HASH),
            6 => Some(Self::CRYPTO_ALGORITHM_FAMILY_MAC),
            7 => Some(Self::CRYPTO_ALGORITHM_FAMILY_KDF),
            8 => Some(Self::CRYPTO_ALGORITHM_FAMILY_KEY_WRAP),
            9 => Some(Self::CRYPTO_ALGORITHM_FAMILY_HPKE),
            10 => Some(Self::CRYPTO_ALGORITHM_FAMILY_CONSTANT_TIME),
            11 => Some(Self::CRYPTO_ALGORITHM_FAMILY_PLATFORM_KEY),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::CRYPTO_ALGORITHM_FAMILY_UNSPECIFIED => "CRYPTO_ALGORITHM_FAMILY_UNSPECIFIED",
            Self::CRYPTO_ALGORITHM_FAMILY_SIGNATURE => "CRYPTO_ALGORITHM_FAMILY_SIGNATURE",
            Self::CRYPTO_ALGORITHM_FAMILY_KEY_AGREEMENT => "CRYPTO_ALGORITHM_FAMILY_KEY_AGREEMENT",
            Self::CRYPTO_ALGORITHM_FAMILY_KEM => "CRYPTO_ALGORITHM_FAMILY_KEM",
            Self::CRYPTO_ALGORITHM_FAMILY_AEAD => "CRYPTO_ALGORITHM_FAMILY_AEAD",
            Self::CRYPTO_ALGORITHM_FAMILY_HASH => "CRYPTO_ALGORITHM_FAMILY_HASH",
            Self::CRYPTO_ALGORITHM_FAMILY_MAC => "CRYPTO_ALGORITHM_FAMILY_MAC",
            Self::CRYPTO_ALGORITHM_FAMILY_KDF => "CRYPTO_ALGORITHM_FAMILY_KDF",
            Self::CRYPTO_ALGORITHM_FAMILY_KEY_WRAP => "CRYPTO_ALGORITHM_FAMILY_KEY_WRAP",
            Self::CRYPTO_ALGORITHM_FAMILY_HPKE => "CRYPTO_ALGORITHM_FAMILY_HPKE",
            Self::CRYPTO_ALGORITHM_FAMILY_CONSTANT_TIME => "CRYPTO_ALGORITHM_FAMILY_CONSTANT_TIME",
            Self::CRYPTO_ALGORITHM_FAMILY_PLATFORM_KEY => "CRYPTO_ALGORITHM_FAMILY_PLATFORM_KEY",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "CRYPTO_ALGORITHM_FAMILY_UNSPECIFIED" => {
                Some(Self::CRYPTO_ALGORITHM_FAMILY_UNSPECIFIED)
            }
            "CRYPTO_ALGORITHM_FAMILY_SIGNATURE" => Some(Self::CRYPTO_ALGORITHM_FAMILY_SIGNATURE),
            "CRYPTO_ALGORITHM_FAMILY_KEY_AGREEMENT" => {
                Some(Self::CRYPTO_ALGORITHM_FAMILY_KEY_AGREEMENT)
            }
            "CRYPTO_ALGORITHM_FAMILY_KEM" => Some(Self::CRYPTO_ALGORITHM_FAMILY_KEM),
            "CRYPTO_ALGORITHM_FAMILY_AEAD" => Some(Self::CRYPTO_ALGORITHM_FAMILY_AEAD),
            "CRYPTO_ALGORITHM_FAMILY_HASH" => Some(Self::CRYPTO_ALGORITHM_FAMILY_HASH),
            "CRYPTO_ALGORITHM_FAMILY_MAC" => Some(Self::CRYPTO_ALGORITHM_FAMILY_MAC),
            "CRYPTO_ALGORITHM_FAMILY_KDF" => Some(Self::CRYPTO_ALGORITHM_FAMILY_KDF),
            "CRYPTO_ALGORITHM_FAMILY_KEY_WRAP" => Some(Self::CRYPTO_ALGORITHM_FAMILY_KEY_WRAP),
            "CRYPTO_ALGORITHM_FAMILY_HPKE" => Some(Self::CRYPTO_ALGORITHM_FAMILY_HPKE),
            "CRYPTO_ALGORITHM_FAMILY_CONSTANT_TIME" => {
                Some(Self::CRYPTO_ALGORITHM_FAMILY_CONSTANT_TIME)
            }
            "CRYPTO_ALGORITHM_FAMILY_PLATFORM_KEY" => {
                Some(Self::CRYPTO_ALGORITHM_FAMILY_PLATFORM_KEY)
            }
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::CRYPTO_ALGORITHM_FAMILY_UNSPECIFIED,
            Self::CRYPTO_ALGORITHM_FAMILY_SIGNATURE,
            Self::CRYPTO_ALGORITHM_FAMILY_KEY_AGREEMENT,
            Self::CRYPTO_ALGORITHM_FAMILY_KEM,
            Self::CRYPTO_ALGORITHM_FAMILY_AEAD,
            Self::CRYPTO_ALGORITHM_FAMILY_HASH,
            Self::CRYPTO_ALGORITHM_FAMILY_MAC,
            Self::CRYPTO_ALGORITHM_FAMILY_KDF,
            Self::CRYPTO_ALGORITHM_FAMILY_KEY_WRAP,
            Self::CRYPTO_ALGORITHM_FAMILY_HPKE,
            Self::CRYPTO_ALGORITHM_FAMILY_CONSTANT_TIME,
            Self::CRYPTO_ALGORITHM_FAMILY_PLATFORM_KEY,
        ]
    }
}
impl ::zeroize::Zeroize for CryptoAlgorithmFamily {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for CryptoAlgorithmFamily {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for CryptoAlgorithmFamily {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for CryptoAlgorithmFamily {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.KeyAlgorithm`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum KeyAlgorithm {
    /// `KEY_ALGORITHM_UNSPECIFIED`.
    #[default]
    KEY_ALGORITHM_UNSPECIFIED = 0,
    /// `KEY_ALGORITHM_ED25519`.
    KEY_ALGORITHM_ED25519 = 100,
    /// `KEY_ALGORITHM_X25519`.
    KEY_ALGORITHM_X25519 = 110,
    /// `KEY_ALGORITHM_P256`.
    KEY_ALGORITHM_P256 = 200,
    /// `KEY_ALGORITHM_P384`.
    KEY_ALGORITHM_P384 = 210,
    /// `KEY_ALGORITHM_P521`.
    KEY_ALGORITHM_P521 = 220,
    /// `KEY_ALGORITHM_SECP256K1`.
    KEY_ALGORITHM_SECP256K1 = 230,
    /// `KEY_ALGORITHM_ML_DSA_44`.
    KEY_ALGORITHM_ML_DSA_44 = 1000,
    /// `KEY_ALGORITHM_ML_DSA_65`.
    KEY_ALGORITHM_ML_DSA_65 = 1010,
    /// `KEY_ALGORITHM_ML_DSA_87`.
    KEY_ALGORITHM_ML_DSA_87 = 1020,
    /// `KEY_ALGORITHM_SLH_DSA_SHA2_128S`.
    KEY_ALGORITHM_SLH_DSA_SHA2_128S = 1100,
    /// `KEY_ALGORITHM_ML_KEM_512`.
    KEY_ALGORITHM_ML_KEM_512 = 2000,
    /// `KEY_ALGORITHM_ML_KEM_768`.
    KEY_ALGORITHM_ML_KEM_768 = 2010,
    /// `KEY_ALGORITHM_ML_KEM_1024`.
    KEY_ALGORITHM_ML_KEM_1024 = 2020,
    /// `KEY_ALGORITHM_X_WING_768`.
    KEY_ALGORITHM_X_WING_768 = 2100,
}
impl KeyAlgorithm {
    /// Idiomatic alias for [`Self::KEY_ALGORITHM_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::KEY_ALGORITHM_UNSPECIFIED;
    /// Idiomatic alias for [`Self::KEY_ALGORITHM_ED25519`].
    #[allow(non_upper_case_globals)]
    pub const Ed25519: Self = Self::KEY_ALGORITHM_ED25519;
    /// Idiomatic alias for [`Self::KEY_ALGORITHM_X25519`].
    #[allow(non_upper_case_globals)]
    pub const X25519: Self = Self::KEY_ALGORITHM_X25519;
    /// Idiomatic alias for [`Self::KEY_ALGORITHM_P256`].
    #[allow(non_upper_case_globals)]
    pub const P256: Self = Self::KEY_ALGORITHM_P256;
    /// Idiomatic alias for [`Self::KEY_ALGORITHM_P384`].
    #[allow(non_upper_case_globals)]
    pub const P384: Self = Self::KEY_ALGORITHM_P384;
    /// Idiomatic alias for [`Self::KEY_ALGORITHM_P521`].
    #[allow(non_upper_case_globals)]
    pub const P521: Self = Self::KEY_ALGORITHM_P521;
    /// Idiomatic alias for [`Self::KEY_ALGORITHM_SECP256K1`].
    #[allow(non_upper_case_globals)]
    pub const Secp256k1: Self = Self::KEY_ALGORITHM_SECP256K1;
    /// Idiomatic alias for [`Self::KEY_ALGORITHM_ML_DSA_44`].
    #[allow(non_upper_case_globals)]
    pub const MlDsa44: Self = Self::KEY_ALGORITHM_ML_DSA_44;
    /// Idiomatic alias for [`Self::KEY_ALGORITHM_ML_DSA_65`].
    #[allow(non_upper_case_globals)]
    pub const MlDsa65: Self = Self::KEY_ALGORITHM_ML_DSA_65;
    /// Idiomatic alias for [`Self::KEY_ALGORITHM_ML_DSA_87`].
    #[allow(non_upper_case_globals)]
    pub const MlDsa87: Self = Self::KEY_ALGORITHM_ML_DSA_87;
    /// Idiomatic alias for [`Self::KEY_ALGORITHM_SLH_DSA_SHA2_128S`].
    #[allow(non_upper_case_globals)]
    pub const SlhDsaSha2128s: Self = Self::KEY_ALGORITHM_SLH_DSA_SHA2_128S;
    /// Idiomatic alias for [`Self::KEY_ALGORITHM_ML_KEM_512`].
    #[allow(non_upper_case_globals)]
    pub const MlKem512: Self = Self::KEY_ALGORITHM_ML_KEM_512;
    /// Idiomatic alias for [`Self::KEY_ALGORITHM_ML_KEM_768`].
    #[allow(non_upper_case_globals)]
    pub const MlKem768: Self = Self::KEY_ALGORITHM_ML_KEM_768;
    /// Idiomatic alias for [`Self::KEY_ALGORITHM_ML_KEM_1024`].
    #[allow(non_upper_case_globals)]
    pub const MlKem1024: Self = Self::KEY_ALGORITHM_ML_KEM_1024;
    /// Idiomatic alias for [`Self::KEY_ALGORITHM_X_WING_768`].
    #[allow(non_upper_case_globals)]
    pub const XWing768: Self = Self::KEY_ALGORITHM_X_WING_768;
}
impl ::buffa::Enumeration for KeyAlgorithm {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::KEY_ALGORITHM_UNSPECIFIED),
            100 => Some(Self::KEY_ALGORITHM_ED25519),
            110 => Some(Self::KEY_ALGORITHM_X25519),
            200 => Some(Self::KEY_ALGORITHM_P256),
            210 => Some(Self::KEY_ALGORITHM_P384),
            220 => Some(Self::KEY_ALGORITHM_P521),
            230 => Some(Self::KEY_ALGORITHM_SECP256K1),
            1000 => Some(Self::KEY_ALGORITHM_ML_DSA_44),
            1010 => Some(Self::KEY_ALGORITHM_ML_DSA_65),
            1020 => Some(Self::KEY_ALGORITHM_ML_DSA_87),
            1100 => Some(Self::KEY_ALGORITHM_SLH_DSA_SHA2_128S),
            2000 => Some(Self::KEY_ALGORITHM_ML_KEM_512),
            2010 => Some(Self::KEY_ALGORITHM_ML_KEM_768),
            2020 => Some(Self::KEY_ALGORITHM_ML_KEM_1024),
            2100 => Some(Self::KEY_ALGORITHM_X_WING_768),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::KEY_ALGORITHM_UNSPECIFIED => "KEY_ALGORITHM_UNSPECIFIED",
            Self::KEY_ALGORITHM_ED25519 => "KEY_ALGORITHM_ED25519",
            Self::KEY_ALGORITHM_X25519 => "KEY_ALGORITHM_X25519",
            Self::KEY_ALGORITHM_P256 => "KEY_ALGORITHM_P256",
            Self::KEY_ALGORITHM_P384 => "KEY_ALGORITHM_P384",
            Self::KEY_ALGORITHM_P521 => "KEY_ALGORITHM_P521",
            Self::KEY_ALGORITHM_SECP256K1 => "KEY_ALGORITHM_SECP256K1",
            Self::KEY_ALGORITHM_ML_DSA_44 => "KEY_ALGORITHM_ML_DSA_44",
            Self::KEY_ALGORITHM_ML_DSA_65 => "KEY_ALGORITHM_ML_DSA_65",
            Self::KEY_ALGORITHM_ML_DSA_87 => "KEY_ALGORITHM_ML_DSA_87",
            Self::KEY_ALGORITHM_SLH_DSA_SHA2_128S => "KEY_ALGORITHM_SLH_DSA_SHA2_128S",
            Self::KEY_ALGORITHM_ML_KEM_512 => "KEY_ALGORITHM_ML_KEM_512",
            Self::KEY_ALGORITHM_ML_KEM_768 => "KEY_ALGORITHM_ML_KEM_768",
            Self::KEY_ALGORITHM_ML_KEM_1024 => "KEY_ALGORITHM_ML_KEM_1024",
            Self::KEY_ALGORITHM_X_WING_768 => "KEY_ALGORITHM_X_WING_768",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "KEY_ALGORITHM_UNSPECIFIED" => Some(Self::KEY_ALGORITHM_UNSPECIFIED),
            "KEY_ALGORITHM_ED25519" => Some(Self::KEY_ALGORITHM_ED25519),
            "KEY_ALGORITHM_X25519" => Some(Self::KEY_ALGORITHM_X25519),
            "KEY_ALGORITHM_P256" => Some(Self::KEY_ALGORITHM_P256),
            "KEY_ALGORITHM_P384" => Some(Self::KEY_ALGORITHM_P384),
            "KEY_ALGORITHM_P521" => Some(Self::KEY_ALGORITHM_P521),
            "KEY_ALGORITHM_SECP256K1" => Some(Self::KEY_ALGORITHM_SECP256K1),
            "KEY_ALGORITHM_ML_DSA_44" => Some(Self::KEY_ALGORITHM_ML_DSA_44),
            "KEY_ALGORITHM_ML_DSA_65" => Some(Self::KEY_ALGORITHM_ML_DSA_65),
            "KEY_ALGORITHM_ML_DSA_87" => Some(Self::KEY_ALGORITHM_ML_DSA_87),
            "KEY_ALGORITHM_SLH_DSA_SHA2_128S" => Some(Self::KEY_ALGORITHM_SLH_DSA_SHA2_128S),
            "KEY_ALGORITHM_ML_KEM_512" => Some(Self::KEY_ALGORITHM_ML_KEM_512),
            "KEY_ALGORITHM_ML_KEM_768" => Some(Self::KEY_ALGORITHM_ML_KEM_768),
            "KEY_ALGORITHM_ML_KEM_1024" => Some(Self::KEY_ALGORITHM_ML_KEM_1024),
            "KEY_ALGORITHM_X_WING_768" => Some(Self::KEY_ALGORITHM_X_WING_768),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::KEY_ALGORITHM_UNSPECIFIED,
            Self::KEY_ALGORITHM_ED25519,
            Self::KEY_ALGORITHM_X25519,
            Self::KEY_ALGORITHM_P256,
            Self::KEY_ALGORITHM_P384,
            Self::KEY_ALGORITHM_P521,
            Self::KEY_ALGORITHM_SECP256K1,
            Self::KEY_ALGORITHM_ML_DSA_44,
            Self::KEY_ALGORITHM_ML_DSA_65,
            Self::KEY_ALGORITHM_ML_DSA_87,
            Self::KEY_ALGORITHM_SLH_DSA_SHA2_128S,
            Self::KEY_ALGORITHM_ML_KEM_512,
            Self::KEY_ALGORITHM_ML_KEM_768,
            Self::KEY_ALGORITHM_ML_KEM_1024,
            Self::KEY_ALGORITHM_X_WING_768,
        ]
    }
}
impl ::zeroize::Zeroize for KeyAlgorithm {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for KeyAlgorithm {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for KeyAlgorithm {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for KeyAlgorithm {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.EcdsaCurve`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum EcdsaCurve {
    /// `ECDSA_CURVE_UNSPECIFIED`.
    #[default]
    ECDSA_CURVE_UNSPECIFIED = 0,
    /// `ECDSA_CURVE_NIST_P256`.
    ECDSA_CURVE_NIST_P256 = 100,
    /// `ECDSA_CURVE_NIST_P384`.
    ECDSA_CURVE_NIST_P384 = 110,
    /// `ECDSA_CURVE_NIST_P521`.
    ECDSA_CURVE_NIST_P521 = 120,
    /// `ECDSA_CURVE_BRAINPOOL_P256R1`.
    ECDSA_CURVE_BRAINPOOL_P256R1 = 200,
    /// `ECDSA_CURVE_BRAINPOOL_P320R1`.
    ECDSA_CURVE_BRAINPOOL_P320R1 = 210,
    /// `ECDSA_CURVE_BRAINPOOL_P384R1`.
    ECDSA_CURVE_BRAINPOOL_P384R1 = 220,
    /// `ECDSA_CURVE_BRAINPOOL_P512R1`.
    ECDSA_CURVE_BRAINPOOL_P512R1 = 230,
}
impl EcdsaCurve {
    /// Idiomatic alias for [`Self::ECDSA_CURVE_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::ECDSA_CURVE_UNSPECIFIED;
    /// Idiomatic alias for [`Self::ECDSA_CURVE_NIST_P256`].
    #[allow(non_upper_case_globals)]
    pub const NistP256: Self = Self::ECDSA_CURVE_NIST_P256;
    /// Idiomatic alias for [`Self::ECDSA_CURVE_NIST_P384`].
    #[allow(non_upper_case_globals)]
    pub const NistP384: Self = Self::ECDSA_CURVE_NIST_P384;
    /// Idiomatic alias for [`Self::ECDSA_CURVE_NIST_P521`].
    #[allow(non_upper_case_globals)]
    pub const NistP521: Self = Self::ECDSA_CURVE_NIST_P521;
    /// Idiomatic alias for [`Self::ECDSA_CURVE_BRAINPOOL_P256R1`].
    #[allow(non_upper_case_globals)]
    pub const BrainpoolP256r1: Self = Self::ECDSA_CURVE_BRAINPOOL_P256R1;
    /// Idiomatic alias for [`Self::ECDSA_CURVE_BRAINPOOL_P320R1`].
    #[allow(non_upper_case_globals)]
    pub const BrainpoolP320r1: Self = Self::ECDSA_CURVE_BRAINPOOL_P320R1;
    /// Idiomatic alias for [`Self::ECDSA_CURVE_BRAINPOOL_P384R1`].
    #[allow(non_upper_case_globals)]
    pub const BrainpoolP384r1: Self = Self::ECDSA_CURVE_BRAINPOOL_P384R1;
    /// Idiomatic alias for [`Self::ECDSA_CURVE_BRAINPOOL_P512R1`].
    #[allow(non_upper_case_globals)]
    pub const BrainpoolP512r1: Self = Self::ECDSA_CURVE_BRAINPOOL_P512R1;
}
impl ::buffa::Enumeration for EcdsaCurve {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::ECDSA_CURVE_UNSPECIFIED),
            100 => Some(Self::ECDSA_CURVE_NIST_P256),
            110 => Some(Self::ECDSA_CURVE_NIST_P384),
            120 => Some(Self::ECDSA_CURVE_NIST_P521),
            200 => Some(Self::ECDSA_CURVE_BRAINPOOL_P256R1),
            210 => Some(Self::ECDSA_CURVE_BRAINPOOL_P320R1),
            220 => Some(Self::ECDSA_CURVE_BRAINPOOL_P384R1),
            230 => Some(Self::ECDSA_CURVE_BRAINPOOL_P512R1),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::ECDSA_CURVE_UNSPECIFIED => "ECDSA_CURVE_UNSPECIFIED",
            Self::ECDSA_CURVE_NIST_P256 => "ECDSA_CURVE_NIST_P256",
            Self::ECDSA_CURVE_NIST_P384 => "ECDSA_CURVE_NIST_P384",
            Self::ECDSA_CURVE_NIST_P521 => "ECDSA_CURVE_NIST_P521",
            Self::ECDSA_CURVE_BRAINPOOL_P256R1 => "ECDSA_CURVE_BRAINPOOL_P256R1",
            Self::ECDSA_CURVE_BRAINPOOL_P320R1 => "ECDSA_CURVE_BRAINPOOL_P320R1",
            Self::ECDSA_CURVE_BRAINPOOL_P384R1 => "ECDSA_CURVE_BRAINPOOL_P384R1",
            Self::ECDSA_CURVE_BRAINPOOL_P512R1 => "ECDSA_CURVE_BRAINPOOL_P512R1",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "ECDSA_CURVE_UNSPECIFIED" => Some(Self::ECDSA_CURVE_UNSPECIFIED),
            "ECDSA_CURVE_NIST_P256" => Some(Self::ECDSA_CURVE_NIST_P256),
            "ECDSA_CURVE_NIST_P384" => Some(Self::ECDSA_CURVE_NIST_P384),
            "ECDSA_CURVE_NIST_P521" => Some(Self::ECDSA_CURVE_NIST_P521),
            "ECDSA_CURVE_BRAINPOOL_P256R1" => Some(Self::ECDSA_CURVE_BRAINPOOL_P256R1),
            "ECDSA_CURVE_BRAINPOOL_P320R1" => Some(Self::ECDSA_CURVE_BRAINPOOL_P320R1),
            "ECDSA_CURVE_BRAINPOOL_P384R1" => Some(Self::ECDSA_CURVE_BRAINPOOL_P384R1),
            "ECDSA_CURVE_BRAINPOOL_P512R1" => Some(Self::ECDSA_CURVE_BRAINPOOL_P512R1),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::ECDSA_CURVE_UNSPECIFIED,
            Self::ECDSA_CURVE_NIST_P256,
            Self::ECDSA_CURVE_NIST_P384,
            Self::ECDSA_CURVE_NIST_P521,
            Self::ECDSA_CURVE_BRAINPOOL_P256R1,
            Self::ECDSA_CURVE_BRAINPOOL_P320R1,
            Self::ECDSA_CURVE_BRAINPOOL_P384R1,
            Self::ECDSA_CURVE_BRAINPOOL_P512R1,
        ]
    }
}
impl ::zeroize::Zeroize for EcdsaCurve {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for EcdsaCurve {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for EcdsaCurve {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for EcdsaCurve {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.PrimeGroup`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum PrimeGroup {
    /// `PRIME_GROUP_UNSPECIFIED`.
    #[default]
    PRIME_GROUP_UNSPECIFIED = 0,
    /// `PRIME_GROUP_NIST_P256`.
    PRIME_GROUP_NIST_P256 = 100,
    /// `PRIME_GROUP_NIST_P384`.
    PRIME_GROUP_NIST_P384 = 110,
    /// `PRIME_GROUP_NIST_P521`.
    PRIME_GROUP_NIST_P521 = 120,
    /// `PRIME_GROUP_NIST_P192`.
    PRIME_GROUP_NIST_P192 = 130,
    /// `PRIME_GROUP_BRAINPOOL_P256R1`.
    PRIME_GROUP_BRAINPOOL_P256R1 = 200,
    /// `PRIME_GROUP_BRAINPOOL_P320R1`.
    PRIME_GROUP_BRAINPOOL_P320R1 = 210,
    /// `PRIME_GROUP_BRAINPOOL_P384R1`.
    PRIME_GROUP_BRAINPOOL_P384R1 = 220,
    /// `PRIME_GROUP_BRAINPOOL_P512R1`.
    PRIME_GROUP_BRAINPOOL_P512R1 = 230,
    /// `PRIME_GROUP_BRAINPOOL_P192R1`.
    PRIME_GROUP_BRAINPOOL_P192R1 = 240,
    /// `PRIME_GROUP_BRAINPOOL_P224R1`.
    PRIME_GROUP_BRAINPOOL_P224R1 = 250,
    /// `PRIME_GROUP_RFC5114_DH1024_160`.
    PRIME_GROUP_RFC5114_DH1024_160 = 300,
    /// `PRIME_GROUP_RFC5114_DH2048_224`.
    PRIME_GROUP_RFC5114_DH2048_224 = 310,
    /// `PRIME_GROUP_RFC5114_DH2048_256`.
    PRIME_GROUP_RFC5114_DH2048_256 = 320,
}
impl PrimeGroup {
    /// Idiomatic alias for [`Self::PRIME_GROUP_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::PRIME_GROUP_UNSPECIFIED;
    /// Idiomatic alias for [`Self::PRIME_GROUP_NIST_P256`].
    #[allow(non_upper_case_globals)]
    pub const NistP256: Self = Self::PRIME_GROUP_NIST_P256;
    /// Idiomatic alias for [`Self::PRIME_GROUP_NIST_P384`].
    #[allow(non_upper_case_globals)]
    pub const NistP384: Self = Self::PRIME_GROUP_NIST_P384;
    /// Idiomatic alias for [`Self::PRIME_GROUP_NIST_P521`].
    #[allow(non_upper_case_globals)]
    pub const NistP521: Self = Self::PRIME_GROUP_NIST_P521;
    /// Idiomatic alias for [`Self::PRIME_GROUP_NIST_P192`].
    #[allow(non_upper_case_globals)]
    pub const NistP192: Self = Self::PRIME_GROUP_NIST_P192;
    /// Idiomatic alias for [`Self::PRIME_GROUP_BRAINPOOL_P256R1`].
    #[allow(non_upper_case_globals)]
    pub const BrainpoolP256r1: Self = Self::PRIME_GROUP_BRAINPOOL_P256R1;
    /// Idiomatic alias for [`Self::PRIME_GROUP_BRAINPOOL_P320R1`].
    #[allow(non_upper_case_globals)]
    pub const BrainpoolP320r1: Self = Self::PRIME_GROUP_BRAINPOOL_P320R1;
    /// Idiomatic alias for [`Self::PRIME_GROUP_BRAINPOOL_P384R1`].
    #[allow(non_upper_case_globals)]
    pub const BrainpoolP384r1: Self = Self::PRIME_GROUP_BRAINPOOL_P384R1;
    /// Idiomatic alias for [`Self::PRIME_GROUP_BRAINPOOL_P512R1`].
    #[allow(non_upper_case_globals)]
    pub const BrainpoolP512r1: Self = Self::PRIME_GROUP_BRAINPOOL_P512R1;
    /// Idiomatic alias for [`Self::PRIME_GROUP_BRAINPOOL_P192R1`].
    #[allow(non_upper_case_globals)]
    pub const BrainpoolP192r1: Self = Self::PRIME_GROUP_BRAINPOOL_P192R1;
    /// Idiomatic alias for [`Self::PRIME_GROUP_BRAINPOOL_P224R1`].
    #[allow(non_upper_case_globals)]
    pub const BrainpoolP224r1: Self = Self::PRIME_GROUP_BRAINPOOL_P224R1;
    /// Idiomatic alias for [`Self::PRIME_GROUP_RFC5114_DH1024_160`].
    #[allow(non_upper_case_globals)]
    pub const Rfc5114Dh1024160: Self = Self::PRIME_GROUP_RFC5114_DH1024_160;
    /// Idiomatic alias for [`Self::PRIME_GROUP_RFC5114_DH2048_224`].
    #[allow(non_upper_case_globals)]
    pub const Rfc5114Dh2048224: Self = Self::PRIME_GROUP_RFC5114_DH2048_224;
    /// Idiomatic alias for [`Self::PRIME_GROUP_RFC5114_DH2048_256`].
    #[allow(non_upper_case_globals)]
    pub const Rfc5114Dh2048256: Self = Self::PRIME_GROUP_RFC5114_DH2048_256;
}
impl ::buffa::Enumeration for PrimeGroup {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::PRIME_GROUP_UNSPECIFIED),
            100 => Some(Self::PRIME_GROUP_NIST_P256),
            110 => Some(Self::PRIME_GROUP_NIST_P384),
            120 => Some(Self::PRIME_GROUP_NIST_P521),
            130 => Some(Self::PRIME_GROUP_NIST_P192),
            200 => Some(Self::PRIME_GROUP_BRAINPOOL_P256R1),
            210 => Some(Self::PRIME_GROUP_BRAINPOOL_P320R1),
            220 => Some(Self::PRIME_GROUP_BRAINPOOL_P384R1),
            230 => Some(Self::PRIME_GROUP_BRAINPOOL_P512R1),
            240 => Some(Self::PRIME_GROUP_BRAINPOOL_P192R1),
            250 => Some(Self::PRIME_GROUP_BRAINPOOL_P224R1),
            300 => Some(Self::PRIME_GROUP_RFC5114_DH1024_160),
            310 => Some(Self::PRIME_GROUP_RFC5114_DH2048_224),
            320 => Some(Self::PRIME_GROUP_RFC5114_DH2048_256),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::PRIME_GROUP_UNSPECIFIED => "PRIME_GROUP_UNSPECIFIED",
            Self::PRIME_GROUP_NIST_P256 => "PRIME_GROUP_NIST_P256",
            Self::PRIME_GROUP_NIST_P384 => "PRIME_GROUP_NIST_P384",
            Self::PRIME_GROUP_NIST_P521 => "PRIME_GROUP_NIST_P521",
            Self::PRIME_GROUP_NIST_P192 => "PRIME_GROUP_NIST_P192",
            Self::PRIME_GROUP_BRAINPOOL_P256R1 => "PRIME_GROUP_BRAINPOOL_P256R1",
            Self::PRIME_GROUP_BRAINPOOL_P320R1 => "PRIME_GROUP_BRAINPOOL_P320R1",
            Self::PRIME_GROUP_BRAINPOOL_P384R1 => "PRIME_GROUP_BRAINPOOL_P384R1",
            Self::PRIME_GROUP_BRAINPOOL_P512R1 => "PRIME_GROUP_BRAINPOOL_P512R1",
            Self::PRIME_GROUP_BRAINPOOL_P192R1 => "PRIME_GROUP_BRAINPOOL_P192R1",
            Self::PRIME_GROUP_BRAINPOOL_P224R1 => "PRIME_GROUP_BRAINPOOL_P224R1",
            Self::PRIME_GROUP_RFC5114_DH1024_160 => "PRIME_GROUP_RFC5114_DH1024_160",
            Self::PRIME_GROUP_RFC5114_DH2048_224 => "PRIME_GROUP_RFC5114_DH2048_224",
            Self::PRIME_GROUP_RFC5114_DH2048_256 => "PRIME_GROUP_RFC5114_DH2048_256",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "PRIME_GROUP_UNSPECIFIED" => Some(Self::PRIME_GROUP_UNSPECIFIED),
            "PRIME_GROUP_NIST_P256" => Some(Self::PRIME_GROUP_NIST_P256),
            "PRIME_GROUP_NIST_P384" => Some(Self::PRIME_GROUP_NIST_P384),
            "PRIME_GROUP_NIST_P521" => Some(Self::PRIME_GROUP_NIST_P521),
            "PRIME_GROUP_NIST_P192" => Some(Self::PRIME_GROUP_NIST_P192),
            "PRIME_GROUP_BRAINPOOL_P256R1" => Some(Self::PRIME_GROUP_BRAINPOOL_P256R1),
            "PRIME_GROUP_BRAINPOOL_P320R1" => Some(Self::PRIME_GROUP_BRAINPOOL_P320R1),
            "PRIME_GROUP_BRAINPOOL_P384R1" => Some(Self::PRIME_GROUP_BRAINPOOL_P384R1),
            "PRIME_GROUP_BRAINPOOL_P512R1" => Some(Self::PRIME_GROUP_BRAINPOOL_P512R1),
            "PRIME_GROUP_BRAINPOOL_P192R1" => Some(Self::PRIME_GROUP_BRAINPOOL_P192R1),
            "PRIME_GROUP_BRAINPOOL_P224R1" => Some(Self::PRIME_GROUP_BRAINPOOL_P224R1),
            "PRIME_GROUP_RFC5114_DH1024_160" => Some(Self::PRIME_GROUP_RFC5114_DH1024_160),
            "PRIME_GROUP_RFC5114_DH2048_224" => Some(Self::PRIME_GROUP_RFC5114_DH2048_224),
            "PRIME_GROUP_RFC5114_DH2048_256" => Some(Self::PRIME_GROUP_RFC5114_DH2048_256),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::PRIME_GROUP_UNSPECIFIED,
            Self::PRIME_GROUP_NIST_P256,
            Self::PRIME_GROUP_NIST_P384,
            Self::PRIME_GROUP_NIST_P521,
            Self::PRIME_GROUP_NIST_P192,
            Self::PRIME_GROUP_BRAINPOOL_P256R1,
            Self::PRIME_GROUP_BRAINPOOL_P320R1,
            Self::PRIME_GROUP_BRAINPOOL_P384R1,
            Self::PRIME_GROUP_BRAINPOOL_P512R1,
            Self::PRIME_GROUP_BRAINPOOL_P192R1,
            Self::PRIME_GROUP_BRAINPOOL_P224R1,
            Self::PRIME_GROUP_RFC5114_DH1024_160,
            Self::PRIME_GROUP_RFC5114_DH2048_224,
            Self::PRIME_GROUP_RFC5114_DH2048_256,
        ]
    }
}
impl ::zeroize::Zeroize for PrimeGroup {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for PrimeGroup {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for PrimeGroup {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for PrimeGroup {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.SignatureAlgorithm`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum SignatureAlgorithm {
    /// `SIGNATURE_ALGORITHM_UNSPECIFIED`.
    #[default]
    SIGNATURE_ALGORITHM_UNSPECIFIED = 0,
    /// `SIGNATURE_ALGORITHM_ED25519`.
    SIGNATURE_ALGORITHM_ED25519 = 100,
    /// `SIGNATURE_ALGORITHM_ECDSA_P256_SHA256`.
    SIGNATURE_ALGORITHM_ECDSA_P256_SHA256 = 200,
    /// `SIGNATURE_ALGORITHM_ECDSA_P384_SHA384`.
    SIGNATURE_ALGORITHM_ECDSA_P384_SHA384 = 210,
    /// `SIGNATURE_ALGORITHM_ECDSA_P521_SHA512`.
    SIGNATURE_ALGORITHM_ECDSA_P521_SHA512 = 220,
    /// `SIGNATURE_ALGORITHM_ECDSA_SECP256K1_SHA256`.
    SIGNATURE_ALGORITHM_ECDSA_SECP256K1_SHA256 = 230,
    /// `SIGNATURE_ALGORITHM_BIP340_SCHNORR_SECP256K1_SHA256`.
    SIGNATURE_ALGORITHM_BIP340_SCHNORR_SECP256K1_SHA256 = 240,
    /// `SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA1`.
    SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA1 = 300,
    /// `SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA256`.
    SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA256 = 310,
    /// `SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA384`.
    SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA384 = 320,
    /// `SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA512`.
    SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA512 = 330,
    /// `SIGNATURE_ALGORITHM_RSA_PSS_SHA1_MGF1_SHA1`.
    SIGNATURE_ALGORITHM_RSA_PSS_SHA1_MGF1_SHA1 = 400,
    /// `SIGNATURE_ALGORITHM_RSA_PSS_SHA256_MGF1_SHA256`.
    SIGNATURE_ALGORITHM_RSA_PSS_SHA256_MGF1_SHA256 = 410,
    /// `SIGNATURE_ALGORITHM_RSA_PSS_SHA384_MGF1_SHA384`.
    SIGNATURE_ALGORITHM_RSA_PSS_SHA384_MGF1_SHA384 = 420,
    /// `SIGNATURE_ALGORITHM_RSA_PSS_SHA512_MGF1_SHA512`.
    SIGNATURE_ALGORITHM_RSA_PSS_SHA512_MGF1_SHA512 = 430,
    /// `SIGNATURE_ALGORITHM_ML_DSA_44`.
    SIGNATURE_ALGORITHM_ML_DSA_44 = 1000,
    /// `SIGNATURE_ALGORITHM_ML_DSA_65`.
    SIGNATURE_ALGORITHM_ML_DSA_65 = 1010,
    /// `SIGNATURE_ALGORITHM_ML_DSA_87`.
    SIGNATURE_ALGORITHM_ML_DSA_87 = 1020,
    /// `SIGNATURE_ALGORITHM_SLH_DSA_SHA2_128S`.
    SIGNATURE_ALGORITHM_SLH_DSA_SHA2_128S = 1100,
}
impl SignatureAlgorithm {
    /// Idiomatic alias for [`Self::SIGNATURE_ALGORITHM_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::SIGNATURE_ALGORITHM_UNSPECIFIED;
    /// Idiomatic alias for [`Self::SIGNATURE_ALGORITHM_ED25519`].
    #[allow(non_upper_case_globals)]
    pub const Ed25519: Self = Self::SIGNATURE_ALGORITHM_ED25519;
    /// Idiomatic alias for [`Self::SIGNATURE_ALGORITHM_ECDSA_P256_SHA256`].
    #[allow(non_upper_case_globals)]
    pub const EcdsaP256Sha256: Self = Self::SIGNATURE_ALGORITHM_ECDSA_P256_SHA256;
    /// Idiomatic alias for [`Self::SIGNATURE_ALGORITHM_ECDSA_P384_SHA384`].
    #[allow(non_upper_case_globals)]
    pub const EcdsaP384Sha384: Self = Self::SIGNATURE_ALGORITHM_ECDSA_P384_SHA384;
    /// Idiomatic alias for [`Self::SIGNATURE_ALGORITHM_ECDSA_P521_SHA512`].
    #[allow(non_upper_case_globals)]
    pub const EcdsaP521Sha512: Self = Self::SIGNATURE_ALGORITHM_ECDSA_P521_SHA512;
    /// Idiomatic alias for [`Self::SIGNATURE_ALGORITHM_ECDSA_SECP256K1_SHA256`].
    #[allow(non_upper_case_globals)]
    pub const EcdsaSecp256k1Sha256: Self = Self::SIGNATURE_ALGORITHM_ECDSA_SECP256K1_SHA256;
    /// Idiomatic alias for [`Self::SIGNATURE_ALGORITHM_BIP340_SCHNORR_SECP256K1_SHA256`].
    #[allow(non_upper_case_globals)]
    pub const Bip340SchnorrSecp256k1Sha256: Self =
        Self::SIGNATURE_ALGORITHM_BIP340_SCHNORR_SECP256K1_SHA256;
    /// Idiomatic alias for [`Self::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA1`].
    #[allow(non_upper_case_globals)]
    pub const RsaPkcs1v15Sha1: Self = Self::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA1;
    /// Idiomatic alias for [`Self::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA256`].
    #[allow(non_upper_case_globals)]
    pub const RsaPkcs1v15Sha256: Self = Self::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA256;
    /// Idiomatic alias for [`Self::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA384`].
    #[allow(non_upper_case_globals)]
    pub const RsaPkcs1v15Sha384: Self = Self::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA384;
    /// Idiomatic alias for [`Self::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA512`].
    #[allow(non_upper_case_globals)]
    pub const RsaPkcs1v15Sha512: Self = Self::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA512;
    /// Idiomatic alias for [`Self::SIGNATURE_ALGORITHM_RSA_PSS_SHA1_MGF1_SHA1`].
    #[allow(non_upper_case_globals)]
    pub const RsaPssSha1Mgf1Sha1: Self = Self::SIGNATURE_ALGORITHM_RSA_PSS_SHA1_MGF1_SHA1;
    /// Idiomatic alias for [`Self::SIGNATURE_ALGORITHM_RSA_PSS_SHA256_MGF1_SHA256`].
    #[allow(non_upper_case_globals)]
    pub const RsaPssSha256Mgf1Sha256: Self = Self::SIGNATURE_ALGORITHM_RSA_PSS_SHA256_MGF1_SHA256;
    /// Idiomatic alias for [`Self::SIGNATURE_ALGORITHM_RSA_PSS_SHA384_MGF1_SHA384`].
    #[allow(non_upper_case_globals)]
    pub const RsaPssSha384Mgf1Sha384: Self = Self::SIGNATURE_ALGORITHM_RSA_PSS_SHA384_MGF1_SHA384;
    /// Idiomatic alias for [`Self::SIGNATURE_ALGORITHM_RSA_PSS_SHA512_MGF1_SHA512`].
    #[allow(non_upper_case_globals)]
    pub const RsaPssSha512Mgf1Sha512: Self = Self::SIGNATURE_ALGORITHM_RSA_PSS_SHA512_MGF1_SHA512;
    /// Idiomatic alias for [`Self::SIGNATURE_ALGORITHM_ML_DSA_44`].
    #[allow(non_upper_case_globals)]
    pub const MlDsa44: Self = Self::SIGNATURE_ALGORITHM_ML_DSA_44;
    /// Idiomatic alias for [`Self::SIGNATURE_ALGORITHM_ML_DSA_65`].
    #[allow(non_upper_case_globals)]
    pub const MlDsa65: Self = Self::SIGNATURE_ALGORITHM_ML_DSA_65;
    /// Idiomatic alias for [`Self::SIGNATURE_ALGORITHM_ML_DSA_87`].
    #[allow(non_upper_case_globals)]
    pub const MlDsa87: Self = Self::SIGNATURE_ALGORITHM_ML_DSA_87;
    /// Idiomatic alias for [`Self::SIGNATURE_ALGORITHM_SLH_DSA_SHA2_128S`].
    #[allow(non_upper_case_globals)]
    pub const SlhDsaSha2128s: Self = Self::SIGNATURE_ALGORITHM_SLH_DSA_SHA2_128S;
}
impl ::buffa::Enumeration for SignatureAlgorithm {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::SIGNATURE_ALGORITHM_UNSPECIFIED),
            100 => Some(Self::SIGNATURE_ALGORITHM_ED25519),
            200 => Some(Self::SIGNATURE_ALGORITHM_ECDSA_P256_SHA256),
            210 => Some(Self::SIGNATURE_ALGORITHM_ECDSA_P384_SHA384),
            220 => Some(Self::SIGNATURE_ALGORITHM_ECDSA_P521_SHA512),
            230 => Some(Self::SIGNATURE_ALGORITHM_ECDSA_SECP256K1_SHA256),
            240 => Some(Self::SIGNATURE_ALGORITHM_BIP340_SCHNORR_SECP256K1_SHA256),
            300 => Some(Self::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA1),
            310 => Some(Self::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA256),
            320 => Some(Self::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA384),
            330 => Some(Self::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA512),
            400 => Some(Self::SIGNATURE_ALGORITHM_RSA_PSS_SHA1_MGF1_SHA1),
            410 => Some(Self::SIGNATURE_ALGORITHM_RSA_PSS_SHA256_MGF1_SHA256),
            420 => Some(Self::SIGNATURE_ALGORITHM_RSA_PSS_SHA384_MGF1_SHA384),
            430 => Some(Self::SIGNATURE_ALGORITHM_RSA_PSS_SHA512_MGF1_SHA512),
            1000 => Some(Self::SIGNATURE_ALGORITHM_ML_DSA_44),
            1010 => Some(Self::SIGNATURE_ALGORITHM_ML_DSA_65),
            1020 => Some(Self::SIGNATURE_ALGORITHM_ML_DSA_87),
            1100 => Some(Self::SIGNATURE_ALGORITHM_SLH_DSA_SHA2_128S),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::SIGNATURE_ALGORITHM_UNSPECIFIED => "SIGNATURE_ALGORITHM_UNSPECIFIED",
            Self::SIGNATURE_ALGORITHM_ED25519 => "SIGNATURE_ALGORITHM_ED25519",
            Self::SIGNATURE_ALGORITHM_ECDSA_P256_SHA256 => "SIGNATURE_ALGORITHM_ECDSA_P256_SHA256",
            Self::SIGNATURE_ALGORITHM_ECDSA_P384_SHA384 => "SIGNATURE_ALGORITHM_ECDSA_P384_SHA384",
            Self::SIGNATURE_ALGORITHM_ECDSA_P521_SHA512 => "SIGNATURE_ALGORITHM_ECDSA_P521_SHA512",
            Self::SIGNATURE_ALGORITHM_ECDSA_SECP256K1_SHA256 => {
                "SIGNATURE_ALGORITHM_ECDSA_SECP256K1_SHA256"
            }
            Self::SIGNATURE_ALGORITHM_BIP340_SCHNORR_SECP256K1_SHA256 => {
                "SIGNATURE_ALGORITHM_BIP340_SCHNORR_SECP256K1_SHA256"
            }
            Self::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA1 => "SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA1",
            Self::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA256 => {
                "SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA256"
            }
            Self::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA384 => {
                "SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA384"
            }
            Self::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA512 => {
                "SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA512"
            }
            Self::SIGNATURE_ALGORITHM_RSA_PSS_SHA1_MGF1_SHA1 => {
                "SIGNATURE_ALGORITHM_RSA_PSS_SHA1_MGF1_SHA1"
            }
            Self::SIGNATURE_ALGORITHM_RSA_PSS_SHA256_MGF1_SHA256 => {
                "SIGNATURE_ALGORITHM_RSA_PSS_SHA256_MGF1_SHA256"
            }
            Self::SIGNATURE_ALGORITHM_RSA_PSS_SHA384_MGF1_SHA384 => {
                "SIGNATURE_ALGORITHM_RSA_PSS_SHA384_MGF1_SHA384"
            }
            Self::SIGNATURE_ALGORITHM_RSA_PSS_SHA512_MGF1_SHA512 => {
                "SIGNATURE_ALGORITHM_RSA_PSS_SHA512_MGF1_SHA512"
            }
            Self::SIGNATURE_ALGORITHM_ML_DSA_44 => "SIGNATURE_ALGORITHM_ML_DSA_44",
            Self::SIGNATURE_ALGORITHM_ML_DSA_65 => "SIGNATURE_ALGORITHM_ML_DSA_65",
            Self::SIGNATURE_ALGORITHM_ML_DSA_87 => "SIGNATURE_ALGORITHM_ML_DSA_87",
            Self::SIGNATURE_ALGORITHM_SLH_DSA_SHA2_128S => "SIGNATURE_ALGORITHM_SLH_DSA_SHA2_128S",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "SIGNATURE_ALGORITHM_UNSPECIFIED" => Some(Self::SIGNATURE_ALGORITHM_UNSPECIFIED),
            "SIGNATURE_ALGORITHM_ED25519" => Some(Self::SIGNATURE_ALGORITHM_ED25519),
            "SIGNATURE_ALGORITHM_ECDSA_P256_SHA256" => {
                Some(Self::SIGNATURE_ALGORITHM_ECDSA_P256_SHA256)
            }
            "SIGNATURE_ALGORITHM_ECDSA_P384_SHA384" => {
                Some(Self::SIGNATURE_ALGORITHM_ECDSA_P384_SHA384)
            }
            "SIGNATURE_ALGORITHM_ECDSA_P521_SHA512" => {
                Some(Self::SIGNATURE_ALGORITHM_ECDSA_P521_SHA512)
            }
            "SIGNATURE_ALGORITHM_ECDSA_SECP256K1_SHA256" => {
                Some(Self::SIGNATURE_ALGORITHM_ECDSA_SECP256K1_SHA256)
            }
            "SIGNATURE_ALGORITHM_BIP340_SCHNORR_SECP256K1_SHA256" => {
                Some(Self::SIGNATURE_ALGORITHM_BIP340_SCHNORR_SECP256K1_SHA256)
            }
            "SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA1" => {
                Some(Self::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA1)
            }
            "SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA256" => {
                Some(Self::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA256)
            }
            "SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA384" => {
                Some(Self::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA384)
            }
            "SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA512" => {
                Some(Self::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA512)
            }
            "SIGNATURE_ALGORITHM_RSA_PSS_SHA1_MGF1_SHA1" => {
                Some(Self::SIGNATURE_ALGORITHM_RSA_PSS_SHA1_MGF1_SHA1)
            }
            "SIGNATURE_ALGORITHM_RSA_PSS_SHA256_MGF1_SHA256" => {
                Some(Self::SIGNATURE_ALGORITHM_RSA_PSS_SHA256_MGF1_SHA256)
            }
            "SIGNATURE_ALGORITHM_RSA_PSS_SHA384_MGF1_SHA384" => {
                Some(Self::SIGNATURE_ALGORITHM_RSA_PSS_SHA384_MGF1_SHA384)
            }
            "SIGNATURE_ALGORITHM_RSA_PSS_SHA512_MGF1_SHA512" => {
                Some(Self::SIGNATURE_ALGORITHM_RSA_PSS_SHA512_MGF1_SHA512)
            }
            "SIGNATURE_ALGORITHM_ML_DSA_44" => Some(Self::SIGNATURE_ALGORITHM_ML_DSA_44),
            "SIGNATURE_ALGORITHM_ML_DSA_65" => Some(Self::SIGNATURE_ALGORITHM_ML_DSA_65),
            "SIGNATURE_ALGORITHM_ML_DSA_87" => Some(Self::SIGNATURE_ALGORITHM_ML_DSA_87),
            "SIGNATURE_ALGORITHM_SLH_DSA_SHA2_128S" => {
                Some(Self::SIGNATURE_ALGORITHM_SLH_DSA_SHA2_128S)
            }
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::SIGNATURE_ALGORITHM_UNSPECIFIED,
            Self::SIGNATURE_ALGORITHM_ED25519,
            Self::SIGNATURE_ALGORITHM_ECDSA_P256_SHA256,
            Self::SIGNATURE_ALGORITHM_ECDSA_P384_SHA384,
            Self::SIGNATURE_ALGORITHM_ECDSA_P521_SHA512,
            Self::SIGNATURE_ALGORITHM_ECDSA_SECP256K1_SHA256,
            Self::SIGNATURE_ALGORITHM_BIP340_SCHNORR_SECP256K1_SHA256,
            Self::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA1,
            Self::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA256,
            Self::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA384,
            Self::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA512,
            Self::SIGNATURE_ALGORITHM_RSA_PSS_SHA1_MGF1_SHA1,
            Self::SIGNATURE_ALGORITHM_RSA_PSS_SHA256_MGF1_SHA256,
            Self::SIGNATURE_ALGORITHM_RSA_PSS_SHA384_MGF1_SHA384,
            Self::SIGNATURE_ALGORITHM_RSA_PSS_SHA512_MGF1_SHA512,
            Self::SIGNATURE_ALGORITHM_ML_DSA_44,
            Self::SIGNATURE_ALGORITHM_ML_DSA_65,
            Self::SIGNATURE_ALGORITHM_ML_DSA_87,
            Self::SIGNATURE_ALGORITHM_SLH_DSA_SHA2_128S,
        ]
    }
}
impl ::zeroize::Zeroize for SignatureAlgorithm {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for SignatureAlgorithm {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for SignatureAlgorithm {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for SignatureAlgorithm {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.KeyAgreementAlgorithm`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum KeyAgreementAlgorithm {
    /// `KEY_AGREEMENT_ALGORITHM_UNSPECIFIED`.
    #[default]
    KEY_AGREEMENT_ALGORITHM_UNSPECIFIED = 0,
    /// `KEY_AGREEMENT_ALGORITHM_X25519`.
    KEY_AGREEMENT_ALGORITHM_X25519 = 100,
    /// `KEY_AGREEMENT_ALGORITHM_P256_ECDH`.
    KEY_AGREEMENT_ALGORITHM_P256_ECDH = 200,
    /// `KEY_AGREEMENT_ALGORITHM_P384_ECDH`.
    KEY_AGREEMENT_ALGORITHM_P384_ECDH = 210,
    /// `KEY_AGREEMENT_ALGORITHM_P521_ECDH`.
    KEY_AGREEMENT_ALGORITHM_P521_ECDH = 220,
}
impl KeyAgreementAlgorithm {
    /// Idiomatic alias for [`Self::KEY_AGREEMENT_ALGORITHM_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::KEY_AGREEMENT_ALGORITHM_UNSPECIFIED;
    /// Idiomatic alias for [`Self::KEY_AGREEMENT_ALGORITHM_X25519`].
    #[allow(non_upper_case_globals)]
    pub const X25519: Self = Self::KEY_AGREEMENT_ALGORITHM_X25519;
    /// Idiomatic alias for [`Self::KEY_AGREEMENT_ALGORITHM_P256_ECDH`].
    #[allow(non_upper_case_globals)]
    pub const P256Ecdh: Self = Self::KEY_AGREEMENT_ALGORITHM_P256_ECDH;
    /// Idiomatic alias for [`Self::KEY_AGREEMENT_ALGORITHM_P384_ECDH`].
    #[allow(non_upper_case_globals)]
    pub const P384Ecdh: Self = Self::KEY_AGREEMENT_ALGORITHM_P384_ECDH;
    /// Idiomatic alias for [`Self::KEY_AGREEMENT_ALGORITHM_P521_ECDH`].
    #[allow(non_upper_case_globals)]
    pub const P521Ecdh: Self = Self::KEY_AGREEMENT_ALGORITHM_P521_ECDH;
}
impl ::buffa::Enumeration for KeyAgreementAlgorithm {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::KEY_AGREEMENT_ALGORITHM_UNSPECIFIED),
            100 => Some(Self::KEY_AGREEMENT_ALGORITHM_X25519),
            200 => Some(Self::KEY_AGREEMENT_ALGORITHM_P256_ECDH),
            210 => Some(Self::KEY_AGREEMENT_ALGORITHM_P384_ECDH),
            220 => Some(Self::KEY_AGREEMENT_ALGORITHM_P521_ECDH),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::KEY_AGREEMENT_ALGORITHM_UNSPECIFIED => "KEY_AGREEMENT_ALGORITHM_UNSPECIFIED",
            Self::KEY_AGREEMENT_ALGORITHM_X25519 => "KEY_AGREEMENT_ALGORITHM_X25519",
            Self::KEY_AGREEMENT_ALGORITHM_P256_ECDH => "KEY_AGREEMENT_ALGORITHM_P256_ECDH",
            Self::KEY_AGREEMENT_ALGORITHM_P384_ECDH => "KEY_AGREEMENT_ALGORITHM_P384_ECDH",
            Self::KEY_AGREEMENT_ALGORITHM_P521_ECDH => "KEY_AGREEMENT_ALGORITHM_P521_ECDH",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "KEY_AGREEMENT_ALGORITHM_UNSPECIFIED" => {
                Some(Self::KEY_AGREEMENT_ALGORITHM_UNSPECIFIED)
            }
            "KEY_AGREEMENT_ALGORITHM_X25519" => Some(Self::KEY_AGREEMENT_ALGORITHM_X25519),
            "KEY_AGREEMENT_ALGORITHM_P256_ECDH" => Some(Self::KEY_AGREEMENT_ALGORITHM_P256_ECDH),
            "KEY_AGREEMENT_ALGORITHM_P384_ECDH" => Some(Self::KEY_AGREEMENT_ALGORITHM_P384_ECDH),
            "KEY_AGREEMENT_ALGORITHM_P521_ECDH" => Some(Self::KEY_AGREEMENT_ALGORITHM_P521_ECDH),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::KEY_AGREEMENT_ALGORITHM_UNSPECIFIED,
            Self::KEY_AGREEMENT_ALGORITHM_X25519,
            Self::KEY_AGREEMENT_ALGORITHM_P256_ECDH,
            Self::KEY_AGREEMENT_ALGORITHM_P384_ECDH,
            Self::KEY_AGREEMENT_ALGORITHM_P521_ECDH,
        ]
    }
}
impl ::zeroize::Zeroize for KeyAgreementAlgorithm {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for KeyAgreementAlgorithm {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for KeyAgreementAlgorithm {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for KeyAgreementAlgorithm {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.KemAlgorithm`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum KemAlgorithm {
    /// `KEM_ALGORITHM_UNSPECIFIED`.
    #[default]
    KEM_ALGORITHM_UNSPECIFIED = 0,
    /// `KEM_ALGORITHM_ML_KEM_512`.
    KEM_ALGORITHM_ML_KEM_512 = 1000,
    /// `KEM_ALGORITHM_ML_KEM_768`.
    KEM_ALGORITHM_ML_KEM_768 = 1010,
    /// `KEM_ALGORITHM_ML_KEM_1024`.
    KEM_ALGORITHM_ML_KEM_1024 = 1020,
    /// `KEM_ALGORITHM_X_WING_768`.
    KEM_ALGORITHM_X_WING_768 = 1100,
}
impl KemAlgorithm {
    /// Idiomatic alias for [`Self::KEM_ALGORITHM_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::KEM_ALGORITHM_UNSPECIFIED;
    /// Idiomatic alias for [`Self::KEM_ALGORITHM_ML_KEM_512`].
    #[allow(non_upper_case_globals)]
    pub const MlKem512: Self = Self::KEM_ALGORITHM_ML_KEM_512;
    /// Idiomatic alias for [`Self::KEM_ALGORITHM_ML_KEM_768`].
    #[allow(non_upper_case_globals)]
    pub const MlKem768: Self = Self::KEM_ALGORITHM_ML_KEM_768;
    /// Idiomatic alias for [`Self::KEM_ALGORITHM_ML_KEM_1024`].
    #[allow(non_upper_case_globals)]
    pub const MlKem1024: Self = Self::KEM_ALGORITHM_ML_KEM_1024;
    /// Idiomatic alias for [`Self::KEM_ALGORITHM_X_WING_768`].
    #[allow(non_upper_case_globals)]
    pub const XWing768: Self = Self::KEM_ALGORITHM_X_WING_768;
}
impl ::buffa::Enumeration for KemAlgorithm {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::KEM_ALGORITHM_UNSPECIFIED),
            1000 => Some(Self::KEM_ALGORITHM_ML_KEM_512),
            1010 => Some(Self::KEM_ALGORITHM_ML_KEM_768),
            1020 => Some(Self::KEM_ALGORITHM_ML_KEM_1024),
            1100 => Some(Self::KEM_ALGORITHM_X_WING_768),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::KEM_ALGORITHM_UNSPECIFIED => "KEM_ALGORITHM_UNSPECIFIED",
            Self::KEM_ALGORITHM_ML_KEM_512 => "KEM_ALGORITHM_ML_KEM_512",
            Self::KEM_ALGORITHM_ML_KEM_768 => "KEM_ALGORITHM_ML_KEM_768",
            Self::KEM_ALGORITHM_ML_KEM_1024 => "KEM_ALGORITHM_ML_KEM_1024",
            Self::KEM_ALGORITHM_X_WING_768 => "KEM_ALGORITHM_X_WING_768",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "KEM_ALGORITHM_UNSPECIFIED" => Some(Self::KEM_ALGORITHM_UNSPECIFIED),
            "KEM_ALGORITHM_ML_KEM_512" => Some(Self::KEM_ALGORITHM_ML_KEM_512),
            "KEM_ALGORITHM_ML_KEM_768" => Some(Self::KEM_ALGORITHM_ML_KEM_768),
            "KEM_ALGORITHM_ML_KEM_1024" => Some(Self::KEM_ALGORITHM_ML_KEM_1024),
            "KEM_ALGORITHM_X_WING_768" => Some(Self::KEM_ALGORITHM_X_WING_768),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::KEM_ALGORITHM_UNSPECIFIED,
            Self::KEM_ALGORITHM_ML_KEM_512,
            Self::KEM_ALGORITHM_ML_KEM_768,
            Self::KEM_ALGORITHM_ML_KEM_1024,
            Self::KEM_ALGORITHM_X_WING_768,
        ]
    }
}
impl ::zeroize::Zeroize for KemAlgorithm {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for KemAlgorithm {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for KemAlgorithm {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for KemAlgorithm {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.HpkeKemId`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum HpkeKemId {
    /// `HPKE_KEM_ID_UNSPECIFIED`.
    #[default]
    HPKE_KEM_ID_UNSPECIFIED = 0,
    /// `HPKE_KEM_ID_DHKEM_P256_HKDF_SHA256`.
    HPKE_KEM_ID_DHKEM_P256_HKDF_SHA256 = 16,
    /// `HPKE_KEM_ID_DHKEM_P384_HKDF_SHA384`.
    HPKE_KEM_ID_DHKEM_P384_HKDF_SHA384 = 17,
    /// `HPKE_KEM_ID_DHKEM_P521_HKDF_SHA512`.
    HPKE_KEM_ID_DHKEM_P521_HKDF_SHA512 = 18,
    /// `HPKE_KEM_ID_DHKEM_CP256_HKDF_SHA256`.
    HPKE_KEM_ID_DHKEM_CP256_HKDF_SHA256 = 19,
    /// `HPKE_KEM_ID_DHKEM_CP384_HKDF_SHA384`.
    HPKE_KEM_ID_DHKEM_CP384_HKDF_SHA384 = 20,
    /// `HPKE_KEM_ID_DHKEM_CP521_HKDF_SHA512`.
    HPKE_KEM_ID_DHKEM_CP521_HKDF_SHA512 = 21,
    /// `HPKE_KEM_ID_DHKEM_SECP256K1_HKDF_SHA256`.
    HPKE_KEM_ID_DHKEM_SECP256K1_HKDF_SHA256 = 22,
    /// `HPKE_KEM_ID_DHKEM_X25519_HKDF_SHA256`.
    HPKE_KEM_ID_DHKEM_X25519_HKDF_SHA256 = 32,
    /// `HPKE_KEM_ID_DHKEM_X448_HKDF_SHA512`.
    HPKE_KEM_ID_DHKEM_X448_HKDF_SHA512 = 33,
    /// `HPKE_KEM_ID_DHKEM_X25519_ELLIGATOR_HKDF_SHA256`.
    HPKE_KEM_ID_DHKEM_X25519_ELLIGATOR_HKDF_SHA256 = 34,
    /// `HPKE_KEM_ID_X25519_KYBER768_DRAFT00`.
    HPKE_KEM_ID_X25519_KYBER768_DRAFT00 = 48,
    /// `HPKE_KEM_ID_ML_KEM_512`.
    HPKE_KEM_ID_ML_KEM_512 = 64,
    /// `HPKE_KEM_ID_ML_KEM_768`.
    HPKE_KEM_ID_ML_KEM_768 = 65,
    /// `HPKE_KEM_ID_ML_KEM_1024`.
    HPKE_KEM_ID_ML_KEM_1024 = 66,
    /// `HPKE_KEM_ID_ML_KEM_768_P256`.
    HPKE_KEM_ID_ML_KEM_768_P256 = 80,
    /// `HPKE_KEM_ID_ML_KEM_1024_P384`.
    HPKE_KEM_ID_ML_KEM_1024_P384 = 81,
    /// `HPKE_KEM_ID_X_WING`.
    HPKE_KEM_ID_X_WING = 25722,
}
impl HpkeKemId {
    /// Idiomatic alias for [`Self::HPKE_KEM_ID_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::HPKE_KEM_ID_UNSPECIFIED;
    /// Idiomatic alias for [`Self::HPKE_KEM_ID_DHKEM_P256_HKDF_SHA256`].
    #[allow(non_upper_case_globals)]
    pub const DhkemP256HkdfSha256: Self = Self::HPKE_KEM_ID_DHKEM_P256_HKDF_SHA256;
    /// Idiomatic alias for [`Self::HPKE_KEM_ID_DHKEM_P384_HKDF_SHA384`].
    #[allow(non_upper_case_globals)]
    pub const DhkemP384HkdfSha384: Self = Self::HPKE_KEM_ID_DHKEM_P384_HKDF_SHA384;
    /// Idiomatic alias for [`Self::HPKE_KEM_ID_DHKEM_P521_HKDF_SHA512`].
    #[allow(non_upper_case_globals)]
    pub const DhkemP521HkdfSha512: Self = Self::HPKE_KEM_ID_DHKEM_P521_HKDF_SHA512;
    /// Idiomatic alias for [`Self::HPKE_KEM_ID_DHKEM_CP256_HKDF_SHA256`].
    #[allow(non_upper_case_globals)]
    pub const DhkemCp256HkdfSha256: Self = Self::HPKE_KEM_ID_DHKEM_CP256_HKDF_SHA256;
    /// Idiomatic alias for [`Self::HPKE_KEM_ID_DHKEM_CP384_HKDF_SHA384`].
    #[allow(non_upper_case_globals)]
    pub const DhkemCp384HkdfSha384: Self = Self::HPKE_KEM_ID_DHKEM_CP384_HKDF_SHA384;
    /// Idiomatic alias for [`Self::HPKE_KEM_ID_DHKEM_CP521_HKDF_SHA512`].
    #[allow(non_upper_case_globals)]
    pub const DhkemCp521HkdfSha512: Self = Self::HPKE_KEM_ID_DHKEM_CP521_HKDF_SHA512;
    /// Idiomatic alias for [`Self::HPKE_KEM_ID_DHKEM_SECP256K1_HKDF_SHA256`].
    #[allow(non_upper_case_globals)]
    pub const DhkemSecp256k1HkdfSha256: Self = Self::HPKE_KEM_ID_DHKEM_SECP256K1_HKDF_SHA256;
    /// Idiomatic alias for [`Self::HPKE_KEM_ID_DHKEM_X25519_HKDF_SHA256`].
    #[allow(non_upper_case_globals)]
    pub const DhkemX25519HkdfSha256: Self = Self::HPKE_KEM_ID_DHKEM_X25519_HKDF_SHA256;
    /// Idiomatic alias for [`Self::HPKE_KEM_ID_DHKEM_X448_HKDF_SHA512`].
    #[allow(non_upper_case_globals)]
    pub const DhkemX448HkdfSha512: Self = Self::HPKE_KEM_ID_DHKEM_X448_HKDF_SHA512;
    /// Idiomatic alias for [`Self::HPKE_KEM_ID_DHKEM_X25519_ELLIGATOR_HKDF_SHA256`].
    #[allow(non_upper_case_globals)]
    pub const DhkemX25519ElligatorHkdfSha256: Self =
        Self::HPKE_KEM_ID_DHKEM_X25519_ELLIGATOR_HKDF_SHA256;
    /// Idiomatic alias for [`Self::HPKE_KEM_ID_X25519_KYBER768_DRAFT00`].
    #[allow(non_upper_case_globals)]
    pub const X25519Kyber768Draft00: Self = Self::HPKE_KEM_ID_X25519_KYBER768_DRAFT00;
    /// Idiomatic alias for [`Self::HPKE_KEM_ID_ML_KEM_512`].
    #[allow(non_upper_case_globals)]
    pub const MlKem512: Self = Self::HPKE_KEM_ID_ML_KEM_512;
    /// Idiomatic alias for [`Self::HPKE_KEM_ID_ML_KEM_768`].
    #[allow(non_upper_case_globals)]
    pub const MlKem768: Self = Self::HPKE_KEM_ID_ML_KEM_768;
    /// Idiomatic alias for [`Self::HPKE_KEM_ID_ML_KEM_1024`].
    #[allow(non_upper_case_globals)]
    pub const MlKem1024: Self = Self::HPKE_KEM_ID_ML_KEM_1024;
    /// Idiomatic alias for [`Self::HPKE_KEM_ID_ML_KEM_768_P256`].
    #[allow(non_upper_case_globals)]
    pub const MlKem768P256: Self = Self::HPKE_KEM_ID_ML_KEM_768_P256;
    /// Idiomatic alias for [`Self::HPKE_KEM_ID_ML_KEM_1024_P384`].
    #[allow(non_upper_case_globals)]
    pub const MlKem1024P384: Self = Self::HPKE_KEM_ID_ML_KEM_1024_P384;
    /// Idiomatic alias for [`Self::HPKE_KEM_ID_X_WING`].
    #[allow(non_upper_case_globals)]
    pub const XWing: Self = Self::HPKE_KEM_ID_X_WING;
}
impl ::buffa::Enumeration for HpkeKemId {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::HPKE_KEM_ID_UNSPECIFIED),
            16 => Some(Self::HPKE_KEM_ID_DHKEM_P256_HKDF_SHA256),
            17 => Some(Self::HPKE_KEM_ID_DHKEM_P384_HKDF_SHA384),
            18 => Some(Self::HPKE_KEM_ID_DHKEM_P521_HKDF_SHA512),
            19 => Some(Self::HPKE_KEM_ID_DHKEM_CP256_HKDF_SHA256),
            20 => Some(Self::HPKE_KEM_ID_DHKEM_CP384_HKDF_SHA384),
            21 => Some(Self::HPKE_KEM_ID_DHKEM_CP521_HKDF_SHA512),
            22 => Some(Self::HPKE_KEM_ID_DHKEM_SECP256K1_HKDF_SHA256),
            32 => Some(Self::HPKE_KEM_ID_DHKEM_X25519_HKDF_SHA256),
            33 => Some(Self::HPKE_KEM_ID_DHKEM_X448_HKDF_SHA512),
            34 => Some(Self::HPKE_KEM_ID_DHKEM_X25519_ELLIGATOR_HKDF_SHA256),
            48 => Some(Self::HPKE_KEM_ID_X25519_KYBER768_DRAFT00),
            64 => Some(Self::HPKE_KEM_ID_ML_KEM_512),
            65 => Some(Self::HPKE_KEM_ID_ML_KEM_768),
            66 => Some(Self::HPKE_KEM_ID_ML_KEM_1024),
            80 => Some(Self::HPKE_KEM_ID_ML_KEM_768_P256),
            81 => Some(Self::HPKE_KEM_ID_ML_KEM_1024_P384),
            25722 => Some(Self::HPKE_KEM_ID_X_WING),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::HPKE_KEM_ID_UNSPECIFIED => "HPKE_KEM_ID_UNSPECIFIED",
            Self::HPKE_KEM_ID_DHKEM_P256_HKDF_SHA256 => "HPKE_KEM_ID_DHKEM_P256_HKDF_SHA256",
            Self::HPKE_KEM_ID_DHKEM_P384_HKDF_SHA384 => "HPKE_KEM_ID_DHKEM_P384_HKDF_SHA384",
            Self::HPKE_KEM_ID_DHKEM_P521_HKDF_SHA512 => "HPKE_KEM_ID_DHKEM_P521_HKDF_SHA512",
            Self::HPKE_KEM_ID_DHKEM_CP256_HKDF_SHA256 => "HPKE_KEM_ID_DHKEM_CP256_HKDF_SHA256",
            Self::HPKE_KEM_ID_DHKEM_CP384_HKDF_SHA384 => "HPKE_KEM_ID_DHKEM_CP384_HKDF_SHA384",
            Self::HPKE_KEM_ID_DHKEM_CP521_HKDF_SHA512 => "HPKE_KEM_ID_DHKEM_CP521_HKDF_SHA512",
            Self::HPKE_KEM_ID_DHKEM_SECP256K1_HKDF_SHA256 => {
                "HPKE_KEM_ID_DHKEM_SECP256K1_HKDF_SHA256"
            }
            Self::HPKE_KEM_ID_DHKEM_X25519_HKDF_SHA256 => "HPKE_KEM_ID_DHKEM_X25519_HKDF_SHA256",
            Self::HPKE_KEM_ID_DHKEM_X448_HKDF_SHA512 => "HPKE_KEM_ID_DHKEM_X448_HKDF_SHA512",
            Self::HPKE_KEM_ID_DHKEM_X25519_ELLIGATOR_HKDF_SHA256 => {
                "HPKE_KEM_ID_DHKEM_X25519_ELLIGATOR_HKDF_SHA256"
            }
            Self::HPKE_KEM_ID_X25519_KYBER768_DRAFT00 => "HPKE_KEM_ID_X25519_KYBER768_DRAFT00",
            Self::HPKE_KEM_ID_ML_KEM_512 => "HPKE_KEM_ID_ML_KEM_512",
            Self::HPKE_KEM_ID_ML_KEM_768 => "HPKE_KEM_ID_ML_KEM_768",
            Self::HPKE_KEM_ID_ML_KEM_1024 => "HPKE_KEM_ID_ML_KEM_1024",
            Self::HPKE_KEM_ID_ML_KEM_768_P256 => "HPKE_KEM_ID_ML_KEM_768_P256",
            Self::HPKE_KEM_ID_ML_KEM_1024_P384 => "HPKE_KEM_ID_ML_KEM_1024_P384",
            Self::HPKE_KEM_ID_X_WING => "HPKE_KEM_ID_X_WING",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "HPKE_KEM_ID_UNSPECIFIED" => Some(Self::HPKE_KEM_ID_UNSPECIFIED),
            "HPKE_KEM_ID_DHKEM_P256_HKDF_SHA256" => Some(Self::HPKE_KEM_ID_DHKEM_P256_HKDF_SHA256),
            "HPKE_KEM_ID_DHKEM_P384_HKDF_SHA384" => Some(Self::HPKE_KEM_ID_DHKEM_P384_HKDF_SHA384),
            "HPKE_KEM_ID_DHKEM_P521_HKDF_SHA512" => Some(Self::HPKE_KEM_ID_DHKEM_P521_HKDF_SHA512),
            "HPKE_KEM_ID_DHKEM_CP256_HKDF_SHA256" => {
                Some(Self::HPKE_KEM_ID_DHKEM_CP256_HKDF_SHA256)
            }
            "HPKE_KEM_ID_DHKEM_CP384_HKDF_SHA384" => {
                Some(Self::HPKE_KEM_ID_DHKEM_CP384_HKDF_SHA384)
            }
            "HPKE_KEM_ID_DHKEM_CP521_HKDF_SHA512" => {
                Some(Self::HPKE_KEM_ID_DHKEM_CP521_HKDF_SHA512)
            }
            "HPKE_KEM_ID_DHKEM_SECP256K1_HKDF_SHA256" => {
                Some(Self::HPKE_KEM_ID_DHKEM_SECP256K1_HKDF_SHA256)
            }
            "HPKE_KEM_ID_DHKEM_X25519_HKDF_SHA256" => {
                Some(Self::HPKE_KEM_ID_DHKEM_X25519_HKDF_SHA256)
            }
            "HPKE_KEM_ID_DHKEM_X448_HKDF_SHA512" => Some(Self::HPKE_KEM_ID_DHKEM_X448_HKDF_SHA512),
            "HPKE_KEM_ID_DHKEM_X25519_ELLIGATOR_HKDF_SHA256" => {
                Some(Self::HPKE_KEM_ID_DHKEM_X25519_ELLIGATOR_HKDF_SHA256)
            }
            "HPKE_KEM_ID_X25519_KYBER768_DRAFT00" => {
                Some(Self::HPKE_KEM_ID_X25519_KYBER768_DRAFT00)
            }
            "HPKE_KEM_ID_ML_KEM_512" => Some(Self::HPKE_KEM_ID_ML_KEM_512),
            "HPKE_KEM_ID_ML_KEM_768" => Some(Self::HPKE_KEM_ID_ML_KEM_768),
            "HPKE_KEM_ID_ML_KEM_1024" => Some(Self::HPKE_KEM_ID_ML_KEM_1024),
            "HPKE_KEM_ID_ML_KEM_768_P256" => Some(Self::HPKE_KEM_ID_ML_KEM_768_P256),
            "HPKE_KEM_ID_ML_KEM_1024_P384" => Some(Self::HPKE_KEM_ID_ML_KEM_1024_P384),
            "HPKE_KEM_ID_X_WING" => Some(Self::HPKE_KEM_ID_X_WING),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::HPKE_KEM_ID_UNSPECIFIED,
            Self::HPKE_KEM_ID_DHKEM_P256_HKDF_SHA256,
            Self::HPKE_KEM_ID_DHKEM_P384_HKDF_SHA384,
            Self::HPKE_KEM_ID_DHKEM_P521_HKDF_SHA512,
            Self::HPKE_KEM_ID_DHKEM_CP256_HKDF_SHA256,
            Self::HPKE_KEM_ID_DHKEM_CP384_HKDF_SHA384,
            Self::HPKE_KEM_ID_DHKEM_CP521_HKDF_SHA512,
            Self::HPKE_KEM_ID_DHKEM_SECP256K1_HKDF_SHA256,
            Self::HPKE_KEM_ID_DHKEM_X25519_HKDF_SHA256,
            Self::HPKE_KEM_ID_DHKEM_X448_HKDF_SHA512,
            Self::HPKE_KEM_ID_DHKEM_X25519_ELLIGATOR_HKDF_SHA256,
            Self::HPKE_KEM_ID_X25519_KYBER768_DRAFT00,
            Self::HPKE_KEM_ID_ML_KEM_512,
            Self::HPKE_KEM_ID_ML_KEM_768,
            Self::HPKE_KEM_ID_ML_KEM_1024,
            Self::HPKE_KEM_ID_ML_KEM_768_P256,
            Self::HPKE_KEM_ID_ML_KEM_1024_P384,
            Self::HPKE_KEM_ID_X_WING,
        ]
    }
}
impl ::zeroize::Zeroize for HpkeKemId {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for HpkeKemId {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for HpkeKemId {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for HpkeKemId {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.HpkeKdfId`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum HpkeKdfId {
    /// `HPKE_KDF_ID_UNSPECIFIED`.
    #[default]
    HPKE_KDF_ID_UNSPECIFIED = 0,
    /// `HPKE_KDF_ID_HKDF_SHA256`.
    HPKE_KDF_ID_HKDF_SHA256 = 1,
    /// `HPKE_KDF_ID_HKDF_SHA384`.
    HPKE_KDF_ID_HKDF_SHA384 = 2,
    /// `HPKE_KDF_ID_HKDF_SHA512`.
    HPKE_KDF_ID_HKDF_SHA512 = 3,
    /// `HPKE_KDF_ID_SHAKE128`.
    HPKE_KDF_ID_SHAKE128 = 16,
    /// `HPKE_KDF_ID_SHAKE256`.
    HPKE_KDF_ID_SHAKE256 = 17,
    /// `HPKE_KDF_ID_TURBO_SHAKE128`.
    HPKE_KDF_ID_TURBO_SHAKE128 = 18,
    /// `HPKE_KDF_ID_TURBO_SHAKE256`.
    HPKE_KDF_ID_TURBO_SHAKE256 = 19,
}
impl HpkeKdfId {
    /// Idiomatic alias for [`Self::HPKE_KDF_ID_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::HPKE_KDF_ID_UNSPECIFIED;
    /// Idiomatic alias for [`Self::HPKE_KDF_ID_HKDF_SHA256`].
    #[allow(non_upper_case_globals)]
    pub const HkdfSha256: Self = Self::HPKE_KDF_ID_HKDF_SHA256;
    /// Idiomatic alias for [`Self::HPKE_KDF_ID_HKDF_SHA384`].
    #[allow(non_upper_case_globals)]
    pub const HkdfSha384: Self = Self::HPKE_KDF_ID_HKDF_SHA384;
    /// Idiomatic alias for [`Self::HPKE_KDF_ID_HKDF_SHA512`].
    #[allow(non_upper_case_globals)]
    pub const HkdfSha512: Self = Self::HPKE_KDF_ID_HKDF_SHA512;
    /// Idiomatic alias for [`Self::HPKE_KDF_ID_SHAKE128`].
    #[allow(non_upper_case_globals)]
    pub const Shake128: Self = Self::HPKE_KDF_ID_SHAKE128;
    /// Idiomatic alias for [`Self::HPKE_KDF_ID_SHAKE256`].
    #[allow(non_upper_case_globals)]
    pub const Shake256: Self = Self::HPKE_KDF_ID_SHAKE256;
    /// Idiomatic alias for [`Self::HPKE_KDF_ID_TURBO_SHAKE128`].
    #[allow(non_upper_case_globals)]
    pub const TurboShake128: Self = Self::HPKE_KDF_ID_TURBO_SHAKE128;
    /// Idiomatic alias for [`Self::HPKE_KDF_ID_TURBO_SHAKE256`].
    #[allow(non_upper_case_globals)]
    pub const TurboShake256: Self = Self::HPKE_KDF_ID_TURBO_SHAKE256;
}
impl ::buffa::Enumeration for HpkeKdfId {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::HPKE_KDF_ID_UNSPECIFIED),
            1 => Some(Self::HPKE_KDF_ID_HKDF_SHA256),
            2 => Some(Self::HPKE_KDF_ID_HKDF_SHA384),
            3 => Some(Self::HPKE_KDF_ID_HKDF_SHA512),
            16 => Some(Self::HPKE_KDF_ID_SHAKE128),
            17 => Some(Self::HPKE_KDF_ID_SHAKE256),
            18 => Some(Self::HPKE_KDF_ID_TURBO_SHAKE128),
            19 => Some(Self::HPKE_KDF_ID_TURBO_SHAKE256),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::HPKE_KDF_ID_UNSPECIFIED => "HPKE_KDF_ID_UNSPECIFIED",
            Self::HPKE_KDF_ID_HKDF_SHA256 => "HPKE_KDF_ID_HKDF_SHA256",
            Self::HPKE_KDF_ID_HKDF_SHA384 => "HPKE_KDF_ID_HKDF_SHA384",
            Self::HPKE_KDF_ID_HKDF_SHA512 => "HPKE_KDF_ID_HKDF_SHA512",
            Self::HPKE_KDF_ID_SHAKE128 => "HPKE_KDF_ID_SHAKE128",
            Self::HPKE_KDF_ID_SHAKE256 => "HPKE_KDF_ID_SHAKE256",
            Self::HPKE_KDF_ID_TURBO_SHAKE128 => "HPKE_KDF_ID_TURBO_SHAKE128",
            Self::HPKE_KDF_ID_TURBO_SHAKE256 => "HPKE_KDF_ID_TURBO_SHAKE256",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "HPKE_KDF_ID_UNSPECIFIED" => Some(Self::HPKE_KDF_ID_UNSPECIFIED),
            "HPKE_KDF_ID_HKDF_SHA256" => Some(Self::HPKE_KDF_ID_HKDF_SHA256),
            "HPKE_KDF_ID_HKDF_SHA384" => Some(Self::HPKE_KDF_ID_HKDF_SHA384),
            "HPKE_KDF_ID_HKDF_SHA512" => Some(Self::HPKE_KDF_ID_HKDF_SHA512),
            "HPKE_KDF_ID_SHAKE128" => Some(Self::HPKE_KDF_ID_SHAKE128),
            "HPKE_KDF_ID_SHAKE256" => Some(Self::HPKE_KDF_ID_SHAKE256),
            "HPKE_KDF_ID_TURBO_SHAKE128" => Some(Self::HPKE_KDF_ID_TURBO_SHAKE128),
            "HPKE_KDF_ID_TURBO_SHAKE256" => Some(Self::HPKE_KDF_ID_TURBO_SHAKE256),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::HPKE_KDF_ID_UNSPECIFIED,
            Self::HPKE_KDF_ID_HKDF_SHA256,
            Self::HPKE_KDF_ID_HKDF_SHA384,
            Self::HPKE_KDF_ID_HKDF_SHA512,
            Self::HPKE_KDF_ID_SHAKE128,
            Self::HPKE_KDF_ID_SHAKE256,
            Self::HPKE_KDF_ID_TURBO_SHAKE128,
            Self::HPKE_KDF_ID_TURBO_SHAKE256,
        ]
    }
}
impl ::zeroize::Zeroize for HpkeKdfId {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for HpkeKdfId {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for HpkeKdfId {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for HpkeKdfId {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.HpkeAeadId`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum HpkeAeadId {
    /// `HPKE_AEAD_ID_UNSPECIFIED`.
    #[default]
    HPKE_AEAD_ID_UNSPECIFIED = 0,
    /// `HPKE_AEAD_ID_AES_128_GCM`.
    HPKE_AEAD_ID_AES_128_GCM = 1,
    /// `HPKE_AEAD_ID_AES_256_GCM`.
    HPKE_AEAD_ID_AES_256_GCM = 2,
    /// `HPKE_AEAD_ID_CHACHA20_POLY1305`.
    HPKE_AEAD_ID_CHACHA20_POLY1305 = 3,
    /// `HPKE_AEAD_ID_EXPORT_ONLY`.
    HPKE_AEAD_ID_EXPORT_ONLY = 65535,
}
impl HpkeAeadId {
    /// Idiomatic alias for [`Self::HPKE_AEAD_ID_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::HPKE_AEAD_ID_UNSPECIFIED;
    /// Idiomatic alias for [`Self::HPKE_AEAD_ID_AES_128_GCM`].
    #[allow(non_upper_case_globals)]
    pub const Aes128Gcm: Self = Self::HPKE_AEAD_ID_AES_128_GCM;
    /// Idiomatic alias for [`Self::HPKE_AEAD_ID_AES_256_GCM`].
    #[allow(non_upper_case_globals)]
    pub const Aes256Gcm: Self = Self::HPKE_AEAD_ID_AES_256_GCM;
    /// Idiomatic alias for [`Self::HPKE_AEAD_ID_CHACHA20_POLY1305`].
    #[allow(non_upper_case_globals)]
    pub const Chacha20Poly1305: Self = Self::HPKE_AEAD_ID_CHACHA20_POLY1305;
    /// Idiomatic alias for [`Self::HPKE_AEAD_ID_EXPORT_ONLY`].
    #[allow(non_upper_case_globals)]
    pub const ExportOnly: Self = Self::HPKE_AEAD_ID_EXPORT_ONLY;
}
impl ::buffa::Enumeration for HpkeAeadId {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::HPKE_AEAD_ID_UNSPECIFIED),
            1 => Some(Self::HPKE_AEAD_ID_AES_128_GCM),
            2 => Some(Self::HPKE_AEAD_ID_AES_256_GCM),
            3 => Some(Self::HPKE_AEAD_ID_CHACHA20_POLY1305),
            65535 => Some(Self::HPKE_AEAD_ID_EXPORT_ONLY),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::HPKE_AEAD_ID_UNSPECIFIED => "HPKE_AEAD_ID_UNSPECIFIED",
            Self::HPKE_AEAD_ID_AES_128_GCM => "HPKE_AEAD_ID_AES_128_GCM",
            Self::HPKE_AEAD_ID_AES_256_GCM => "HPKE_AEAD_ID_AES_256_GCM",
            Self::HPKE_AEAD_ID_CHACHA20_POLY1305 => "HPKE_AEAD_ID_CHACHA20_POLY1305",
            Self::HPKE_AEAD_ID_EXPORT_ONLY => "HPKE_AEAD_ID_EXPORT_ONLY",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "HPKE_AEAD_ID_UNSPECIFIED" => Some(Self::HPKE_AEAD_ID_UNSPECIFIED),
            "HPKE_AEAD_ID_AES_128_GCM" => Some(Self::HPKE_AEAD_ID_AES_128_GCM),
            "HPKE_AEAD_ID_AES_256_GCM" => Some(Self::HPKE_AEAD_ID_AES_256_GCM),
            "HPKE_AEAD_ID_CHACHA20_POLY1305" => Some(Self::HPKE_AEAD_ID_CHACHA20_POLY1305),
            "HPKE_AEAD_ID_EXPORT_ONLY" => Some(Self::HPKE_AEAD_ID_EXPORT_ONLY),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::HPKE_AEAD_ID_UNSPECIFIED,
            Self::HPKE_AEAD_ID_AES_128_GCM,
            Self::HPKE_AEAD_ID_AES_256_GCM,
            Self::HPKE_AEAD_ID_CHACHA20_POLY1305,
            Self::HPKE_AEAD_ID_EXPORT_ONLY,
        ]
    }
}
impl ::zeroize::Zeroize for HpkeAeadId {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for HpkeAeadId {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for HpkeAeadId {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for HpkeAeadId {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.AeadAlgorithm`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum AeadAlgorithm {
    /// `AEAD_ALGORITHM_UNSPECIFIED`.
    #[default]
    AEAD_ALGORITHM_UNSPECIFIED = 0,
    /// `AEAD_ALGORITHM_AES_128_GCM`.
    AEAD_ALGORITHM_AES_128_GCM = 100,
    /// `AEAD_ALGORITHM_AES_192_GCM`.
    AEAD_ALGORITHM_AES_192_GCM = 110,
    /// `AEAD_ALGORITHM_AES_256_GCM`.
    AEAD_ALGORITHM_AES_256_GCM = 120,
    /// `AEAD_ALGORITHM_AES_256_GCM_SIV`.
    AEAD_ALGORITHM_AES_256_GCM_SIV = 130,
    /// `AEAD_ALGORITHM_CHACHA20_POLY1305`.
    AEAD_ALGORITHM_CHACHA20_POLY1305 = 200,
    /// `AEAD_ALGORITHM_XCHACHA20_POLY1305`.
    AEAD_ALGORITHM_XCHACHA20_POLY1305 = 210,
}
impl AeadAlgorithm {
    /// Idiomatic alias for [`Self::AEAD_ALGORITHM_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::AEAD_ALGORITHM_UNSPECIFIED;
    /// Idiomatic alias for [`Self::AEAD_ALGORITHM_AES_128_GCM`].
    #[allow(non_upper_case_globals)]
    pub const Aes128Gcm: Self = Self::AEAD_ALGORITHM_AES_128_GCM;
    /// Idiomatic alias for [`Self::AEAD_ALGORITHM_AES_192_GCM`].
    #[allow(non_upper_case_globals)]
    pub const Aes192Gcm: Self = Self::AEAD_ALGORITHM_AES_192_GCM;
    /// Idiomatic alias for [`Self::AEAD_ALGORITHM_AES_256_GCM`].
    #[allow(non_upper_case_globals)]
    pub const Aes256Gcm: Self = Self::AEAD_ALGORITHM_AES_256_GCM;
    /// Idiomatic alias for [`Self::AEAD_ALGORITHM_AES_256_GCM_SIV`].
    #[allow(non_upper_case_globals)]
    pub const Aes256GcmSiv: Self = Self::AEAD_ALGORITHM_AES_256_GCM_SIV;
    /// Idiomatic alias for [`Self::AEAD_ALGORITHM_CHACHA20_POLY1305`].
    #[allow(non_upper_case_globals)]
    pub const Chacha20Poly1305: Self = Self::AEAD_ALGORITHM_CHACHA20_POLY1305;
    /// Idiomatic alias for [`Self::AEAD_ALGORITHM_XCHACHA20_POLY1305`].
    #[allow(non_upper_case_globals)]
    pub const Xchacha20Poly1305: Self = Self::AEAD_ALGORITHM_XCHACHA20_POLY1305;
}
impl ::buffa::Enumeration for AeadAlgorithm {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::AEAD_ALGORITHM_UNSPECIFIED),
            100 => Some(Self::AEAD_ALGORITHM_AES_128_GCM),
            110 => Some(Self::AEAD_ALGORITHM_AES_192_GCM),
            120 => Some(Self::AEAD_ALGORITHM_AES_256_GCM),
            130 => Some(Self::AEAD_ALGORITHM_AES_256_GCM_SIV),
            200 => Some(Self::AEAD_ALGORITHM_CHACHA20_POLY1305),
            210 => Some(Self::AEAD_ALGORITHM_XCHACHA20_POLY1305),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::AEAD_ALGORITHM_UNSPECIFIED => "AEAD_ALGORITHM_UNSPECIFIED",
            Self::AEAD_ALGORITHM_AES_128_GCM => "AEAD_ALGORITHM_AES_128_GCM",
            Self::AEAD_ALGORITHM_AES_192_GCM => "AEAD_ALGORITHM_AES_192_GCM",
            Self::AEAD_ALGORITHM_AES_256_GCM => "AEAD_ALGORITHM_AES_256_GCM",
            Self::AEAD_ALGORITHM_AES_256_GCM_SIV => "AEAD_ALGORITHM_AES_256_GCM_SIV",
            Self::AEAD_ALGORITHM_CHACHA20_POLY1305 => "AEAD_ALGORITHM_CHACHA20_POLY1305",
            Self::AEAD_ALGORITHM_XCHACHA20_POLY1305 => "AEAD_ALGORITHM_XCHACHA20_POLY1305",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "AEAD_ALGORITHM_UNSPECIFIED" => Some(Self::AEAD_ALGORITHM_UNSPECIFIED),
            "AEAD_ALGORITHM_AES_128_GCM" => Some(Self::AEAD_ALGORITHM_AES_128_GCM),
            "AEAD_ALGORITHM_AES_192_GCM" => Some(Self::AEAD_ALGORITHM_AES_192_GCM),
            "AEAD_ALGORITHM_AES_256_GCM" => Some(Self::AEAD_ALGORITHM_AES_256_GCM),
            "AEAD_ALGORITHM_AES_256_GCM_SIV" => Some(Self::AEAD_ALGORITHM_AES_256_GCM_SIV),
            "AEAD_ALGORITHM_CHACHA20_POLY1305" => Some(Self::AEAD_ALGORITHM_CHACHA20_POLY1305),
            "AEAD_ALGORITHM_XCHACHA20_POLY1305" => Some(Self::AEAD_ALGORITHM_XCHACHA20_POLY1305),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::AEAD_ALGORITHM_UNSPECIFIED,
            Self::AEAD_ALGORITHM_AES_128_GCM,
            Self::AEAD_ALGORITHM_AES_192_GCM,
            Self::AEAD_ALGORITHM_AES_256_GCM,
            Self::AEAD_ALGORITHM_AES_256_GCM_SIV,
            Self::AEAD_ALGORITHM_CHACHA20_POLY1305,
            Self::AEAD_ALGORITHM_XCHACHA20_POLY1305,
        ]
    }
}
impl ::zeroize::Zeroize for AeadAlgorithm {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for AeadAlgorithm {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for AeadAlgorithm {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for AeadAlgorithm {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.HashAlgorithm`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum HashAlgorithm {
    /// `HASH_ALGORITHM_UNSPECIFIED`.
    #[default]
    HASH_ALGORITHM_UNSPECIFIED = 0,
    /// `HASH_ALGORITHM_SHA2_256`.
    HASH_ALGORITHM_SHA2_256 = 100,
    /// `HASH_ALGORITHM_SHA2_384`.
    HASH_ALGORITHM_SHA2_384 = 110,
    /// `HASH_ALGORITHM_SHA2_512`.
    HASH_ALGORITHM_SHA2_512 = 120,
    /// `HASH_ALGORITHM_SHA3_224`.
    HASH_ALGORITHM_SHA3_224 = 200,
    /// `HASH_ALGORITHM_SHA3_256`.
    HASH_ALGORITHM_SHA3_256 = 210,
    /// `HASH_ALGORITHM_SHA3_384`.
    HASH_ALGORITHM_SHA3_384 = 220,
    /// `HASH_ALGORITHM_SHA3_512`.
    HASH_ALGORITHM_SHA3_512 = 230,
}
impl HashAlgorithm {
    /// Idiomatic alias for [`Self::HASH_ALGORITHM_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::HASH_ALGORITHM_UNSPECIFIED;
    /// Idiomatic alias for [`Self::HASH_ALGORITHM_SHA2_256`].
    #[allow(non_upper_case_globals)]
    pub const Sha2256: Self = Self::HASH_ALGORITHM_SHA2_256;
    /// Idiomatic alias for [`Self::HASH_ALGORITHM_SHA2_384`].
    #[allow(non_upper_case_globals)]
    pub const Sha2384: Self = Self::HASH_ALGORITHM_SHA2_384;
    /// Idiomatic alias for [`Self::HASH_ALGORITHM_SHA2_512`].
    #[allow(non_upper_case_globals)]
    pub const Sha2512: Self = Self::HASH_ALGORITHM_SHA2_512;
    /// Idiomatic alias for [`Self::HASH_ALGORITHM_SHA3_224`].
    #[allow(non_upper_case_globals)]
    pub const Sha3224: Self = Self::HASH_ALGORITHM_SHA3_224;
    /// Idiomatic alias for [`Self::HASH_ALGORITHM_SHA3_256`].
    #[allow(non_upper_case_globals)]
    pub const Sha3256: Self = Self::HASH_ALGORITHM_SHA3_256;
    /// Idiomatic alias for [`Self::HASH_ALGORITHM_SHA3_384`].
    #[allow(non_upper_case_globals)]
    pub const Sha3384: Self = Self::HASH_ALGORITHM_SHA3_384;
    /// Idiomatic alias for [`Self::HASH_ALGORITHM_SHA3_512`].
    #[allow(non_upper_case_globals)]
    pub const Sha3512: Self = Self::HASH_ALGORITHM_SHA3_512;
}
impl ::buffa::Enumeration for HashAlgorithm {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::HASH_ALGORITHM_UNSPECIFIED),
            100 => Some(Self::HASH_ALGORITHM_SHA2_256),
            110 => Some(Self::HASH_ALGORITHM_SHA2_384),
            120 => Some(Self::HASH_ALGORITHM_SHA2_512),
            200 => Some(Self::HASH_ALGORITHM_SHA3_224),
            210 => Some(Self::HASH_ALGORITHM_SHA3_256),
            220 => Some(Self::HASH_ALGORITHM_SHA3_384),
            230 => Some(Self::HASH_ALGORITHM_SHA3_512),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::HASH_ALGORITHM_UNSPECIFIED => "HASH_ALGORITHM_UNSPECIFIED",
            Self::HASH_ALGORITHM_SHA2_256 => "HASH_ALGORITHM_SHA2_256",
            Self::HASH_ALGORITHM_SHA2_384 => "HASH_ALGORITHM_SHA2_384",
            Self::HASH_ALGORITHM_SHA2_512 => "HASH_ALGORITHM_SHA2_512",
            Self::HASH_ALGORITHM_SHA3_224 => "HASH_ALGORITHM_SHA3_224",
            Self::HASH_ALGORITHM_SHA3_256 => "HASH_ALGORITHM_SHA3_256",
            Self::HASH_ALGORITHM_SHA3_384 => "HASH_ALGORITHM_SHA3_384",
            Self::HASH_ALGORITHM_SHA3_512 => "HASH_ALGORITHM_SHA3_512",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "HASH_ALGORITHM_UNSPECIFIED" => Some(Self::HASH_ALGORITHM_UNSPECIFIED),
            "HASH_ALGORITHM_SHA2_256" => Some(Self::HASH_ALGORITHM_SHA2_256),
            "HASH_ALGORITHM_SHA2_384" => Some(Self::HASH_ALGORITHM_SHA2_384),
            "HASH_ALGORITHM_SHA2_512" => Some(Self::HASH_ALGORITHM_SHA2_512),
            "HASH_ALGORITHM_SHA3_224" => Some(Self::HASH_ALGORITHM_SHA3_224),
            "HASH_ALGORITHM_SHA3_256" => Some(Self::HASH_ALGORITHM_SHA3_256),
            "HASH_ALGORITHM_SHA3_384" => Some(Self::HASH_ALGORITHM_SHA3_384),
            "HASH_ALGORITHM_SHA3_512" => Some(Self::HASH_ALGORITHM_SHA3_512),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::HASH_ALGORITHM_UNSPECIFIED,
            Self::HASH_ALGORITHM_SHA2_256,
            Self::HASH_ALGORITHM_SHA2_384,
            Self::HASH_ALGORITHM_SHA2_512,
            Self::HASH_ALGORITHM_SHA3_224,
            Self::HASH_ALGORITHM_SHA3_256,
            Self::HASH_ALGORITHM_SHA3_384,
            Self::HASH_ALGORITHM_SHA3_512,
        ]
    }
}
impl ::zeroize::Zeroize for HashAlgorithm {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for HashAlgorithm {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for HashAlgorithm {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for HashAlgorithm {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.MacAlgorithm`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum MacAlgorithm {
    /// `MAC_ALGORITHM_UNSPECIFIED`.
    #[default]
    MAC_ALGORITHM_UNSPECIFIED = 0,
    /// `MAC_ALGORITHM_HMAC_SHA256`.
    MAC_ALGORITHM_HMAC_SHA256 = 100,
    /// `MAC_ALGORITHM_HMAC_SHA384`.
    MAC_ALGORITHM_HMAC_SHA384 = 110,
    /// `MAC_ALGORITHM_HMAC_SHA512`.
    MAC_ALGORITHM_HMAC_SHA512 = 120,
}
impl MacAlgorithm {
    /// Idiomatic alias for [`Self::MAC_ALGORITHM_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::MAC_ALGORITHM_UNSPECIFIED;
    /// Idiomatic alias for [`Self::MAC_ALGORITHM_HMAC_SHA256`].
    #[allow(non_upper_case_globals)]
    pub const HmacSha256: Self = Self::MAC_ALGORITHM_HMAC_SHA256;
    /// Idiomatic alias for [`Self::MAC_ALGORITHM_HMAC_SHA384`].
    #[allow(non_upper_case_globals)]
    pub const HmacSha384: Self = Self::MAC_ALGORITHM_HMAC_SHA384;
    /// Idiomatic alias for [`Self::MAC_ALGORITHM_HMAC_SHA512`].
    #[allow(non_upper_case_globals)]
    pub const HmacSha512: Self = Self::MAC_ALGORITHM_HMAC_SHA512;
}
impl ::buffa::Enumeration for MacAlgorithm {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::MAC_ALGORITHM_UNSPECIFIED),
            100 => Some(Self::MAC_ALGORITHM_HMAC_SHA256),
            110 => Some(Self::MAC_ALGORITHM_HMAC_SHA384),
            120 => Some(Self::MAC_ALGORITHM_HMAC_SHA512),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::MAC_ALGORITHM_UNSPECIFIED => "MAC_ALGORITHM_UNSPECIFIED",
            Self::MAC_ALGORITHM_HMAC_SHA256 => "MAC_ALGORITHM_HMAC_SHA256",
            Self::MAC_ALGORITHM_HMAC_SHA384 => "MAC_ALGORITHM_HMAC_SHA384",
            Self::MAC_ALGORITHM_HMAC_SHA512 => "MAC_ALGORITHM_HMAC_SHA512",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "MAC_ALGORITHM_UNSPECIFIED" => Some(Self::MAC_ALGORITHM_UNSPECIFIED),
            "MAC_ALGORITHM_HMAC_SHA256" => Some(Self::MAC_ALGORITHM_HMAC_SHA256),
            "MAC_ALGORITHM_HMAC_SHA384" => Some(Self::MAC_ALGORITHM_HMAC_SHA384),
            "MAC_ALGORITHM_HMAC_SHA512" => Some(Self::MAC_ALGORITHM_HMAC_SHA512),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::MAC_ALGORITHM_UNSPECIFIED,
            Self::MAC_ALGORITHM_HMAC_SHA256,
            Self::MAC_ALGORITHM_HMAC_SHA384,
            Self::MAC_ALGORITHM_HMAC_SHA512,
        ]
    }
}
impl ::zeroize::Zeroize for MacAlgorithm {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for MacAlgorithm {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for MacAlgorithm {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for MacAlgorithm {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.KdfAlgorithm`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum KdfAlgorithm {
    /// `KDF_ALGORITHM_UNSPECIFIED`.
    #[default]
    KDF_ALGORITHM_UNSPECIFIED = 0,
    /// `KDF_ALGORITHM_HKDF_SHA256`.
    KDF_ALGORITHM_HKDF_SHA256 = 100,
    /// `KDF_ALGORITHM_HKDF_SHA384`.
    KDF_ALGORITHM_HKDF_SHA384 = 110,
    /// `KDF_ALGORITHM_ARGON2ID`.
    KDF_ALGORITHM_ARGON2ID = 200,
    /// `KDF_ALGORITHM_PBKDF2_HMAC_SHA256`.
    KDF_ALGORITHM_PBKDF2_HMAC_SHA256 = 300,
    /// `KDF_ALGORITHM_PBKDF2_HMAC_SHA512`.
    KDF_ALGORITHM_PBKDF2_HMAC_SHA512 = 310,
    /// `KDF_ALGORITHM_JWA_CONCAT_KDF_SHA256`.
    KDF_ALGORITHM_JWA_CONCAT_KDF_SHA256 = 400,
    /// `KDF_ALGORITHM_KMAC_256`.
    KDF_ALGORITHM_KMAC_256 = 500,
}
impl KdfAlgorithm {
    /// Idiomatic alias for [`Self::KDF_ALGORITHM_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::KDF_ALGORITHM_UNSPECIFIED;
    /// Idiomatic alias for [`Self::KDF_ALGORITHM_HKDF_SHA256`].
    #[allow(non_upper_case_globals)]
    pub const HkdfSha256: Self = Self::KDF_ALGORITHM_HKDF_SHA256;
    /// Idiomatic alias for [`Self::KDF_ALGORITHM_HKDF_SHA384`].
    #[allow(non_upper_case_globals)]
    pub const HkdfSha384: Self = Self::KDF_ALGORITHM_HKDF_SHA384;
    /// Idiomatic alias for [`Self::KDF_ALGORITHM_ARGON2ID`].
    #[allow(non_upper_case_globals)]
    pub const Argon2id: Self = Self::KDF_ALGORITHM_ARGON2ID;
    /// Idiomatic alias for [`Self::KDF_ALGORITHM_PBKDF2_HMAC_SHA256`].
    #[allow(non_upper_case_globals)]
    pub const Pbkdf2HmacSha256: Self = Self::KDF_ALGORITHM_PBKDF2_HMAC_SHA256;
    /// Idiomatic alias for [`Self::KDF_ALGORITHM_PBKDF2_HMAC_SHA512`].
    #[allow(non_upper_case_globals)]
    pub const Pbkdf2HmacSha512: Self = Self::KDF_ALGORITHM_PBKDF2_HMAC_SHA512;
    /// Idiomatic alias for [`Self::KDF_ALGORITHM_JWA_CONCAT_KDF_SHA256`].
    #[allow(non_upper_case_globals)]
    pub const JwaConcatKdfSha256: Self = Self::KDF_ALGORITHM_JWA_CONCAT_KDF_SHA256;
    /// Idiomatic alias for [`Self::KDF_ALGORITHM_KMAC_256`].
    #[allow(non_upper_case_globals)]
    pub const Kmac256: Self = Self::KDF_ALGORITHM_KMAC_256;
}
impl ::buffa::Enumeration for KdfAlgorithm {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::KDF_ALGORITHM_UNSPECIFIED),
            100 => Some(Self::KDF_ALGORITHM_HKDF_SHA256),
            110 => Some(Self::KDF_ALGORITHM_HKDF_SHA384),
            200 => Some(Self::KDF_ALGORITHM_ARGON2ID),
            300 => Some(Self::KDF_ALGORITHM_PBKDF2_HMAC_SHA256),
            310 => Some(Self::KDF_ALGORITHM_PBKDF2_HMAC_SHA512),
            400 => Some(Self::KDF_ALGORITHM_JWA_CONCAT_KDF_SHA256),
            500 => Some(Self::KDF_ALGORITHM_KMAC_256),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::KDF_ALGORITHM_UNSPECIFIED => "KDF_ALGORITHM_UNSPECIFIED",
            Self::KDF_ALGORITHM_HKDF_SHA256 => "KDF_ALGORITHM_HKDF_SHA256",
            Self::KDF_ALGORITHM_HKDF_SHA384 => "KDF_ALGORITHM_HKDF_SHA384",
            Self::KDF_ALGORITHM_ARGON2ID => "KDF_ALGORITHM_ARGON2ID",
            Self::KDF_ALGORITHM_PBKDF2_HMAC_SHA256 => "KDF_ALGORITHM_PBKDF2_HMAC_SHA256",
            Self::KDF_ALGORITHM_PBKDF2_HMAC_SHA512 => "KDF_ALGORITHM_PBKDF2_HMAC_SHA512",
            Self::KDF_ALGORITHM_JWA_CONCAT_KDF_SHA256 => "KDF_ALGORITHM_JWA_CONCAT_KDF_SHA256",
            Self::KDF_ALGORITHM_KMAC_256 => "KDF_ALGORITHM_KMAC_256",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "KDF_ALGORITHM_UNSPECIFIED" => Some(Self::KDF_ALGORITHM_UNSPECIFIED),
            "KDF_ALGORITHM_HKDF_SHA256" => Some(Self::KDF_ALGORITHM_HKDF_SHA256),
            "KDF_ALGORITHM_HKDF_SHA384" => Some(Self::KDF_ALGORITHM_HKDF_SHA384),
            "KDF_ALGORITHM_ARGON2ID" => Some(Self::KDF_ALGORITHM_ARGON2ID),
            "KDF_ALGORITHM_PBKDF2_HMAC_SHA256" => Some(Self::KDF_ALGORITHM_PBKDF2_HMAC_SHA256),
            "KDF_ALGORITHM_PBKDF2_HMAC_SHA512" => Some(Self::KDF_ALGORITHM_PBKDF2_HMAC_SHA512),
            "KDF_ALGORITHM_JWA_CONCAT_KDF_SHA256" => {
                Some(Self::KDF_ALGORITHM_JWA_CONCAT_KDF_SHA256)
            }
            "KDF_ALGORITHM_KMAC_256" => Some(Self::KDF_ALGORITHM_KMAC_256),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::KDF_ALGORITHM_UNSPECIFIED,
            Self::KDF_ALGORITHM_HKDF_SHA256,
            Self::KDF_ALGORITHM_HKDF_SHA384,
            Self::KDF_ALGORITHM_ARGON2ID,
            Self::KDF_ALGORITHM_PBKDF2_HMAC_SHA256,
            Self::KDF_ALGORITHM_PBKDF2_HMAC_SHA512,
            Self::KDF_ALGORITHM_JWA_CONCAT_KDF_SHA256,
            Self::KDF_ALGORITHM_KMAC_256,
        ]
    }
}
impl ::zeroize::Zeroize for KdfAlgorithm {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for KdfAlgorithm {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for KdfAlgorithm {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for KdfAlgorithm {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.Argon2idKdfVersion`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum Argon2idKdfVersion {
    /// `ARGON2ID_KDF_VERSION_UNSPECIFIED`.
    #[default]
    ARGON2ID_KDF_VERSION_UNSPECIFIED = 0,
    /// `ARGON2ID_KDF_VERSION_V1`.
    ARGON2ID_KDF_VERSION_V1 = 1,
    /// `ARGON2ID_KDF_VERSION_V2`.
    ARGON2ID_KDF_VERSION_V2 = 2,
}
impl Argon2idKdfVersion {
    /// Idiomatic alias for [`Self::ARGON2ID_KDF_VERSION_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::ARGON2ID_KDF_VERSION_UNSPECIFIED;
    /// Idiomatic alias for [`Self::ARGON2ID_KDF_VERSION_V1`].
    #[allow(non_upper_case_globals)]
    pub const V1: Self = Self::ARGON2ID_KDF_VERSION_V1;
    /// Idiomatic alias for [`Self::ARGON2ID_KDF_VERSION_V2`].
    #[allow(non_upper_case_globals)]
    pub const V2: Self = Self::ARGON2ID_KDF_VERSION_V2;
}
impl ::buffa::Enumeration for Argon2idKdfVersion {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::ARGON2ID_KDF_VERSION_UNSPECIFIED),
            1 => Some(Self::ARGON2ID_KDF_VERSION_V1),
            2 => Some(Self::ARGON2ID_KDF_VERSION_V2),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::ARGON2ID_KDF_VERSION_UNSPECIFIED => "ARGON2ID_KDF_VERSION_UNSPECIFIED",
            Self::ARGON2ID_KDF_VERSION_V1 => "ARGON2ID_KDF_VERSION_V1",
            Self::ARGON2ID_KDF_VERSION_V2 => "ARGON2ID_KDF_VERSION_V2",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "ARGON2ID_KDF_VERSION_UNSPECIFIED" => Some(Self::ARGON2ID_KDF_VERSION_UNSPECIFIED),
            "ARGON2ID_KDF_VERSION_V1" => Some(Self::ARGON2ID_KDF_VERSION_V1),
            "ARGON2ID_KDF_VERSION_V2" => Some(Self::ARGON2ID_KDF_VERSION_V2),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::ARGON2ID_KDF_VERSION_UNSPECIFIED,
            Self::ARGON2ID_KDF_VERSION_V1,
            Self::ARGON2ID_KDF_VERSION_V2,
        ]
    }
}
impl ::zeroize::Zeroize for Argon2idKdfVersion {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for Argon2idKdfVersion {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for Argon2idKdfVersion {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for Argon2idKdfVersion {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.KeyWrapAlgorithm`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum KeyWrapAlgorithm {
    /// `KEY_WRAP_ALGORITHM_UNSPECIFIED`.
    #[default]
    KEY_WRAP_ALGORITHM_UNSPECIFIED = 0,
    /// `KEY_WRAP_ALGORITHM_AES_128_KW`.
    KEY_WRAP_ALGORITHM_AES_128_KW = 100,
    /// `KEY_WRAP_ALGORITHM_AES_192_KW`.
    KEY_WRAP_ALGORITHM_AES_192_KW = 110,
    /// `KEY_WRAP_ALGORITHM_AES_256_KW`.
    KEY_WRAP_ALGORITHM_AES_256_KW = 120,
}
impl KeyWrapAlgorithm {
    /// Idiomatic alias for [`Self::KEY_WRAP_ALGORITHM_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::KEY_WRAP_ALGORITHM_UNSPECIFIED;
    /// Idiomatic alias for [`Self::KEY_WRAP_ALGORITHM_AES_128_KW`].
    #[allow(non_upper_case_globals)]
    pub const Aes128Kw: Self = Self::KEY_WRAP_ALGORITHM_AES_128_KW;
    /// Idiomatic alias for [`Self::KEY_WRAP_ALGORITHM_AES_192_KW`].
    #[allow(non_upper_case_globals)]
    pub const Aes192Kw: Self = Self::KEY_WRAP_ALGORITHM_AES_192_KW;
    /// Idiomatic alias for [`Self::KEY_WRAP_ALGORITHM_AES_256_KW`].
    #[allow(non_upper_case_globals)]
    pub const Aes256Kw: Self = Self::KEY_WRAP_ALGORITHM_AES_256_KW;
}
impl ::buffa::Enumeration for KeyWrapAlgorithm {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::KEY_WRAP_ALGORITHM_UNSPECIFIED),
            100 => Some(Self::KEY_WRAP_ALGORITHM_AES_128_KW),
            110 => Some(Self::KEY_WRAP_ALGORITHM_AES_192_KW),
            120 => Some(Self::KEY_WRAP_ALGORITHM_AES_256_KW),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::KEY_WRAP_ALGORITHM_UNSPECIFIED => "KEY_WRAP_ALGORITHM_UNSPECIFIED",
            Self::KEY_WRAP_ALGORITHM_AES_128_KW => "KEY_WRAP_ALGORITHM_AES_128_KW",
            Self::KEY_WRAP_ALGORITHM_AES_192_KW => "KEY_WRAP_ALGORITHM_AES_192_KW",
            Self::KEY_WRAP_ALGORITHM_AES_256_KW => "KEY_WRAP_ALGORITHM_AES_256_KW",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "KEY_WRAP_ALGORITHM_UNSPECIFIED" => Some(Self::KEY_WRAP_ALGORITHM_UNSPECIFIED),
            "KEY_WRAP_ALGORITHM_AES_128_KW" => Some(Self::KEY_WRAP_ALGORITHM_AES_128_KW),
            "KEY_WRAP_ALGORITHM_AES_192_KW" => Some(Self::KEY_WRAP_ALGORITHM_AES_192_KW),
            "KEY_WRAP_ALGORITHM_AES_256_KW" => Some(Self::KEY_WRAP_ALGORITHM_AES_256_KW),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::KEY_WRAP_ALGORITHM_UNSPECIFIED,
            Self::KEY_WRAP_ALGORITHM_AES_128_KW,
            Self::KEY_WRAP_ALGORITHM_AES_192_KW,
            Self::KEY_WRAP_ALGORITHM_AES_256_KW,
        ]
    }
}
impl ::zeroize::Zeroize for KeyWrapAlgorithm {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for KeyWrapAlgorithm {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for KeyWrapAlgorithm {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for KeyWrapAlgorithm {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.MulticodecKeyAlgorithm`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum MulticodecKeyAlgorithm {
    /// `MULTICODEC_KEY_ALGORITHM_UNSPECIFIED`.
    #[default]
    MULTICODEC_KEY_ALGORITHM_UNSPECIFIED = 0,
    /// `MULTICODEC_KEY_ALGORITHM_ED25519_PUB`.
    MULTICODEC_KEY_ALGORITHM_ED25519_PUB = 1,
    /// `MULTICODEC_KEY_ALGORITHM_X25519_PUB`.
    MULTICODEC_KEY_ALGORITHM_X25519_PUB = 2,
    /// `MULTICODEC_KEY_ALGORITHM_SECP256K1_PUB`.
    MULTICODEC_KEY_ALGORITHM_SECP256K1_PUB = 3,
    /// `MULTICODEC_KEY_ALGORITHM_P256_PUB`.
    MULTICODEC_KEY_ALGORITHM_P256_PUB = 4,
    /// `MULTICODEC_KEY_ALGORITHM_P384_PUB`.
    MULTICODEC_KEY_ALGORITHM_P384_PUB = 5,
    /// `MULTICODEC_KEY_ALGORITHM_P521_PUB`.
    MULTICODEC_KEY_ALGORITHM_P521_PUB = 6,
    /// `MULTICODEC_KEY_ALGORITHM_ED448_PUB`.
    MULTICODEC_KEY_ALGORITHM_ED448_PUB = 7,
    /// `MULTICODEC_KEY_ALGORITHM_RSA_PUB`.
    MULTICODEC_KEY_ALGORITHM_RSA_PUB = 8,
    /// `MULTICODEC_KEY_ALGORITHM_ML_KEM_512_PUB`.
    MULTICODEC_KEY_ALGORITHM_ML_KEM_512_PUB = 9,
    /// `MULTICODEC_KEY_ALGORITHM_ML_KEM_768_PUB`.
    MULTICODEC_KEY_ALGORITHM_ML_KEM_768_PUB = 10,
    /// `MULTICODEC_KEY_ALGORITHM_ML_KEM_1024_PUB`.
    MULTICODEC_KEY_ALGORITHM_ML_KEM_1024_PUB = 11,
    /// `MULTICODEC_KEY_ALGORITHM_ML_DSA_44_PUB`.
    MULTICODEC_KEY_ALGORITHM_ML_DSA_44_PUB = 12,
    /// `MULTICODEC_KEY_ALGORITHM_ML_DSA_65_PUB`.
    MULTICODEC_KEY_ALGORITHM_ML_DSA_65_PUB = 13,
    /// `MULTICODEC_KEY_ALGORITHM_ML_DSA_87_PUB`.
    MULTICODEC_KEY_ALGORITHM_ML_DSA_87_PUB = 14,
    /// `MULTICODEC_KEY_ALGORITHM_ED25519_PRIV`.
    MULTICODEC_KEY_ALGORITHM_ED25519_PRIV = 15,
    /// `MULTICODEC_KEY_ALGORITHM_X25519_PRIV`.
    MULTICODEC_KEY_ALGORITHM_X25519_PRIV = 16,
    /// `MULTICODEC_KEY_ALGORITHM_SECP256K1_PRIV`.
    MULTICODEC_KEY_ALGORITHM_SECP256K1_PRIV = 17,
    /// `MULTICODEC_KEY_ALGORITHM_P256_PRIV`.
    MULTICODEC_KEY_ALGORITHM_P256_PRIV = 18,
    /// `MULTICODEC_KEY_ALGORITHM_P384_PRIV`.
    MULTICODEC_KEY_ALGORITHM_P384_PRIV = 19,
    /// `MULTICODEC_KEY_ALGORITHM_P521_PRIV`.
    MULTICODEC_KEY_ALGORITHM_P521_PRIV = 20,
    /// `MULTICODEC_KEY_ALGORITHM_ED448_PRIV`.
    MULTICODEC_KEY_ALGORITHM_ED448_PRIV = 21,
    /// `MULTICODEC_KEY_ALGORITHM_RSA_PRIV`.
    MULTICODEC_KEY_ALGORITHM_RSA_PRIV = 22,
    /// `MULTICODEC_KEY_ALGORITHM_ML_KEM_512_PRIV`.
    MULTICODEC_KEY_ALGORITHM_ML_KEM_512_PRIV = 23,
    /// `MULTICODEC_KEY_ALGORITHM_ML_KEM_768_PRIV`.
    MULTICODEC_KEY_ALGORITHM_ML_KEM_768_PRIV = 24,
    /// `MULTICODEC_KEY_ALGORITHM_ML_KEM_1024_PRIV`.
    MULTICODEC_KEY_ALGORITHM_ML_KEM_1024_PRIV = 25,
}
impl MulticodecKeyAlgorithm {
    /// Idiomatic alias for [`Self::MULTICODEC_KEY_ALGORITHM_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::MULTICODEC_KEY_ALGORITHM_UNSPECIFIED;
    /// Idiomatic alias for [`Self::MULTICODEC_KEY_ALGORITHM_ED25519_PUB`].
    #[allow(non_upper_case_globals)]
    pub const Ed25519Pub: Self = Self::MULTICODEC_KEY_ALGORITHM_ED25519_PUB;
    /// Idiomatic alias for [`Self::MULTICODEC_KEY_ALGORITHM_X25519_PUB`].
    #[allow(non_upper_case_globals)]
    pub const X25519Pub: Self = Self::MULTICODEC_KEY_ALGORITHM_X25519_PUB;
    /// Idiomatic alias for [`Self::MULTICODEC_KEY_ALGORITHM_SECP256K1_PUB`].
    #[allow(non_upper_case_globals)]
    pub const Secp256k1Pub: Self = Self::MULTICODEC_KEY_ALGORITHM_SECP256K1_PUB;
    /// Idiomatic alias for [`Self::MULTICODEC_KEY_ALGORITHM_P256_PUB`].
    #[allow(non_upper_case_globals)]
    pub const P256Pub: Self = Self::MULTICODEC_KEY_ALGORITHM_P256_PUB;
    /// Idiomatic alias for [`Self::MULTICODEC_KEY_ALGORITHM_P384_PUB`].
    #[allow(non_upper_case_globals)]
    pub const P384Pub: Self = Self::MULTICODEC_KEY_ALGORITHM_P384_PUB;
    /// Idiomatic alias for [`Self::MULTICODEC_KEY_ALGORITHM_P521_PUB`].
    #[allow(non_upper_case_globals)]
    pub const P521Pub: Self = Self::MULTICODEC_KEY_ALGORITHM_P521_PUB;
    /// Idiomatic alias for [`Self::MULTICODEC_KEY_ALGORITHM_ED448_PUB`].
    #[allow(non_upper_case_globals)]
    pub const Ed448Pub: Self = Self::MULTICODEC_KEY_ALGORITHM_ED448_PUB;
    /// Idiomatic alias for [`Self::MULTICODEC_KEY_ALGORITHM_RSA_PUB`].
    #[allow(non_upper_case_globals)]
    pub const RsaPub: Self = Self::MULTICODEC_KEY_ALGORITHM_RSA_PUB;
    /// Idiomatic alias for [`Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_512_PUB`].
    #[allow(non_upper_case_globals)]
    pub const MlKem512Pub: Self = Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_512_PUB;
    /// Idiomatic alias for [`Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_768_PUB`].
    #[allow(non_upper_case_globals)]
    pub const MlKem768Pub: Self = Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_768_PUB;
    /// Idiomatic alias for [`Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_1024_PUB`].
    #[allow(non_upper_case_globals)]
    pub const MlKem1024Pub: Self = Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_1024_PUB;
    /// Idiomatic alias for [`Self::MULTICODEC_KEY_ALGORITHM_ML_DSA_44_PUB`].
    #[allow(non_upper_case_globals)]
    pub const MlDsa44Pub: Self = Self::MULTICODEC_KEY_ALGORITHM_ML_DSA_44_PUB;
    /// Idiomatic alias for [`Self::MULTICODEC_KEY_ALGORITHM_ML_DSA_65_PUB`].
    #[allow(non_upper_case_globals)]
    pub const MlDsa65Pub: Self = Self::MULTICODEC_KEY_ALGORITHM_ML_DSA_65_PUB;
    /// Idiomatic alias for [`Self::MULTICODEC_KEY_ALGORITHM_ML_DSA_87_PUB`].
    #[allow(non_upper_case_globals)]
    pub const MlDsa87Pub: Self = Self::MULTICODEC_KEY_ALGORITHM_ML_DSA_87_PUB;
    /// Idiomatic alias for [`Self::MULTICODEC_KEY_ALGORITHM_ED25519_PRIV`].
    #[allow(non_upper_case_globals)]
    pub const Ed25519Priv: Self = Self::MULTICODEC_KEY_ALGORITHM_ED25519_PRIV;
    /// Idiomatic alias for [`Self::MULTICODEC_KEY_ALGORITHM_X25519_PRIV`].
    #[allow(non_upper_case_globals)]
    pub const X25519Priv: Self = Self::MULTICODEC_KEY_ALGORITHM_X25519_PRIV;
    /// Idiomatic alias for [`Self::MULTICODEC_KEY_ALGORITHM_SECP256K1_PRIV`].
    #[allow(non_upper_case_globals)]
    pub const Secp256k1Priv: Self = Self::MULTICODEC_KEY_ALGORITHM_SECP256K1_PRIV;
    /// Idiomatic alias for [`Self::MULTICODEC_KEY_ALGORITHM_P256_PRIV`].
    #[allow(non_upper_case_globals)]
    pub const P256Priv: Self = Self::MULTICODEC_KEY_ALGORITHM_P256_PRIV;
    /// Idiomatic alias for [`Self::MULTICODEC_KEY_ALGORITHM_P384_PRIV`].
    #[allow(non_upper_case_globals)]
    pub const P384Priv: Self = Self::MULTICODEC_KEY_ALGORITHM_P384_PRIV;
    /// Idiomatic alias for [`Self::MULTICODEC_KEY_ALGORITHM_P521_PRIV`].
    #[allow(non_upper_case_globals)]
    pub const P521Priv: Self = Self::MULTICODEC_KEY_ALGORITHM_P521_PRIV;
    /// Idiomatic alias for [`Self::MULTICODEC_KEY_ALGORITHM_ED448_PRIV`].
    #[allow(non_upper_case_globals)]
    pub const Ed448Priv: Self = Self::MULTICODEC_KEY_ALGORITHM_ED448_PRIV;
    /// Idiomatic alias for [`Self::MULTICODEC_KEY_ALGORITHM_RSA_PRIV`].
    #[allow(non_upper_case_globals)]
    pub const RsaPriv: Self = Self::MULTICODEC_KEY_ALGORITHM_RSA_PRIV;
    /// Idiomatic alias for [`Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_512_PRIV`].
    #[allow(non_upper_case_globals)]
    pub const MlKem512Priv: Self = Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_512_PRIV;
    /// Idiomatic alias for [`Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_768_PRIV`].
    #[allow(non_upper_case_globals)]
    pub const MlKem768Priv: Self = Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_768_PRIV;
    /// Idiomatic alias for [`Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_1024_PRIV`].
    #[allow(non_upper_case_globals)]
    pub const MlKem1024Priv: Self = Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_1024_PRIV;
}
impl ::buffa::Enumeration for MulticodecKeyAlgorithm {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::MULTICODEC_KEY_ALGORITHM_UNSPECIFIED),
            1 => Some(Self::MULTICODEC_KEY_ALGORITHM_ED25519_PUB),
            2 => Some(Self::MULTICODEC_KEY_ALGORITHM_X25519_PUB),
            3 => Some(Self::MULTICODEC_KEY_ALGORITHM_SECP256K1_PUB),
            4 => Some(Self::MULTICODEC_KEY_ALGORITHM_P256_PUB),
            5 => Some(Self::MULTICODEC_KEY_ALGORITHM_P384_PUB),
            6 => Some(Self::MULTICODEC_KEY_ALGORITHM_P521_PUB),
            7 => Some(Self::MULTICODEC_KEY_ALGORITHM_ED448_PUB),
            8 => Some(Self::MULTICODEC_KEY_ALGORITHM_RSA_PUB),
            9 => Some(Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_512_PUB),
            10 => Some(Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_768_PUB),
            11 => Some(Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_1024_PUB),
            12 => Some(Self::MULTICODEC_KEY_ALGORITHM_ML_DSA_44_PUB),
            13 => Some(Self::MULTICODEC_KEY_ALGORITHM_ML_DSA_65_PUB),
            14 => Some(Self::MULTICODEC_KEY_ALGORITHM_ML_DSA_87_PUB),
            15 => Some(Self::MULTICODEC_KEY_ALGORITHM_ED25519_PRIV),
            16 => Some(Self::MULTICODEC_KEY_ALGORITHM_X25519_PRIV),
            17 => Some(Self::MULTICODEC_KEY_ALGORITHM_SECP256K1_PRIV),
            18 => Some(Self::MULTICODEC_KEY_ALGORITHM_P256_PRIV),
            19 => Some(Self::MULTICODEC_KEY_ALGORITHM_P384_PRIV),
            20 => Some(Self::MULTICODEC_KEY_ALGORITHM_P521_PRIV),
            21 => Some(Self::MULTICODEC_KEY_ALGORITHM_ED448_PRIV),
            22 => Some(Self::MULTICODEC_KEY_ALGORITHM_RSA_PRIV),
            23 => Some(Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_512_PRIV),
            24 => Some(Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_768_PRIV),
            25 => Some(Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_1024_PRIV),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::MULTICODEC_KEY_ALGORITHM_UNSPECIFIED => "MULTICODEC_KEY_ALGORITHM_UNSPECIFIED",
            Self::MULTICODEC_KEY_ALGORITHM_ED25519_PUB => "MULTICODEC_KEY_ALGORITHM_ED25519_PUB",
            Self::MULTICODEC_KEY_ALGORITHM_X25519_PUB => "MULTICODEC_KEY_ALGORITHM_X25519_PUB",
            Self::MULTICODEC_KEY_ALGORITHM_SECP256K1_PUB => {
                "MULTICODEC_KEY_ALGORITHM_SECP256K1_PUB"
            }
            Self::MULTICODEC_KEY_ALGORITHM_P256_PUB => "MULTICODEC_KEY_ALGORITHM_P256_PUB",
            Self::MULTICODEC_KEY_ALGORITHM_P384_PUB => "MULTICODEC_KEY_ALGORITHM_P384_PUB",
            Self::MULTICODEC_KEY_ALGORITHM_P521_PUB => "MULTICODEC_KEY_ALGORITHM_P521_PUB",
            Self::MULTICODEC_KEY_ALGORITHM_ED448_PUB => "MULTICODEC_KEY_ALGORITHM_ED448_PUB",
            Self::MULTICODEC_KEY_ALGORITHM_RSA_PUB => "MULTICODEC_KEY_ALGORITHM_RSA_PUB",
            Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_512_PUB => {
                "MULTICODEC_KEY_ALGORITHM_ML_KEM_512_PUB"
            }
            Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_768_PUB => {
                "MULTICODEC_KEY_ALGORITHM_ML_KEM_768_PUB"
            }
            Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_1024_PUB => {
                "MULTICODEC_KEY_ALGORITHM_ML_KEM_1024_PUB"
            }
            Self::MULTICODEC_KEY_ALGORITHM_ML_DSA_44_PUB => {
                "MULTICODEC_KEY_ALGORITHM_ML_DSA_44_PUB"
            }
            Self::MULTICODEC_KEY_ALGORITHM_ML_DSA_65_PUB => {
                "MULTICODEC_KEY_ALGORITHM_ML_DSA_65_PUB"
            }
            Self::MULTICODEC_KEY_ALGORITHM_ML_DSA_87_PUB => {
                "MULTICODEC_KEY_ALGORITHM_ML_DSA_87_PUB"
            }
            Self::MULTICODEC_KEY_ALGORITHM_ED25519_PRIV => "MULTICODEC_KEY_ALGORITHM_ED25519_PRIV",
            Self::MULTICODEC_KEY_ALGORITHM_X25519_PRIV => "MULTICODEC_KEY_ALGORITHM_X25519_PRIV",
            Self::MULTICODEC_KEY_ALGORITHM_SECP256K1_PRIV => {
                "MULTICODEC_KEY_ALGORITHM_SECP256K1_PRIV"
            }
            Self::MULTICODEC_KEY_ALGORITHM_P256_PRIV => "MULTICODEC_KEY_ALGORITHM_P256_PRIV",
            Self::MULTICODEC_KEY_ALGORITHM_P384_PRIV => "MULTICODEC_KEY_ALGORITHM_P384_PRIV",
            Self::MULTICODEC_KEY_ALGORITHM_P521_PRIV => "MULTICODEC_KEY_ALGORITHM_P521_PRIV",
            Self::MULTICODEC_KEY_ALGORITHM_ED448_PRIV => "MULTICODEC_KEY_ALGORITHM_ED448_PRIV",
            Self::MULTICODEC_KEY_ALGORITHM_RSA_PRIV => "MULTICODEC_KEY_ALGORITHM_RSA_PRIV",
            Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_512_PRIV => {
                "MULTICODEC_KEY_ALGORITHM_ML_KEM_512_PRIV"
            }
            Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_768_PRIV => {
                "MULTICODEC_KEY_ALGORITHM_ML_KEM_768_PRIV"
            }
            Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_1024_PRIV => {
                "MULTICODEC_KEY_ALGORITHM_ML_KEM_1024_PRIV"
            }
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "MULTICODEC_KEY_ALGORITHM_UNSPECIFIED" => {
                Some(Self::MULTICODEC_KEY_ALGORITHM_UNSPECIFIED)
            }
            "MULTICODEC_KEY_ALGORITHM_ED25519_PUB" => {
                Some(Self::MULTICODEC_KEY_ALGORITHM_ED25519_PUB)
            }
            "MULTICODEC_KEY_ALGORITHM_X25519_PUB" => {
                Some(Self::MULTICODEC_KEY_ALGORITHM_X25519_PUB)
            }
            "MULTICODEC_KEY_ALGORITHM_SECP256K1_PUB" => {
                Some(Self::MULTICODEC_KEY_ALGORITHM_SECP256K1_PUB)
            }
            "MULTICODEC_KEY_ALGORITHM_P256_PUB" => Some(Self::MULTICODEC_KEY_ALGORITHM_P256_PUB),
            "MULTICODEC_KEY_ALGORITHM_P384_PUB" => Some(Self::MULTICODEC_KEY_ALGORITHM_P384_PUB),
            "MULTICODEC_KEY_ALGORITHM_P521_PUB" => Some(Self::MULTICODEC_KEY_ALGORITHM_P521_PUB),
            "MULTICODEC_KEY_ALGORITHM_ED448_PUB" => Some(Self::MULTICODEC_KEY_ALGORITHM_ED448_PUB),
            "MULTICODEC_KEY_ALGORITHM_RSA_PUB" => Some(Self::MULTICODEC_KEY_ALGORITHM_RSA_PUB),
            "MULTICODEC_KEY_ALGORITHM_ML_KEM_512_PUB" => {
                Some(Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_512_PUB)
            }
            "MULTICODEC_KEY_ALGORITHM_ML_KEM_768_PUB" => {
                Some(Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_768_PUB)
            }
            "MULTICODEC_KEY_ALGORITHM_ML_KEM_1024_PUB" => {
                Some(Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_1024_PUB)
            }
            "MULTICODEC_KEY_ALGORITHM_ML_DSA_44_PUB" => {
                Some(Self::MULTICODEC_KEY_ALGORITHM_ML_DSA_44_PUB)
            }
            "MULTICODEC_KEY_ALGORITHM_ML_DSA_65_PUB" => {
                Some(Self::MULTICODEC_KEY_ALGORITHM_ML_DSA_65_PUB)
            }
            "MULTICODEC_KEY_ALGORITHM_ML_DSA_87_PUB" => {
                Some(Self::MULTICODEC_KEY_ALGORITHM_ML_DSA_87_PUB)
            }
            "MULTICODEC_KEY_ALGORITHM_ED25519_PRIV" => {
                Some(Self::MULTICODEC_KEY_ALGORITHM_ED25519_PRIV)
            }
            "MULTICODEC_KEY_ALGORITHM_X25519_PRIV" => {
                Some(Self::MULTICODEC_KEY_ALGORITHM_X25519_PRIV)
            }
            "MULTICODEC_KEY_ALGORITHM_SECP256K1_PRIV" => {
                Some(Self::MULTICODEC_KEY_ALGORITHM_SECP256K1_PRIV)
            }
            "MULTICODEC_KEY_ALGORITHM_P256_PRIV" => Some(Self::MULTICODEC_KEY_ALGORITHM_P256_PRIV),
            "MULTICODEC_KEY_ALGORITHM_P384_PRIV" => Some(Self::MULTICODEC_KEY_ALGORITHM_P384_PRIV),
            "MULTICODEC_KEY_ALGORITHM_P521_PRIV" => Some(Self::MULTICODEC_KEY_ALGORITHM_P521_PRIV),
            "MULTICODEC_KEY_ALGORITHM_ED448_PRIV" => {
                Some(Self::MULTICODEC_KEY_ALGORITHM_ED448_PRIV)
            }
            "MULTICODEC_KEY_ALGORITHM_RSA_PRIV" => Some(Self::MULTICODEC_KEY_ALGORITHM_RSA_PRIV),
            "MULTICODEC_KEY_ALGORITHM_ML_KEM_512_PRIV" => {
                Some(Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_512_PRIV)
            }
            "MULTICODEC_KEY_ALGORITHM_ML_KEM_768_PRIV" => {
                Some(Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_768_PRIV)
            }
            "MULTICODEC_KEY_ALGORITHM_ML_KEM_1024_PRIV" => {
                Some(Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_1024_PRIV)
            }
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::MULTICODEC_KEY_ALGORITHM_UNSPECIFIED,
            Self::MULTICODEC_KEY_ALGORITHM_ED25519_PUB,
            Self::MULTICODEC_KEY_ALGORITHM_X25519_PUB,
            Self::MULTICODEC_KEY_ALGORITHM_SECP256K1_PUB,
            Self::MULTICODEC_KEY_ALGORITHM_P256_PUB,
            Self::MULTICODEC_KEY_ALGORITHM_P384_PUB,
            Self::MULTICODEC_KEY_ALGORITHM_P521_PUB,
            Self::MULTICODEC_KEY_ALGORITHM_ED448_PUB,
            Self::MULTICODEC_KEY_ALGORITHM_RSA_PUB,
            Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_512_PUB,
            Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_768_PUB,
            Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_1024_PUB,
            Self::MULTICODEC_KEY_ALGORITHM_ML_DSA_44_PUB,
            Self::MULTICODEC_KEY_ALGORITHM_ML_DSA_65_PUB,
            Self::MULTICODEC_KEY_ALGORITHM_ML_DSA_87_PUB,
            Self::MULTICODEC_KEY_ALGORITHM_ED25519_PRIV,
            Self::MULTICODEC_KEY_ALGORITHM_X25519_PRIV,
            Self::MULTICODEC_KEY_ALGORITHM_SECP256K1_PRIV,
            Self::MULTICODEC_KEY_ALGORITHM_P256_PRIV,
            Self::MULTICODEC_KEY_ALGORITHM_P384_PRIV,
            Self::MULTICODEC_KEY_ALGORITHM_P521_PRIV,
            Self::MULTICODEC_KEY_ALGORITHM_ED448_PRIV,
            Self::MULTICODEC_KEY_ALGORITHM_RSA_PRIV,
            Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_512_PRIV,
            Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_768_PRIV,
            Self::MULTICODEC_KEY_ALGORITHM_ML_KEM_1024_PRIV,
        ]
    }
}
impl ::zeroize::Zeroize for MulticodecKeyAlgorithm {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for MulticodecKeyAlgorithm {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for MulticodecKeyAlgorithm {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for MulticodecKeyAlgorithm {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.RsaHashAlgorithm`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum RsaHashAlgorithm {
    /// `RSA_HASH_ALGORITHM_UNSPECIFIED`.
    #[default]
    RSA_HASH_ALGORITHM_UNSPECIFIED = 0,
    /// `RSA_HASH_ALGORITHM_SHA1`.
    RSA_HASH_ALGORITHM_SHA1 = 100,
    /// `RSA_HASH_ALGORITHM_SHA256`.
    RSA_HASH_ALGORITHM_SHA256 = 200,
    /// `RSA_HASH_ALGORITHM_SHA384`.
    RSA_HASH_ALGORITHM_SHA384 = 210,
    /// `RSA_HASH_ALGORITHM_SHA512`.
    RSA_HASH_ALGORITHM_SHA512 = 220,
}
impl RsaHashAlgorithm {
    /// Idiomatic alias for [`Self::RSA_HASH_ALGORITHM_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::RSA_HASH_ALGORITHM_UNSPECIFIED;
    /// Idiomatic alias for [`Self::RSA_HASH_ALGORITHM_SHA1`].
    #[allow(non_upper_case_globals)]
    pub const Sha1: Self = Self::RSA_HASH_ALGORITHM_SHA1;
    /// Idiomatic alias for [`Self::RSA_HASH_ALGORITHM_SHA256`].
    #[allow(non_upper_case_globals)]
    pub const Sha256: Self = Self::RSA_HASH_ALGORITHM_SHA256;
    /// Idiomatic alias for [`Self::RSA_HASH_ALGORITHM_SHA384`].
    #[allow(non_upper_case_globals)]
    pub const Sha384: Self = Self::RSA_HASH_ALGORITHM_SHA384;
    /// Idiomatic alias for [`Self::RSA_HASH_ALGORITHM_SHA512`].
    #[allow(non_upper_case_globals)]
    pub const Sha512: Self = Self::RSA_HASH_ALGORITHM_SHA512;
}
impl ::buffa::Enumeration for RsaHashAlgorithm {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::RSA_HASH_ALGORITHM_UNSPECIFIED),
            100 => Some(Self::RSA_HASH_ALGORITHM_SHA1),
            200 => Some(Self::RSA_HASH_ALGORITHM_SHA256),
            210 => Some(Self::RSA_HASH_ALGORITHM_SHA384),
            220 => Some(Self::RSA_HASH_ALGORITHM_SHA512),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::RSA_HASH_ALGORITHM_UNSPECIFIED => "RSA_HASH_ALGORITHM_UNSPECIFIED",
            Self::RSA_HASH_ALGORITHM_SHA1 => "RSA_HASH_ALGORITHM_SHA1",
            Self::RSA_HASH_ALGORITHM_SHA256 => "RSA_HASH_ALGORITHM_SHA256",
            Self::RSA_HASH_ALGORITHM_SHA384 => "RSA_HASH_ALGORITHM_SHA384",
            Self::RSA_HASH_ALGORITHM_SHA512 => "RSA_HASH_ALGORITHM_SHA512",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "RSA_HASH_ALGORITHM_UNSPECIFIED" => Some(Self::RSA_HASH_ALGORITHM_UNSPECIFIED),
            "RSA_HASH_ALGORITHM_SHA1" => Some(Self::RSA_HASH_ALGORITHM_SHA1),
            "RSA_HASH_ALGORITHM_SHA256" => Some(Self::RSA_HASH_ALGORITHM_SHA256),
            "RSA_HASH_ALGORITHM_SHA384" => Some(Self::RSA_HASH_ALGORITHM_SHA384),
            "RSA_HASH_ALGORITHM_SHA512" => Some(Self::RSA_HASH_ALGORITHM_SHA512),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::RSA_HASH_ALGORITHM_UNSPECIFIED,
            Self::RSA_HASH_ALGORITHM_SHA1,
            Self::RSA_HASH_ALGORITHM_SHA256,
            Self::RSA_HASH_ALGORITHM_SHA384,
            Self::RSA_HASH_ALGORITHM_SHA512,
        ]
    }
}
impl ::zeroize::Zeroize for RsaHashAlgorithm {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for RsaHashAlgorithm {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for RsaHashAlgorithm {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for RsaHashAlgorithm {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.RsaPublicKeyDerEncoding`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum RsaPublicKeyDerEncoding {
    /// `RSA_PUBLIC_KEY_DER_ENCODING_UNSPECIFIED`.
    #[default]
    RSA_PUBLIC_KEY_DER_ENCODING_UNSPECIFIED = 0,
    /// `RSA_PUBLIC_KEY_DER_ENCODING_PKCS1`.
    RSA_PUBLIC_KEY_DER_ENCODING_PKCS1 = 1,
    /// `RSA_PUBLIC_KEY_DER_ENCODING_SPKI`.
    RSA_PUBLIC_KEY_DER_ENCODING_SPKI = 2,
}
impl RsaPublicKeyDerEncoding {
    /// Idiomatic alias for [`Self::RSA_PUBLIC_KEY_DER_ENCODING_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::RSA_PUBLIC_KEY_DER_ENCODING_UNSPECIFIED;
    /// Idiomatic alias for [`Self::RSA_PUBLIC_KEY_DER_ENCODING_PKCS1`].
    #[allow(non_upper_case_globals)]
    pub const Pkcs1: Self = Self::RSA_PUBLIC_KEY_DER_ENCODING_PKCS1;
    /// Idiomatic alias for [`Self::RSA_PUBLIC_KEY_DER_ENCODING_SPKI`].
    #[allow(non_upper_case_globals)]
    pub const Spki: Self = Self::RSA_PUBLIC_KEY_DER_ENCODING_SPKI;
}
impl ::buffa::Enumeration for RsaPublicKeyDerEncoding {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::RSA_PUBLIC_KEY_DER_ENCODING_UNSPECIFIED),
            1 => Some(Self::RSA_PUBLIC_KEY_DER_ENCODING_PKCS1),
            2 => Some(Self::RSA_PUBLIC_KEY_DER_ENCODING_SPKI),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::RSA_PUBLIC_KEY_DER_ENCODING_UNSPECIFIED => {
                "RSA_PUBLIC_KEY_DER_ENCODING_UNSPECIFIED"
            }
            Self::RSA_PUBLIC_KEY_DER_ENCODING_PKCS1 => "RSA_PUBLIC_KEY_DER_ENCODING_PKCS1",
            Self::RSA_PUBLIC_KEY_DER_ENCODING_SPKI => "RSA_PUBLIC_KEY_DER_ENCODING_SPKI",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "RSA_PUBLIC_KEY_DER_ENCODING_UNSPECIFIED" => {
                Some(Self::RSA_PUBLIC_KEY_DER_ENCODING_UNSPECIFIED)
            }
            "RSA_PUBLIC_KEY_DER_ENCODING_PKCS1" => Some(Self::RSA_PUBLIC_KEY_DER_ENCODING_PKCS1),
            "RSA_PUBLIC_KEY_DER_ENCODING_SPKI" => Some(Self::RSA_PUBLIC_KEY_DER_ENCODING_SPKI),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::RSA_PUBLIC_KEY_DER_ENCODING_UNSPECIFIED,
            Self::RSA_PUBLIC_KEY_DER_ENCODING_PKCS1,
            Self::RSA_PUBLIC_KEY_DER_ENCODING_SPKI,
        ]
    }
}
impl ::zeroize::Zeroize for RsaPublicKeyDerEncoding {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for RsaPublicKeyDerEncoding {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for RsaPublicKeyDerEncoding {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for RsaPublicKeyDerEncoding {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.PlatformKeyProvider`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum PlatformKeyProvider {
    /// `PLATFORM_KEY_PROVIDER_UNSPECIFIED`.
    #[default]
    PLATFORM_KEY_PROVIDER_UNSPECIFIED = 0,
    /// `PLATFORM_KEY_PROVIDER_APPLE_KEYCHAIN`.
    PLATFORM_KEY_PROVIDER_APPLE_KEYCHAIN = 100,
    /// `PLATFORM_KEY_PROVIDER_ANDROID_KEYSTORE`.
    PLATFORM_KEY_PROVIDER_ANDROID_KEYSTORE = 200,
}
impl PlatformKeyProvider {
    /// Idiomatic alias for [`Self::PLATFORM_KEY_PROVIDER_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::PLATFORM_KEY_PROVIDER_UNSPECIFIED;
    /// Idiomatic alias for [`Self::PLATFORM_KEY_PROVIDER_APPLE_KEYCHAIN`].
    #[allow(non_upper_case_globals)]
    pub const AppleKeychain: Self = Self::PLATFORM_KEY_PROVIDER_APPLE_KEYCHAIN;
    /// Idiomatic alias for [`Self::PLATFORM_KEY_PROVIDER_ANDROID_KEYSTORE`].
    #[allow(non_upper_case_globals)]
    pub const AndroidKeystore: Self = Self::PLATFORM_KEY_PROVIDER_ANDROID_KEYSTORE;
}
impl ::buffa::Enumeration for PlatformKeyProvider {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::PLATFORM_KEY_PROVIDER_UNSPECIFIED),
            100 => Some(Self::PLATFORM_KEY_PROVIDER_APPLE_KEYCHAIN),
            200 => Some(Self::PLATFORM_KEY_PROVIDER_ANDROID_KEYSTORE),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::PLATFORM_KEY_PROVIDER_UNSPECIFIED => "PLATFORM_KEY_PROVIDER_UNSPECIFIED",
            Self::PLATFORM_KEY_PROVIDER_APPLE_KEYCHAIN => "PLATFORM_KEY_PROVIDER_APPLE_KEYCHAIN",
            Self::PLATFORM_KEY_PROVIDER_ANDROID_KEYSTORE => {
                "PLATFORM_KEY_PROVIDER_ANDROID_KEYSTORE"
            }
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "PLATFORM_KEY_PROVIDER_UNSPECIFIED" => Some(Self::PLATFORM_KEY_PROVIDER_UNSPECIFIED),
            "PLATFORM_KEY_PROVIDER_APPLE_KEYCHAIN" => {
                Some(Self::PLATFORM_KEY_PROVIDER_APPLE_KEYCHAIN)
            }
            "PLATFORM_KEY_PROVIDER_ANDROID_KEYSTORE" => {
                Some(Self::PLATFORM_KEY_PROVIDER_ANDROID_KEYSTORE)
            }
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::PLATFORM_KEY_PROVIDER_UNSPECIFIED,
            Self::PLATFORM_KEY_PROVIDER_APPLE_KEYCHAIN,
            Self::PLATFORM_KEY_PROVIDER_ANDROID_KEYSTORE,
        ]
    }
}
impl ::zeroize::Zeroize for PlatformKeyProvider {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for PlatformKeyProvider {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for PlatformKeyProvider {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for PlatformKeyProvider {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.PlatformKeySecurityLevel`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum PlatformKeySecurityLevel {
    /// `PLATFORM_KEY_SECURITY_LEVEL_UNSPECIFIED`.
    #[default]
    PLATFORM_KEY_SECURITY_LEVEL_UNSPECIFIED = 0,
    /// `PLATFORM_KEY_SECURITY_LEVEL_SOFTWARE`.
    PLATFORM_KEY_SECURITY_LEVEL_SOFTWARE = 1,
    /// `PLATFORM_KEY_SECURITY_LEVEL_TRUSTED_EXECUTION_ENVIRONMENT`.
    PLATFORM_KEY_SECURITY_LEVEL_TRUSTED_EXECUTION_ENVIRONMENT = 2,
    /// `PLATFORM_KEY_SECURITY_LEVEL_SECURE_ENCLAVE`.
    PLATFORM_KEY_SECURITY_LEVEL_SECURE_ENCLAVE = 3,
    /// `PLATFORM_KEY_SECURITY_LEVEL_STRONGBOX`.
    PLATFORM_KEY_SECURITY_LEVEL_STRONGBOX = 4,
}
impl PlatformKeySecurityLevel {
    /// Idiomatic alias for [`Self::PLATFORM_KEY_SECURITY_LEVEL_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::PLATFORM_KEY_SECURITY_LEVEL_UNSPECIFIED;
    /// Idiomatic alias for [`Self::PLATFORM_KEY_SECURITY_LEVEL_SOFTWARE`].
    #[allow(non_upper_case_globals)]
    pub const Software: Self = Self::PLATFORM_KEY_SECURITY_LEVEL_SOFTWARE;
    /// Idiomatic alias for [`Self::PLATFORM_KEY_SECURITY_LEVEL_TRUSTED_EXECUTION_ENVIRONMENT`].
    #[allow(non_upper_case_globals)]
    pub const TrustedExecutionEnvironment: Self =
        Self::PLATFORM_KEY_SECURITY_LEVEL_TRUSTED_EXECUTION_ENVIRONMENT;
    /// Idiomatic alias for [`Self::PLATFORM_KEY_SECURITY_LEVEL_SECURE_ENCLAVE`].
    #[allow(non_upper_case_globals)]
    pub const SecureEnclave: Self = Self::PLATFORM_KEY_SECURITY_LEVEL_SECURE_ENCLAVE;
    /// Idiomatic alias for [`Self::PLATFORM_KEY_SECURITY_LEVEL_STRONGBOX`].
    #[allow(non_upper_case_globals)]
    pub const Strongbox: Self = Self::PLATFORM_KEY_SECURITY_LEVEL_STRONGBOX;
}
impl ::buffa::Enumeration for PlatformKeySecurityLevel {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::PLATFORM_KEY_SECURITY_LEVEL_UNSPECIFIED),
            1 => Some(Self::PLATFORM_KEY_SECURITY_LEVEL_SOFTWARE),
            2 => Some(Self::PLATFORM_KEY_SECURITY_LEVEL_TRUSTED_EXECUTION_ENVIRONMENT),
            3 => Some(Self::PLATFORM_KEY_SECURITY_LEVEL_SECURE_ENCLAVE),
            4 => Some(Self::PLATFORM_KEY_SECURITY_LEVEL_STRONGBOX),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::PLATFORM_KEY_SECURITY_LEVEL_UNSPECIFIED => {
                "PLATFORM_KEY_SECURITY_LEVEL_UNSPECIFIED"
            }
            Self::PLATFORM_KEY_SECURITY_LEVEL_SOFTWARE => "PLATFORM_KEY_SECURITY_LEVEL_SOFTWARE",
            Self::PLATFORM_KEY_SECURITY_LEVEL_TRUSTED_EXECUTION_ENVIRONMENT => {
                "PLATFORM_KEY_SECURITY_LEVEL_TRUSTED_EXECUTION_ENVIRONMENT"
            }
            Self::PLATFORM_KEY_SECURITY_LEVEL_SECURE_ENCLAVE => {
                "PLATFORM_KEY_SECURITY_LEVEL_SECURE_ENCLAVE"
            }
            Self::PLATFORM_KEY_SECURITY_LEVEL_STRONGBOX => "PLATFORM_KEY_SECURITY_LEVEL_STRONGBOX",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "PLATFORM_KEY_SECURITY_LEVEL_UNSPECIFIED" => {
                Some(Self::PLATFORM_KEY_SECURITY_LEVEL_UNSPECIFIED)
            }
            "PLATFORM_KEY_SECURITY_LEVEL_SOFTWARE" => {
                Some(Self::PLATFORM_KEY_SECURITY_LEVEL_SOFTWARE)
            }
            "PLATFORM_KEY_SECURITY_LEVEL_TRUSTED_EXECUTION_ENVIRONMENT" => {
                Some(Self::PLATFORM_KEY_SECURITY_LEVEL_TRUSTED_EXECUTION_ENVIRONMENT)
            }
            "PLATFORM_KEY_SECURITY_LEVEL_SECURE_ENCLAVE" => {
                Some(Self::PLATFORM_KEY_SECURITY_LEVEL_SECURE_ENCLAVE)
            }
            "PLATFORM_KEY_SECURITY_LEVEL_STRONGBOX" => {
                Some(Self::PLATFORM_KEY_SECURITY_LEVEL_STRONGBOX)
            }
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::PLATFORM_KEY_SECURITY_LEVEL_UNSPECIFIED,
            Self::PLATFORM_KEY_SECURITY_LEVEL_SOFTWARE,
            Self::PLATFORM_KEY_SECURITY_LEVEL_TRUSTED_EXECUTION_ENVIRONMENT,
            Self::PLATFORM_KEY_SECURITY_LEVEL_SECURE_ENCLAVE,
            Self::PLATFORM_KEY_SECURITY_LEVEL_STRONGBOX,
        ]
    }
}
impl ::zeroize::Zeroize for PlatformKeySecurityLevel {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for PlatformKeySecurityLevel {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for PlatformKeySecurityLevel {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for PlatformKeySecurityLevel {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.PlatformKeyPurpose`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum PlatformKeyPurpose {
    /// `PLATFORM_KEY_PURPOSE_UNSPECIFIED`.
    #[default]
    PLATFORM_KEY_PURPOSE_UNSPECIFIED = 0,
    /// `PLATFORM_KEY_PURPOSE_SIGNING`.
    PLATFORM_KEY_PURPOSE_SIGNING = 1,
    /// `PLATFORM_KEY_PURPOSE_KEY_AGREEMENT`.
    PLATFORM_KEY_PURPOSE_KEY_AGREEMENT = 2,
}
impl PlatformKeyPurpose {
    /// Idiomatic alias for [`Self::PLATFORM_KEY_PURPOSE_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::PLATFORM_KEY_PURPOSE_UNSPECIFIED;
    /// Idiomatic alias for [`Self::PLATFORM_KEY_PURPOSE_SIGNING`].
    #[allow(non_upper_case_globals)]
    pub const Signing: Self = Self::PLATFORM_KEY_PURPOSE_SIGNING;
    /// Idiomatic alias for [`Self::PLATFORM_KEY_PURPOSE_KEY_AGREEMENT`].
    #[allow(non_upper_case_globals)]
    pub const KeyAgreement: Self = Self::PLATFORM_KEY_PURPOSE_KEY_AGREEMENT;
}
impl ::buffa::Enumeration for PlatformKeyPurpose {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::PLATFORM_KEY_PURPOSE_UNSPECIFIED),
            1 => Some(Self::PLATFORM_KEY_PURPOSE_SIGNING),
            2 => Some(Self::PLATFORM_KEY_PURPOSE_KEY_AGREEMENT),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::PLATFORM_KEY_PURPOSE_UNSPECIFIED => "PLATFORM_KEY_PURPOSE_UNSPECIFIED",
            Self::PLATFORM_KEY_PURPOSE_SIGNING => "PLATFORM_KEY_PURPOSE_SIGNING",
            Self::PLATFORM_KEY_PURPOSE_KEY_AGREEMENT => "PLATFORM_KEY_PURPOSE_KEY_AGREEMENT",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "PLATFORM_KEY_PURPOSE_UNSPECIFIED" => Some(Self::PLATFORM_KEY_PURPOSE_UNSPECIFIED),
            "PLATFORM_KEY_PURPOSE_SIGNING" => Some(Self::PLATFORM_KEY_PURPOSE_SIGNING),
            "PLATFORM_KEY_PURPOSE_KEY_AGREEMENT" => Some(Self::PLATFORM_KEY_PURPOSE_KEY_AGREEMENT),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::PLATFORM_KEY_PURPOSE_UNSPECIFIED,
            Self::PLATFORM_KEY_PURPOSE_SIGNING,
            Self::PLATFORM_KEY_PURPOSE_KEY_AGREEMENT,
        ]
    }
}
impl ::zeroize::Zeroize for PlatformKeyPurpose {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for PlatformKeyPurpose {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for PlatformKeyPurpose {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for PlatformKeyPurpose {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.AppleSecureEnclaveAccessPolicy`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum AppleSecureEnclaveAccessPolicy {
    /// `APPLE_SECURE_ENCLAVE_ACCESS_POLICY_UNSPECIFIED`.
    #[default]
    APPLE_SECURE_ENCLAVE_ACCESS_POLICY_UNSPECIFIED = 0,
    /// `APPLE_SECURE_ENCLAVE_ACCESS_POLICY_PRIVATE_KEY_USAGE`.
    APPLE_SECURE_ENCLAVE_ACCESS_POLICY_PRIVATE_KEY_USAGE = 1,
    /// `APPLE_SECURE_ENCLAVE_ACCESS_POLICY_USER_PRESENCE`.
    APPLE_SECURE_ENCLAVE_ACCESS_POLICY_USER_PRESENCE = 2,
    /// `APPLE_SECURE_ENCLAVE_ACCESS_POLICY_BIOMETRY_ANY`.
    APPLE_SECURE_ENCLAVE_ACCESS_POLICY_BIOMETRY_ANY = 3,
    /// `APPLE_SECURE_ENCLAVE_ACCESS_POLICY_BIOMETRY_CURRENT_SET`.
    APPLE_SECURE_ENCLAVE_ACCESS_POLICY_BIOMETRY_CURRENT_SET = 4,
    /// `APPLE_SECURE_ENCLAVE_ACCESS_POLICY_DEVICE_PASSCODE`.
    APPLE_SECURE_ENCLAVE_ACCESS_POLICY_DEVICE_PASSCODE = 5,
}
impl AppleSecureEnclaveAccessPolicy {
    /// Idiomatic alias for [`Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_UNSPECIFIED;
    /// Idiomatic alias for [`Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_PRIVATE_KEY_USAGE`].
    #[allow(non_upper_case_globals)]
    pub const PrivateKeyUsage: Self = Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_PRIVATE_KEY_USAGE;
    /// Idiomatic alias for [`Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_USER_PRESENCE`].
    #[allow(non_upper_case_globals)]
    pub const UserPresence: Self = Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_USER_PRESENCE;
    /// Idiomatic alias for [`Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_BIOMETRY_ANY`].
    #[allow(non_upper_case_globals)]
    pub const BiometryAny: Self = Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_BIOMETRY_ANY;
    /// Idiomatic alias for [`Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_BIOMETRY_CURRENT_SET`].
    #[allow(non_upper_case_globals)]
    pub const BiometryCurrentSet: Self =
        Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_BIOMETRY_CURRENT_SET;
    /// Idiomatic alias for [`Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_DEVICE_PASSCODE`].
    #[allow(non_upper_case_globals)]
    pub const DevicePasscode: Self = Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_DEVICE_PASSCODE;
}
impl ::buffa::Enumeration for AppleSecureEnclaveAccessPolicy {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_UNSPECIFIED),
            1 => Some(Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_PRIVATE_KEY_USAGE),
            2 => Some(Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_USER_PRESENCE),
            3 => Some(Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_BIOMETRY_ANY),
            4 => Some(Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_BIOMETRY_CURRENT_SET),
            5 => Some(Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_DEVICE_PASSCODE),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_UNSPECIFIED => {
                "APPLE_SECURE_ENCLAVE_ACCESS_POLICY_UNSPECIFIED"
            }
            Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_PRIVATE_KEY_USAGE => {
                "APPLE_SECURE_ENCLAVE_ACCESS_POLICY_PRIVATE_KEY_USAGE"
            }
            Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_USER_PRESENCE => {
                "APPLE_SECURE_ENCLAVE_ACCESS_POLICY_USER_PRESENCE"
            }
            Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_BIOMETRY_ANY => {
                "APPLE_SECURE_ENCLAVE_ACCESS_POLICY_BIOMETRY_ANY"
            }
            Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_BIOMETRY_CURRENT_SET => {
                "APPLE_SECURE_ENCLAVE_ACCESS_POLICY_BIOMETRY_CURRENT_SET"
            }
            Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_DEVICE_PASSCODE => {
                "APPLE_SECURE_ENCLAVE_ACCESS_POLICY_DEVICE_PASSCODE"
            }
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "APPLE_SECURE_ENCLAVE_ACCESS_POLICY_UNSPECIFIED" => {
                Some(Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_UNSPECIFIED)
            }
            "APPLE_SECURE_ENCLAVE_ACCESS_POLICY_PRIVATE_KEY_USAGE" => {
                Some(Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_PRIVATE_KEY_USAGE)
            }
            "APPLE_SECURE_ENCLAVE_ACCESS_POLICY_USER_PRESENCE" => {
                Some(Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_USER_PRESENCE)
            }
            "APPLE_SECURE_ENCLAVE_ACCESS_POLICY_BIOMETRY_ANY" => {
                Some(Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_BIOMETRY_ANY)
            }
            "APPLE_SECURE_ENCLAVE_ACCESS_POLICY_BIOMETRY_CURRENT_SET" => {
                Some(Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_BIOMETRY_CURRENT_SET)
            }
            "APPLE_SECURE_ENCLAVE_ACCESS_POLICY_DEVICE_PASSCODE" => {
                Some(Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_DEVICE_PASSCODE)
            }
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_UNSPECIFIED,
            Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_PRIVATE_KEY_USAGE,
            Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_USER_PRESENCE,
            Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_BIOMETRY_ANY,
            Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_BIOMETRY_CURRENT_SET,
            Self::APPLE_SECURE_ENCLAVE_ACCESS_POLICY_DEVICE_PASSCODE,
        ]
    }
}
impl ::zeroize::Zeroize for AppleSecureEnclaveAccessPolicy {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for AppleSecureEnclaveAccessPolicy {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for AppleSecureEnclaveAccessPolicy {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for AppleSecureEnclaveAccessPolicy {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.AppleKeychainAccessibility`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum AppleKeychainAccessibility {
    /// `APPLE_KEYCHAIN_ACCESSIBILITY_UNSPECIFIED`.
    #[default]
    APPLE_KEYCHAIN_ACCESSIBILITY_UNSPECIFIED = 0,
    /// `APPLE_KEYCHAIN_ACCESSIBILITY_WHEN_UNLOCKED_THIS_DEVICE_ONLY`.
    APPLE_KEYCHAIN_ACCESSIBILITY_WHEN_UNLOCKED_THIS_DEVICE_ONLY = 1,
    /// `APPLE_KEYCHAIN_ACCESSIBILITY_WHEN_PASSCODE_SET_THIS_DEVICE_ONLY`.
    APPLE_KEYCHAIN_ACCESSIBILITY_WHEN_PASSCODE_SET_THIS_DEVICE_ONLY = 2,
}
impl AppleKeychainAccessibility {
    /// Idiomatic alias for [`Self::APPLE_KEYCHAIN_ACCESSIBILITY_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::APPLE_KEYCHAIN_ACCESSIBILITY_UNSPECIFIED;
    /// Idiomatic alias for [`Self::APPLE_KEYCHAIN_ACCESSIBILITY_WHEN_UNLOCKED_THIS_DEVICE_ONLY`].
    #[allow(non_upper_case_globals)]
    pub const WhenUnlockedThisDeviceOnly: Self =
        Self::APPLE_KEYCHAIN_ACCESSIBILITY_WHEN_UNLOCKED_THIS_DEVICE_ONLY;
    /// Idiomatic alias for [`Self::APPLE_KEYCHAIN_ACCESSIBILITY_WHEN_PASSCODE_SET_THIS_DEVICE_ONLY`].
    #[allow(non_upper_case_globals)]
    pub const WhenPasscodeSetThisDeviceOnly: Self =
        Self::APPLE_KEYCHAIN_ACCESSIBILITY_WHEN_PASSCODE_SET_THIS_DEVICE_ONLY;
}
impl ::buffa::Enumeration for AppleKeychainAccessibility {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::APPLE_KEYCHAIN_ACCESSIBILITY_UNSPECIFIED),
            1 => Some(Self::APPLE_KEYCHAIN_ACCESSIBILITY_WHEN_UNLOCKED_THIS_DEVICE_ONLY),
            2 => Some(Self::APPLE_KEYCHAIN_ACCESSIBILITY_WHEN_PASSCODE_SET_THIS_DEVICE_ONLY),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::APPLE_KEYCHAIN_ACCESSIBILITY_UNSPECIFIED => {
                "APPLE_KEYCHAIN_ACCESSIBILITY_UNSPECIFIED"
            }
            Self::APPLE_KEYCHAIN_ACCESSIBILITY_WHEN_UNLOCKED_THIS_DEVICE_ONLY => {
                "APPLE_KEYCHAIN_ACCESSIBILITY_WHEN_UNLOCKED_THIS_DEVICE_ONLY"
            }
            Self::APPLE_KEYCHAIN_ACCESSIBILITY_WHEN_PASSCODE_SET_THIS_DEVICE_ONLY => {
                "APPLE_KEYCHAIN_ACCESSIBILITY_WHEN_PASSCODE_SET_THIS_DEVICE_ONLY"
            }
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "APPLE_KEYCHAIN_ACCESSIBILITY_UNSPECIFIED" => {
                Some(Self::APPLE_KEYCHAIN_ACCESSIBILITY_UNSPECIFIED)
            }
            "APPLE_KEYCHAIN_ACCESSIBILITY_WHEN_UNLOCKED_THIS_DEVICE_ONLY" => {
                Some(Self::APPLE_KEYCHAIN_ACCESSIBILITY_WHEN_UNLOCKED_THIS_DEVICE_ONLY)
            }
            "APPLE_KEYCHAIN_ACCESSIBILITY_WHEN_PASSCODE_SET_THIS_DEVICE_ONLY" => {
                Some(Self::APPLE_KEYCHAIN_ACCESSIBILITY_WHEN_PASSCODE_SET_THIS_DEVICE_ONLY)
            }
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::APPLE_KEYCHAIN_ACCESSIBILITY_UNSPECIFIED,
            Self::APPLE_KEYCHAIN_ACCESSIBILITY_WHEN_UNLOCKED_THIS_DEVICE_ONLY,
            Self::APPLE_KEYCHAIN_ACCESSIBILITY_WHEN_PASSCODE_SET_THIS_DEVICE_ONLY,
        ]
    }
}
impl ::zeroize::Zeroize for AppleKeychainAccessibility {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for AppleKeychainAccessibility {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for AppleKeychainAccessibility {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for AppleKeychainAccessibility {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.CryptoVerificationStatus`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum CryptoVerificationStatus {
    /// `CRYPTO_VERIFICATION_STATUS_UNSPECIFIED`.
    #[default]
    CRYPTO_VERIFICATION_STATUS_UNSPECIFIED = 0,
    /// `CRYPTO_VERIFICATION_STATUS_VALID`.
    CRYPTO_VERIFICATION_STATUS_VALID = 1,
    /// `CRYPTO_VERIFICATION_STATUS_INVALID`.
    CRYPTO_VERIFICATION_STATUS_INVALID = 2,
    /// `CRYPTO_VERIFICATION_STATUS_ERROR`.
    CRYPTO_VERIFICATION_STATUS_ERROR = 3,
}
impl CryptoVerificationStatus {
    /// Idiomatic alias for [`Self::CRYPTO_VERIFICATION_STATUS_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::CRYPTO_VERIFICATION_STATUS_UNSPECIFIED;
    /// Idiomatic alias for [`Self::CRYPTO_VERIFICATION_STATUS_VALID`].
    #[allow(non_upper_case_globals)]
    pub const Valid: Self = Self::CRYPTO_VERIFICATION_STATUS_VALID;
    /// Idiomatic alias for [`Self::CRYPTO_VERIFICATION_STATUS_INVALID`].
    #[allow(non_upper_case_globals)]
    pub const Invalid: Self = Self::CRYPTO_VERIFICATION_STATUS_INVALID;
    /// Idiomatic alias for [`Self::CRYPTO_VERIFICATION_STATUS_ERROR`].
    #[allow(non_upper_case_globals)]
    pub const Error: Self = Self::CRYPTO_VERIFICATION_STATUS_ERROR;
}
impl ::buffa::Enumeration for CryptoVerificationStatus {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::CRYPTO_VERIFICATION_STATUS_UNSPECIFIED),
            1 => Some(Self::CRYPTO_VERIFICATION_STATUS_VALID),
            2 => Some(Self::CRYPTO_VERIFICATION_STATUS_INVALID),
            3 => Some(Self::CRYPTO_VERIFICATION_STATUS_ERROR),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::CRYPTO_VERIFICATION_STATUS_UNSPECIFIED => {
                "CRYPTO_VERIFICATION_STATUS_UNSPECIFIED"
            }
            Self::CRYPTO_VERIFICATION_STATUS_VALID => "CRYPTO_VERIFICATION_STATUS_VALID",
            Self::CRYPTO_VERIFICATION_STATUS_INVALID => "CRYPTO_VERIFICATION_STATUS_INVALID",
            Self::CRYPTO_VERIFICATION_STATUS_ERROR => "CRYPTO_VERIFICATION_STATUS_ERROR",
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "CRYPTO_VERIFICATION_STATUS_UNSPECIFIED" => {
                Some(Self::CRYPTO_VERIFICATION_STATUS_UNSPECIFIED)
            }
            "CRYPTO_VERIFICATION_STATUS_VALID" => Some(Self::CRYPTO_VERIFICATION_STATUS_VALID),
            "CRYPTO_VERIFICATION_STATUS_INVALID" => Some(Self::CRYPTO_VERIFICATION_STATUS_INVALID),
            "CRYPTO_VERIFICATION_STATUS_ERROR" => Some(Self::CRYPTO_VERIFICATION_STATUS_ERROR),
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::CRYPTO_VERIFICATION_STATUS_UNSPECIFIED,
            Self::CRYPTO_VERIFICATION_STATUS_VALID,
            Self::CRYPTO_VERIFICATION_STATUS_INVALID,
            Self::CRYPTO_VERIFICATION_STATUS_ERROR,
        ]
    }
}
impl ::zeroize::Zeroize for CryptoVerificationStatus {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for CryptoVerificationStatus {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for CryptoVerificationStatus {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for CryptoVerificationStatus {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}

/// Schema-owned identity `reallyme.crypto.v1.CryptoProviderSupportStatus`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum CryptoProviderSupportStatus {
    /// `CRYPTO_PROVIDER_SUPPORT_STATUS_UNSPECIFIED`.
    #[default]
    CRYPTO_PROVIDER_SUPPORT_STATUS_UNSPECIFIED = 0,
    /// `CRYPTO_PROVIDER_SUPPORT_STATUS_SUPPORTED`.
    CRYPTO_PROVIDER_SUPPORT_STATUS_SUPPORTED = 1,
    /// `CRYPTO_PROVIDER_SUPPORT_STATUS_PROVIDER_AWARE`.
    CRYPTO_PROVIDER_SUPPORT_STATUS_PROVIDER_AWARE = 2,
    /// `CRYPTO_PROVIDER_SUPPORT_STATUS_PARTIAL`.
    CRYPTO_PROVIDER_SUPPORT_STATUS_PARTIAL = 3,
    /// `CRYPTO_PROVIDER_SUPPORT_STATUS_UNSUPPORTED`.
    CRYPTO_PROVIDER_SUPPORT_STATUS_UNSUPPORTED = 4,
}
impl CryptoProviderSupportStatus {
    /// Idiomatic alias for [`Self::CRYPTO_PROVIDER_SUPPORT_STATUS_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::CRYPTO_PROVIDER_SUPPORT_STATUS_UNSPECIFIED;
    /// Idiomatic alias for [`Self::CRYPTO_PROVIDER_SUPPORT_STATUS_SUPPORTED`].
    #[allow(non_upper_case_globals)]
    pub const Supported: Self = Self::CRYPTO_PROVIDER_SUPPORT_STATUS_SUPPORTED;
    /// Idiomatic alias for [`Self::CRYPTO_PROVIDER_SUPPORT_STATUS_PROVIDER_AWARE`].
    #[allow(non_upper_case_globals)]
    pub const ProviderAware: Self = Self::CRYPTO_PROVIDER_SUPPORT_STATUS_PROVIDER_AWARE;
    /// Idiomatic alias for [`Self::CRYPTO_PROVIDER_SUPPORT_STATUS_PARTIAL`].
    #[allow(non_upper_case_globals)]
    pub const Partial: Self = Self::CRYPTO_PROVIDER_SUPPORT_STATUS_PARTIAL;
    /// Idiomatic alias for [`Self::CRYPTO_PROVIDER_SUPPORT_STATUS_UNSUPPORTED`].
    #[allow(non_upper_case_globals)]
    pub const Unsupported: Self = Self::CRYPTO_PROVIDER_SUPPORT_STATUS_UNSUPPORTED;
}
impl ::buffa::Enumeration for CryptoProviderSupportStatus {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::CRYPTO_PROVIDER_SUPPORT_STATUS_UNSPECIFIED),
            1 => Some(Self::CRYPTO_PROVIDER_SUPPORT_STATUS_SUPPORTED),
            2 => Some(Self::CRYPTO_PROVIDER_SUPPORT_STATUS_PROVIDER_AWARE),
            3 => Some(Self::CRYPTO_PROVIDER_SUPPORT_STATUS_PARTIAL),
            4 => Some(Self::CRYPTO_PROVIDER_SUPPORT_STATUS_UNSUPPORTED),
            _ => None,
        }
    }
    fn to_i32(&self) -> i32 {
        *self as i32
    }
    fn proto_name(&self) -> &'static str {
        match self {
            Self::CRYPTO_PROVIDER_SUPPORT_STATUS_UNSPECIFIED => {
                "CRYPTO_PROVIDER_SUPPORT_STATUS_UNSPECIFIED"
            }
            Self::CRYPTO_PROVIDER_SUPPORT_STATUS_SUPPORTED => {
                "CRYPTO_PROVIDER_SUPPORT_STATUS_SUPPORTED"
            }
            Self::CRYPTO_PROVIDER_SUPPORT_STATUS_PROVIDER_AWARE => {
                "CRYPTO_PROVIDER_SUPPORT_STATUS_PROVIDER_AWARE"
            }
            Self::CRYPTO_PROVIDER_SUPPORT_STATUS_PARTIAL => {
                "CRYPTO_PROVIDER_SUPPORT_STATUS_PARTIAL"
            }
            Self::CRYPTO_PROVIDER_SUPPORT_STATUS_UNSUPPORTED => {
                "CRYPTO_PROVIDER_SUPPORT_STATUS_UNSUPPORTED"
            }
        }
    }
    fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "CRYPTO_PROVIDER_SUPPORT_STATUS_UNSPECIFIED" => {
                Some(Self::CRYPTO_PROVIDER_SUPPORT_STATUS_UNSPECIFIED)
            }
            "CRYPTO_PROVIDER_SUPPORT_STATUS_SUPPORTED" => {
                Some(Self::CRYPTO_PROVIDER_SUPPORT_STATUS_SUPPORTED)
            }
            "CRYPTO_PROVIDER_SUPPORT_STATUS_PROVIDER_AWARE" => {
                Some(Self::CRYPTO_PROVIDER_SUPPORT_STATUS_PROVIDER_AWARE)
            }
            "CRYPTO_PROVIDER_SUPPORT_STATUS_PARTIAL" => {
                Some(Self::CRYPTO_PROVIDER_SUPPORT_STATUS_PARTIAL)
            }
            "CRYPTO_PROVIDER_SUPPORT_STATUS_UNSUPPORTED" => {
                Some(Self::CRYPTO_PROVIDER_SUPPORT_STATUS_UNSUPPORTED)
            }
            _ => None,
        }
    }
    fn values() -> &'static [Self] {
        &[
            Self::CRYPTO_PROVIDER_SUPPORT_STATUS_UNSPECIFIED,
            Self::CRYPTO_PROVIDER_SUPPORT_STATUS_SUPPORTED,
            Self::CRYPTO_PROVIDER_SUPPORT_STATUS_PROVIDER_AWARE,
            Self::CRYPTO_PROVIDER_SUPPORT_STATUS_PARTIAL,
            Self::CRYPTO_PROVIDER_SUPPORT_STATUS_UNSUPPORTED,
        ]
    }
}
impl ::zeroize::Zeroize for CryptoProviderSupportStatus {
    fn zeroize(&mut self) {
        ::buffa::sensitive::reset_copy(self);
    }
}
impl ::serde::Serialize for CryptoProviderSupportStatus {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(::buffa::Enumeration::proto_name(self))
    }
}
impl<'de> ::serde::Deserialize<'de> for CryptoProviderSupportStatus {
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::enum_json::deserialize(deserializer)
    }
}
impl ::buffa::json_helpers::ProtoElemJson for CryptoProviderSupportStatus {
    fn serialize_proto_json<S: ::serde::Serializer>(
        value: &Self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(value, serializer)
    }
    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        ::serde::Deserialize::deserialize(deserializer)
    }
}
