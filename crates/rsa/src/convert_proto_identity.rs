// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Identity-only protobuf adapters; primitive inputs and operations are unchanged.

use crypto_proto::convert::UnsupportedProtoAlgorithm;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoRsaHashIdentifier, CryptoRsaPublicKeyDerEncodingIdentifier, RsaHashAlgorithm,
    RsaPublicKeyDerEncoding as ProtoRsaEncoding,
};

use crate::{RsaHash, RsaPublicKeyDerEncoding};

impl TryFrom<&CryptoRsaHashIdentifier> for RsaHash {
    type Error = UnsupportedProtoAlgorithm;

    fn try_from(identifier: &CryptoRsaHashIdentifier) -> Result<Self, Self::Error> {
        // Unknown modifiers must not be silently stripped from a recognized
        // identity. The decoded clearing owner retains them on this error path.
        if !identifier.__buffa_unknown_fields.is_empty() {
            return Err(UnsupportedProtoAlgorithm);
        }
        match identifier.hash.as_known() {
            Some(RsaHashAlgorithm::RSA_HASH_ALGORITHM_SHA1) => Ok(Self::Sha1),
            Some(RsaHashAlgorithm::RSA_HASH_ALGORITHM_SHA256) => Ok(Self::Sha256),
            Some(RsaHashAlgorithm::RSA_HASH_ALGORITHM_SHA384) => Ok(Self::Sha384),
            Some(RsaHashAlgorithm::RSA_HASH_ALGORITHM_SHA512) => Ok(Self::Sha512),
            _ => Err(UnsupportedProtoAlgorithm),
        }
    }
}

impl From<RsaHash> for CryptoRsaHashIdentifier {
    fn from(value: RsaHash) -> Self {
        // Exhaustive native matching makes a newly introduced variant require
        // a reviewed schema mapping without changing existing discriminants.
        let identity = match value {
            RsaHash::Sha1 => RsaHashAlgorithm::RSA_HASH_ALGORITHM_SHA1,
            RsaHash::Sha256 => RsaHashAlgorithm::RSA_HASH_ALGORITHM_SHA256,
            RsaHash::Sha384 => RsaHashAlgorithm::RSA_HASH_ALGORITHM_SHA384,
            RsaHash::Sha512 => RsaHashAlgorithm::RSA_HASH_ALGORITHM_SHA512,
        };
        Self {
            hash: identity.into(),
            __buffa_unknown_fields: Default::default(),
        }
    }
}

impl TryFrom<&CryptoRsaPublicKeyDerEncodingIdentifier> for RsaPublicKeyDerEncoding {
    type Error = UnsupportedProtoAlgorithm;

    fn try_from(identifier: &CryptoRsaPublicKeyDerEncodingIdentifier) -> Result<Self, Self::Error> {
        // Unknown modifiers must not be silently stripped from a recognized
        // identity. The decoded clearing owner retains them on this error path.
        if !identifier.__buffa_unknown_fields.is_empty() {
            return Err(UnsupportedProtoAlgorithm);
        }
        match identifier.encoding.as_known() {
            Some(ProtoRsaEncoding::RSA_PUBLIC_KEY_DER_ENCODING_PKCS1) => Ok(Self::Pkcs1),
            Some(ProtoRsaEncoding::RSA_PUBLIC_KEY_DER_ENCODING_SPKI) => Ok(Self::Spki),
            _ => Err(UnsupportedProtoAlgorithm),
        }
    }
}

impl From<RsaPublicKeyDerEncoding> for CryptoRsaPublicKeyDerEncodingIdentifier {
    fn from(value: RsaPublicKeyDerEncoding) -> Self {
        // Exhaustive native matching makes a newly introduced variant require
        // a reviewed schema mapping without changing existing discriminants.
        let identity = match value {
            RsaPublicKeyDerEncoding::Pkcs1 => ProtoRsaEncoding::RSA_PUBLIC_KEY_DER_ENCODING_PKCS1,
            RsaPublicKeyDerEncoding::Spki => ProtoRsaEncoding::RSA_PUBLIC_KEY_DER_ENCODING_SPKI,
        };
        Self {
            encoding: identity.into(),
            __buffa_unknown_fields: Default::default(),
        }
    }
}
