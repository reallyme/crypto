// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Algorithm and typed-error mapping for protobuf operation processing.

#[cfg(all(
    any(
        feature = "sha2",
        feature = "sha3",
        feature = "aes",
        feature = "aes-gcm-siv",
        feature = "chacha20-poly1305",
        feature = "hmac",
        feature = "aes-kw",
        feature = "kmac",
        feature = "hkdf",
        feature = "argon2id",
        feature = "pbkdf2",
        feature = "concat-kdf"
    ),
    any(feature = "native", feature = "wasm")
))]
use buffa::EnumValue;
use buffa::{MessageField, ProtoBox};
#[cfg(all(
    any(
        feature = "aes",
        feature = "aes-gcm-siv",
        feature = "chacha20-poly1305"
    ),
    any(feature = "native", feature = "wasm")
))]
use crypto_core::AeadAlgorithm as CoreAead;
#[cfg(all(
    any(feature = "sha2", feature = "sha3"),
    any(feature = "native", feature = "wasm")
))]
use crypto_core::HashAlgorithm as CoreHash;
#[cfg(all(feature = "aes-kw", any(feature = "native", feature = "wasm")))]
use crypto_core::KeyWrapAlgorithm as CoreKeyWrap;
#[cfg(all(feature = "hmac", any(feature = "native", feature = "wasm")))]
use crypto_core::MacAlgorithm;
#[cfg(all(
    any(
        feature = "aes",
        feature = "aes-gcm-siv",
        feature = "chacha20-poly1305"
    ),
    any(feature = "native", feature = "wasm")
))]
use crypto_proto::generated::proto::reallyme::crypto::v1::AeadAlgorithm as ProtoAead;
#[cfg(all(
    any(feature = "sha2", feature = "sha3"),
    any(feature = "native", feature = "wasm")
))]
use crypto_proto::generated::proto::reallyme::crypto::v1::HashAlgorithm as ProtoHash;
#[cfg(all(feature = "hpke", any(feature = "native", feature = "wasm")))]
use crypto_proto::generated::proto::reallyme::crypto::v1::HpkeSuiteIdentifier;
#[cfg(all(
    any(
        feature = "kmac",
        feature = "hkdf",
        feature = "argon2id",
        feature = "pbkdf2",
        feature = "concat-kdf"
    ),
    any(feature = "native", feature = "wasm")
))]
use crypto_proto::generated::proto::reallyme::crypto::v1::KdfAlgorithm as ProtoKdf;
#[cfg(all(feature = "aes-kw", any(feature = "native", feature = "wasm")))]
use crypto_proto::generated::proto::reallyme::crypto::v1::KeyWrapAlgorithm as ProtoKeyWrap;
#[cfg(all(feature = "hmac", any(feature = "native", feature = "wasm")))]
use crypto_proto::generated::proto::reallyme::crypto::v1::MacAlgorithm as ProtoMac;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as ProtoAlgorithmBranch,
    CryptoAlgorithmIdentifier,
};
use crypto_proto::wire::CryptoWireError;

use super::identifier::algorithm_branch;
use super::wire_error::invalid_parameter;
#[cfg(all(
    any(
        feature = "sha2",
        feature = "sha3",
        feature = "aes",
        feature = "aes-gcm-siv",
        feature = "chacha20-poly1305",
        feature = "hmac",
        feature = "aes-kw",
        feature = "kmac",
        feature = "hkdf",
        feature = "argon2id",
        feature = "pbkdf2",
        feature = "concat-kdf",
        feature = "hpke"
    ),
    any(feature = "native", feature = "wasm")
))]
use super::wire_error::unsupported_algorithm;

#[cfg(all(feature = "hpke", any(feature = "native", feature = "wasm")))]
pub(super) fn hpke_suite(
    identifier: &MessageField<CryptoAlgorithmIdentifier, impl ProtoBox<CryptoAlgorithmIdentifier>>,
) -> Result<crate::hpke::HpkeSuite, CryptoWireError> {
    match algorithm_branch(identifier)? {
        ProtoAlgorithmBranch::HpkeSuite(suite) => hpke_suite_components(suite),
        _ => Err(invalid_parameter()),
    }
}

#[cfg(all(feature = "hpke", any(feature = "native", feature = "wasm")))]
fn hpke_suite_components(
    suite: &HpkeSuiteIdentifier,
) -> Result<crate::hpke::HpkeSuite, CryptoWireError> {
    let kem = u16::try_from(suite.kem.to_i32())
        .ok()
        .and_then(|value| crate::hpke::HpkeKemId::try_from(value).ok())
        .ok_or_else(unsupported_algorithm)?;
    let kdf = u16::try_from(suite.kdf.to_i32())
        .ok()
        .and_then(|value| crate::hpke::HpkeKdfId::try_from(value).ok())
        .ok_or_else(unsupported_algorithm)?;
    let aead = u16::try_from(suite.aead.to_i32())
        .ok()
        .and_then(|value| crate::hpke::HpkeAeadId::try_from(value).ok())
        .ok_or_else(unsupported_algorithm)?;
    Ok(crate::hpke::HpkeSuite::new(kem, kdf, aead))
}

#[cfg(all(
    any(
        feature = "aes",
        feature = "aes-gcm-siv",
        feature = "chacha20-poly1305"
    ),
    any(feature = "native", feature = "wasm")
))]
pub(super) fn aead_algorithm(
    identifier: &MessageField<CryptoAlgorithmIdentifier, impl ProtoBox<CryptoAlgorithmIdentifier>>,
) -> Result<CoreAead, CryptoWireError> {
    match algorithm_branch(identifier)? {
        ProtoAlgorithmBranch::Aead(value) => value
            .as_known()
            .ok_or_else(unsupported_algorithm)
            .and_then(|value| CoreAead::try_from(value).map_err(|_| unsupported_algorithm())),
        _ => Err(invalid_parameter()),
    }
}

#[cfg(all(
    any(feature = "sha2", feature = "sha3"),
    any(feature = "native", feature = "wasm")
))]
pub(super) fn hash_algorithm(
    identifier: &MessageField<CryptoAlgorithmIdentifier, impl ProtoBox<CryptoAlgorithmIdentifier>>,
) -> Result<CoreHash, CryptoWireError> {
    match algorithm_branch(identifier)? {
        ProtoAlgorithmBranch::Hash(value) => value
            .as_known()
            .ok_or_else(unsupported_algorithm)
            .and_then(|value| CoreHash::try_from(value).map_err(|_| unsupported_algorithm())),
        _ => Err(invalid_parameter()),
    }
}

#[cfg(all(feature = "hmac", any(feature = "native", feature = "wasm")))]
pub(super) fn mac_algorithm(
    identifier: &MessageField<CryptoAlgorithmIdentifier, impl ProtoBox<CryptoAlgorithmIdentifier>>,
) -> Result<MacAlgorithm, CryptoWireError> {
    match algorithm_branch(identifier)? {
        ProtoAlgorithmBranch::Mac(value) => match value.as_known() {
            Some(ProtoMac::MAC_ALGORITHM_HMAC_SHA256) => Ok(MacAlgorithm::HmacSha256),
            Some(ProtoMac::MAC_ALGORITHM_HMAC_SHA384) => Ok(MacAlgorithm::HmacSha384),
            Some(ProtoMac::MAC_ALGORITHM_HMAC_SHA512) => Ok(MacAlgorithm::HmacSha512),
            Some(ProtoMac::MAC_ALGORITHM_UNSPECIFIED) | None => Err(unsupported_algorithm()),
        },
        _ => Err(invalid_parameter()),
    }
}

#[cfg(all(feature = "kmac", any(feature = "native", feature = "wasm")))]
pub(super) fn require_kmac256(
    identifier: &MessageField<CryptoAlgorithmIdentifier, impl ProtoBox<CryptoAlgorithmIdentifier>>,
) -> Result<(), CryptoWireError> {
    match algorithm_branch(identifier)? {
        ProtoAlgorithmBranch::Kdf(value)
            if value.as_known() == Some(ProtoKdf::KDF_ALGORITHM_KMAC_256) =>
        {
            Ok(())
        }
        ProtoAlgorithmBranch::Kdf(_) => Err(unsupported_algorithm()),
        _ => Err(invalid_parameter()),
    }
}

#[cfg(all(feature = "argon2id", any(feature = "native", feature = "wasm")))]
pub(super) fn require_argon2id(
    identifier: &MessageField<CryptoAlgorithmIdentifier, impl ProtoBox<CryptoAlgorithmIdentifier>>,
) -> Result<(), CryptoWireError> {
    match algorithm_branch(identifier)? {
        ProtoAlgorithmBranch::Kdf(value)
            if value.as_known() == Some(ProtoKdf::KDF_ALGORITHM_ARGON2ID) =>
        {
            Ok(())
        }
        ProtoAlgorithmBranch::Kdf(_) => Err(unsupported_algorithm()),
        _ => Err(invalid_parameter()),
    }
}

#[cfg(all(feature = "hkdf", any(feature = "native", feature = "wasm")))]
pub(super) fn hkdf_suite(
    identifier: &MessageField<CryptoAlgorithmIdentifier, impl ProtoBox<CryptoAlgorithmIdentifier>>,
) -> Result<(crypto_hkdf::HkdfSuite, ProtoKdf), CryptoWireError> {
    match algorithm_branch(identifier)? {
        ProtoAlgorithmBranch::Kdf(value) => match value.as_known() {
            Some(ProtoKdf::KDF_ALGORITHM_HKDF_SHA256) => Ok((
                crypto_hkdf::HkdfSuite::Sha2_256,
                ProtoKdf::KDF_ALGORITHM_HKDF_SHA256,
            )),
            Some(ProtoKdf::KDF_ALGORITHM_HKDF_SHA384) => Ok((
                crypto_hkdf::HkdfSuite::Sha2_384,
                ProtoKdf::KDF_ALGORITHM_HKDF_SHA384,
            )),
            _ => Err(unsupported_algorithm()),
        },
        _ => Err(invalid_parameter()),
    }
}

#[cfg(all(feature = "concat-kdf", any(feature = "native", feature = "wasm")))]
pub(super) fn require_jwa_concat_kdf_sha256(
    identifier: &MessageField<CryptoAlgorithmIdentifier, impl ProtoBox<CryptoAlgorithmIdentifier>>,
) -> Result<(), CryptoWireError> {
    match algorithm_branch(identifier)? {
        ProtoAlgorithmBranch::Kdf(value)
            if value.as_known() == Some(ProtoKdf::KDF_ALGORITHM_JWA_CONCAT_KDF_SHA256) =>
        {
            Ok(())
        }
        ProtoAlgorithmBranch::Kdf(_) => Err(unsupported_algorithm()),
        _ => Err(invalid_parameter()),
    }
}

#[cfg(all(feature = "pbkdf2", any(feature = "native", feature = "wasm")))]
pub(super) fn pbkdf2_prf(
    identifier: &MessageField<CryptoAlgorithmIdentifier, impl ProtoBox<CryptoAlgorithmIdentifier>>,
) -> Result<crypto_pbkdf2::Pbkdf2Prf, CryptoWireError> {
    match algorithm_branch(identifier)? {
        ProtoAlgorithmBranch::Kdf(value) => match value.as_known() {
            Some(ProtoKdf::KDF_ALGORITHM_PBKDF2_HMAC_SHA256) => {
                Ok(crypto_pbkdf2::Pbkdf2Prf::HmacSha256)
            }
            Some(ProtoKdf::KDF_ALGORITHM_PBKDF2_HMAC_SHA512) => {
                Ok(crypto_pbkdf2::Pbkdf2Prf::HmacSha512)
            }
            Some(_) | None => Err(unsupported_algorithm()),
        },
        _ => Err(invalid_parameter()),
    }
}

#[cfg(all(feature = "aes-kw", any(feature = "native", feature = "wasm")))]
pub(super) fn key_wrap_algorithm(
    identifier: &MessageField<CryptoAlgorithmIdentifier, impl ProtoBox<CryptoAlgorithmIdentifier>>,
) -> Result<CoreKeyWrap, CryptoWireError> {
    match algorithm_branch(identifier)? {
        ProtoAlgorithmBranch::KeyWrap(value) => match value.as_known() {
            Some(ProtoKeyWrap::KEY_WRAP_ALGORITHM_AES_128_KW) => Ok(CoreKeyWrap::Aes128Kw),
            Some(ProtoKeyWrap::KEY_WRAP_ALGORITHM_AES_192_KW) => Ok(CoreKeyWrap::Aes192Kw),
            Some(ProtoKeyWrap::KEY_WRAP_ALGORITHM_AES_256_KW) => Ok(CoreKeyWrap::Aes256Kw),
            Some(ProtoKeyWrap::KEY_WRAP_ALGORITHM_UNSPECIFIED) | None => {
                Err(unsupported_algorithm())
            }
        },
        _ => Err(invalid_parameter()),
    }
}

#[cfg(all(
    any(
        feature = "aes",
        feature = "aes-gcm-siv",
        feature = "chacha20-poly1305"
    ),
    any(feature = "native", feature = "wasm")
))]
pub(super) fn aead_identifier(algorithm: ProtoAead) -> CryptoAlgorithmIdentifier {
    CryptoAlgorithmIdentifier {
        algorithm: Some(ProtoAlgorithmBranch::Aead(EnumValue::from(algorithm))),
        __buffa_unknown_fields: Default::default(),
    }
}

#[cfg(all(
    any(feature = "sha2", feature = "sha3"),
    any(feature = "native", feature = "wasm")
))]
pub(super) fn hash_identifier(algorithm: ProtoHash) -> CryptoAlgorithmIdentifier {
    CryptoAlgorithmIdentifier {
        algorithm: Some(ProtoAlgorithmBranch::Hash(EnumValue::from(algorithm))),
        __buffa_unknown_fields: Default::default(),
    }
}

#[cfg(all(feature = "hmac", any(feature = "native", feature = "wasm")))]
pub(super) fn mac_identifier(algorithm: ProtoMac) -> CryptoAlgorithmIdentifier {
    CryptoAlgorithmIdentifier {
        algorithm: Some(ProtoAlgorithmBranch::Mac(EnumValue::from(algorithm))),
        __buffa_unknown_fields: Default::default(),
    }
}

#[cfg(all(
    any(
        feature = "kmac",
        feature = "hkdf",
        feature = "argon2id",
        feature = "pbkdf2",
        feature = "concat-kdf"
    ),
    any(feature = "native", feature = "wasm")
))]
pub(super) fn kdf_identifier(algorithm: ProtoKdf) -> CryptoAlgorithmIdentifier {
    CryptoAlgorithmIdentifier {
        algorithm: Some(ProtoAlgorithmBranch::Kdf(EnumValue::from(algorithm))),
        __buffa_unknown_fields: Default::default(),
    }
}

#[cfg(all(feature = "aes-kw", any(feature = "native", feature = "wasm")))]
pub(super) fn key_wrap_identifier(algorithm: CoreKeyWrap) -> CryptoAlgorithmIdentifier {
    CryptoAlgorithmIdentifier {
        algorithm: Some(ProtoAlgorithmBranch::KeyWrap(EnumValue::from(
            proto_key_wrap_algorithm(algorithm),
        ))),
        __buffa_unknown_fields: Default::default(),
    }
}

#[cfg(all(feature = "aes-kw", any(feature = "native", feature = "wasm")))]
pub(super) fn proto_key_wrap_algorithm(algorithm: CoreKeyWrap) -> ProtoKeyWrap {
    match algorithm {
        CoreKeyWrap::Aes128Kw => ProtoKeyWrap::KEY_WRAP_ALGORITHM_AES_128_KW,
        CoreKeyWrap::Aes192Kw => ProtoKeyWrap::KEY_WRAP_ALGORITHM_AES_192_KW,
        CoreKeyWrap::Aes256Kw => ProtoKeyWrap::KEY_WRAP_ALGORITHM_AES_256_KW,
        _ => ProtoKeyWrap::KEY_WRAP_ALGORITHM_UNSPECIFIED,
    }
}

#[cfg(all(feature = "hmac", any(feature = "native", feature = "wasm")))]
pub(super) fn proto_mac_algorithm(algorithm: MacAlgorithm) -> ProtoMac {
    match algorithm {
        MacAlgorithm::HmacSha256 => ProtoMac::MAC_ALGORITHM_HMAC_SHA256,
        MacAlgorithm::HmacSha384 => ProtoMac::MAC_ALGORITHM_HMAC_SHA384,
        MacAlgorithm::HmacSha512 => ProtoMac::MAC_ALGORITHM_HMAC_SHA512,
    }
}
