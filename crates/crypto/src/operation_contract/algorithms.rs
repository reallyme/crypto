// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

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
#[cfg(all(feature = "hpke-api", any(feature = "native", feature = "wasm")))]
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
#[cfg(any(
    feature = "aes",
    feature = "aes-gcm-siv",
    feature = "chacha20-poly1305",
    feature = "sha2",
    feature = "sha3",
    feature = "hmac",
    feature = "aes-kw"
))]
use super::identifier::native_identity;
use super::wire_error::invalid_parameter;
#[cfg(all(
    any(
        feature = "aes-kw",
        feature = "kmac",
        feature = "hkdf",
        feature = "argon2id",
        feature = "pbkdf2",
        feature = "concat-kdf",
        feature = "hpke-api"
    ),
    any(feature = "native", feature = "wasm")
))]
use super::wire_error::unsupported_algorithm;

#[cfg(all(feature = "hpke-api", any(feature = "native", feature = "wasm")))]
pub(super) fn hpke_suite(
    identifier: &MessageField<CryptoAlgorithmIdentifier, impl ProtoBox<CryptoAlgorithmIdentifier>>,
) -> Result<crate::hpke::HpkeSuite, CryptoWireError> {
    match algorithm_branch(identifier)? {
        ProtoAlgorithmBranch::HpkeSuite(suite) => hpke_suite_components(suite),
        _ => Err(invalid_parameter()),
    }
}

#[cfg(all(feature = "hpke-api", any(feature = "native", feature = "wasm")))]
fn hpke_suite_components(
    suite: &HpkeSuiteIdentifier,
) -> Result<crate::hpke::HpkeSuite, CryptoWireError> {
    crate::hpke::HpkeSuite::try_from(suite).map_err(|_| unsupported_algorithm())
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
        ProtoAlgorithmBranch::Aead(_) => native_identity(identifier),
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
        ProtoAlgorithmBranch::Hash(_) => native_identity(identifier),
        _ => Err(invalid_parameter()),
    }
}

#[cfg(all(feature = "hmac", any(feature = "native", feature = "wasm")))]
pub(super) fn mac_algorithm(
    identifier: &MessageField<CryptoAlgorithmIdentifier, impl ProtoBox<CryptoAlgorithmIdentifier>>,
) -> Result<MacAlgorithm, CryptoWireError> {
    match algorithm_branch(identifier)? {
        ProtoAlgorithmBranch::Mac(_) => native_identity(identifier),
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
        ProtoAlgorithmBranch::Kdf(value) => {
            use crypto_proto::generated::proto::reallyme::crypto::v1::{
                CryptoHkdfSuiteIdentifier, HashAlgorithm,
            };
            let (algorithm, hash) = match value.as_known() {
                Some(algorithm @ ProtoKdf::KDF_ALGORITHM_HKDF_SHA256) => {
                    (algorithm, HashAlgorithm::HASH_ALGORITHM_SHA2_256)
                }
                Some(algorithm @ ProtoKdf::KDF_ALGORITHM_HKDF_SHA384) => {
                    (algorithm, HashAlgorithm::HASH_ALGORITHM_SHA2_384)
                }
                _ => return Err(unsupported_algorithm()),
            };
            let identity = CryptoHkdfSuiteIdentifier {
                hash: hash.into(),
                __buffa_unknown_fields: Default::default(),
            };
            crypto_hkdf::HkdfSuite::try_from(&identity)
                .map(|suite| (suite, algorithm))
                .map_err(|_| unsupported_algorithm())
        }
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
        ProtoAlgorithmBranch::Kdf(value) => {
            use crypto_proto::generated::proto::reallyme::crypto::v1::{
                CryptoPbkdf2PrfIdentifier, MacAlgorithm,
            };
            let prf = match value.as_known() {
                Some(ProtoKdf::KDF_ALGORITHM_PBKDF2_HMAC_SHA256) => {
                    MacAlgorithm::MAC_ALGORITHM_HMAC_SHA256
                }
                Some(ProtoKdf::KDF_ALGORITHM_PBKDF2_HMAC_SHA512) => {
                    MacAlgorithm::MAC_ALGORITHM_HMAC_SHA512
                }
                _ => return Err(unsupported_algorithm()),
            };
            let identity = CryptoPbkdf2PrfIdentifier {
                prf: prf.into(),
                __buffa_unknown_fields: Default::default(),
            };
            crypto_pbkdf2::Pbkdf2Prf::try_from(&identity).map_err(|_| unsupported_algorithm())
        }
        _ => Err(invalid_parameter()),
    }
}

#[cfg(all(feature = "aes-kw", any(feature = "native", feature = "wasm")))]
pub(super) fn key_wrap_algorithm(
    identifier: &MessageField<CryptoAlgorithmIdentifier, impl ProtoBox<CryptoAlgorithmIdentifier>>,
) -> Result<CoreKeyWrap, CryptoWireError> {
    match algorithm_branch(identifier)? {
        ProtoAlgorithmBranch::KeyWrap(_) => native_identity(identifier),
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
pub(super) fn key_wrap_identifier(
    algorithm: CoreKeyWrap,
) -> Result<CryptoAlgorithmIdentifier, CryptoWireError> {
    Ok(CryptoAlgorithmIdentifier {
        algorithm: Some(ProtoAlgorithmBranch::KeyWrap(EnumValue::from(
            ProtoKeyWrap::try_from(algorithm).map_err(|_| unsupported_algorithm())?,
        ))),
        __buffa_unknown_fields: Default::default(),
    })
}

#[cfg(all(feature = "hmac", any(feature = "native", feature = "wasm")))]
pub(super) fn proto_mac_algorithm(algorithm: MacAlgorithm) -> ProtoMac {
    algorithm.into()
}
