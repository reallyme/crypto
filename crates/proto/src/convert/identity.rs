// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Total identity conversion, including unknown generated enum values.

use crypto_core::{
    AeadAlgorithm as CoreAead, Algorithm as CoreKey, HashAlgorithm as CoreHash,
    KeyWrapAlgorithm as CoreKeyWrap, MacAlgorithm as CoreMac,
};

use crate::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as Identity, AeadAlgorithm,
    CryptoAlgorithmIdentifier, CryptoKeyAlgorithmIdentifier, HashAlgorithm, KemAlgorithm,
    KeyAgreementAlgorithm, KeyAlgorithm, KeyWrapAlgorithm, MacAlgorithm, SignatureAlgorithm,
};

use super::UnsupportedProtoAlgorithm;

fn require_known_fields(
    identifier: &CryptoAlgorithmIdentifier,
) -> Result<(), UnsupportedProtoAlgorithm> {
    if identifier.__buffa_unknown_fields.is_empty() {
        Ok(())
    } else {
        Err(UnsupportedProtoAlgorithm)
    }
}

impl TryFrom<&CryptoAlgorithmIdentifier> for CoreKey {
    type Error = UnsupportedProtoAlgorithm;

    fn try_from(identifier: &CryptoAlgorithmIdentifier) -> Result<Self, Self::Error> {
        require_known_fields(identifier)?;
        Self::try_from(&CryptoKeyAlgorithmIdentifier {
            algorithm: key_identity(identifier)?.into(),
            __buffa_unknown_fields: Default::default(),
        })
    }
}

impl TryFrom<&CryptoKeyAlgorithmIdentifier> for CoreKey {
    type Error = UnsupportedProtoAlgorithm;

    fn try_from(identifier: &CryptoKeyAlgorithmIdentifier) -> Result<Self, Self::Error> {
        if !identifier.__buffa_unknown_fields.is_empty() {
            return Err(UnsupportedProtoAlgorithm);
        }
        let key = identifier
            .algorithm
            .as_known()
            .ok_or(UnsupportedProtoAlgorithm)?;
        match key {
            KeyAlgorithm::KEY_ALGORITHM_ED25519 => Ok(Self::Ed25519),
            KeyAlgorithm::KEY_ALGORITHM_X25519 => Ok(Self::X25519),
            KeyAlgorithm::KEY_ALGORITHM_P256 => Ok(Self::P256),
            KeyAlgorithm::KEY_ALGORITHM_P384 => Ok(Self::P384),
            KeyAlgorithm::KEY_ALGORITHM_P521 => Ok(Self::P521),
            KeyAlgorithm::KEY_ALGORITHM_SECP256K1 => Ok(Self::Secp256k1),
            KeyAlgorithm::KEY_ALGORITHM_ML_DSA_44 => Ok(Self::MlDsa44),
            KeyAlgorithm::KEY_ALGORITHM_ML_DSA_65 => Ok(Self::MlDsa65),
            KeyAlgorithm::KEY_ALGORITHM_ML_DSA_87 => Ok(Self::MlDsa87),
            KeyAlgorithm::KEY_ALGORITHM_SLH_DSA_SHA2_128S => Ok(Self::SlhDsaSha2_128s),
            KeyAlgorithm::KEY_ALGORITHM_ML_KEM_512 => Ok(Self::MlKem512),
            KeyAlgorithm::KEY_ALGORITHM_ML_KEM_768 => Ok(Self::MlKem768),
            KeyAlgorithm::KEY_ALGORITHM_ML_KEM_1024 => Ok(Self::MlKem1024),
            KeyAlgorithm::KEY_ALGORITHM_X_WING_768 => Ok(Self::XWing768),
            KeyAlgorithm::KEY_ALGORITHM_UNSPECIFIED => Err(UnsupportedProtoAlgorithm),
        }
    }
}

fn key_identity(
    identifier: &CryptoAlgorithmIdentifier,
) -> Result<KeyAlgorithm, UnsupportedProtoAlgorithm> {
    match &identifier.algorithm {
        Some(Identity::Signature(value)) => match value.as_known() {
            Some(SignatureAlgorithm::SIGNATURE_ALGORITHM_ED25519) => {
                Ok(KeyAlgorithm::KEY_ALGORITHM_ED25519)
            }
            Some(SignatureAlgorithm::SIGNATURE_ALGORITHM_ECDSA_P256_SHA256) => {
                Ok(KeyAlgorithm::KEY_ALGORITHM_P256)
            }
            Some(SignatureAlgorithm::SIGNATURE_ALGORITHM_ECDSA_P384_SHA384) => {
                Ok(KeyAlgorithm::KEY_ALGORITHM_P384)
            }
            Some(SignatureAlgorithm::SIGNATURE_ALGORITHM_ECDSA_P521_SHA512) => {
                Ok(KeyAlgorithm::KEY_ALGORITHM_P521)
            }
            Some(SignatureAlgorithm::SIGNATURE_ALGORITHM_ECDSA_SECP256K1_SHA256) => {
                Ok(KeyAlgorithm::KEY_ALGORITHM_SECP256K1)
            }
            Some(SignatureAlgorithm::SIGNATURE_ALGORITHM_ML_DSA_44) => {
                Ok(KeyAlgorithm::KEY_ALGORITHM_ML_DSA_44)
            }
            Some(SignatureAlgorithm::SIGNATURE_ALGORITHM_ML_DSA_65) => {
                Ok(KeyAlgorithm::KEY_ALGORITHM_ML_DSA_65)
            }
            Some(SignatureAlgorithm::SIGNATURE_ALGORITHM_ML_DSA_87) => {
                Ok(KeyAlgorithm::KEY_ALGORITHM_ML_DSA_87)
            }
            Some(SignatureAlgorithm::SIGNATURE_ALGORITHM_SLH_DSA_SHA2_128S) => {
                Ok(KeyAlgorithm::KEY_ALGORITHM_SLH_DSA_SHA2_128S)
            }
            // Fixed signature suites are not interchangeable key identities.
            _ => Err(UnsupportedProtoAlgorithm),
        },
        Some(Identity::KeyAgreement(value)) => match value.as_known() {
            Some(KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_X25519) => {
                Ok(KeyAlgorithm::KEY_ALGORITHM_X25519)
            }
            Some(KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_P256_ECDH) => {
                Ok(KeyAlgorithm::KEY_ALGORITHM_P256)
            }
            Some(KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_P384_ECDH) => {
                Ok(KeyAlgorithm::KEY_ALGORITHM_P384)
            }
            Some(KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_P521_ECDH) => {
                Ok(KeyAlgorithm::KEY_ALGORITHM_P521)
            }
            _ => Err(UnsupportedProtoAlgorithm),
        },
        Some(Identity::Kem(value)) => match value.as_known() {
            Some(KemAlgorithm::KEM_ALGORITHM_ML_KEM_512) => {
                Ok(KeyAlgorithm::KEY_ALGORITHM_ML_KEM_512)
            }
            Some(KemAlgorithm::KEM_ALGORITHM_ML_KEM_768) => {
                Ok(KeyAlgorithm::KEY_ALGORITHM_ML_KEM_768)
            }
            Some(KemAlgorithm::KEM_ALGORITHM_ML_KEM_1024) => {
                Ok(KeyAlgorithm::KEY_ALGORITHM_ML_KEM_1024)
            }
            Some(KemAlgorithm::KEM_ALGORITHM_X_WING_768) => {
                Ok(KeyAlgorithm::KEY_ALGORITHM_X_WING_768)
            }
            _ => Err(UnsupportedProtoAlgorithm),
        },
        _ => Err(UnsupportedProtoAlgorithm),
    }
}

impl TryFrom<&CryptoAlgorithmIdentifier> for CoreAead {
    type Error = UnsupportedProtoAlgorithm;

    fn try_from(identifier: &CryptoAlgorithmIdentifier) -> Result<Self, Self::Error> {
        require_known_fields(identifier)?;
        let Some(Identity::Aead(value)) = &identifier.algorithm else {
            return Err(UnsupportedProtoAlgorithm);
        };
        match value.as_known() {
            Some(AeadAlgorithm::AEAD_ALGORITHM_AES_128_GCM) => Ok(Self::Aes128Gcm),
            Some(AeadAlgorithm::AEAD_ALGORITHM_AES_192_GCM) => Ok(Self::Aes192Gcm),
            Some(AeadAlgorithm::AEAD_ALGORITHM_AES_256_GCM) => Ok(Self::Aes256Gcm),
            Some(AeadAlgorithm::AEAD_ALGORITHM_AES_256_GCM_SIV) => Ok(Self::Aes256GcmSiv),
            Some(AeadAlgorithm::AEAD_ALGORITHM_CHACHA20_POLY1305) => Ok(Self::ChaCha20Poly1305),
            Some(AeadAlgorithm::AEAD_ALGORITHM_XCHACHA20_POLY1305) => Ok(Self::XChaCha20Poly1305),
            Some(AeadAlgorithm::AEAD_ALGORITHM_UNSPECIFIED) | None => {
                Err(UnsupportedProtoAlgorithm)
            }
        }
    }
}

impl TryFrom<&CryptoAlgorithmIdentifier> for CoreHash {
    type Error = UnsupportedProtoAlgorithm;

    fn try_from(identifier: &CryptoAlgorithmIdentifier) -> Result<Self, Self::Error> {
        require_known_fields(identifier)?;
        let Some(Identity::Hash(value)) = &identifier.algorithm else {
            return Err(UnsupportedProtoAlgorithm);
        };
        match value.as_known() {
            Some(HashAlgorithm::HASH_ALGORITHM_SHA2_256) => Ok(Self::Sha2_256),
            Some(HashAlgorithm::HASH_ALGORITHM_SHA2_384) => Ok(Self::Sha2_384),
            Some(HashAlgorithm::HASH_ALGORITHM_SHA2_512) => Ok(Self::Sha2_512),
            Some(HashAlgorithm::HASH_ALGORITHM_SHA3_224) => Ok(Self::Sha3_224),
            Some(HashAlgorithm::HASH_ALGORITHM_SHA3_256) => Ok(Self::Sha3_256),
            Some(HashAlgorithm::HASH_ALGORITHM_SHA3_384) => Ok(Self::Sha3_384),
            Some(HashAlgorithm::HASH_ALGORITHM_SHA3_512) => Ok(Self::Sha3_512),
            Some(HashAlgorithm::HASH_ALGORITHM_UNSPECIFIED) | None => {
                Err(UnsupportedProtoAlgorithm)
            }
        }
    }
}

impl TryFrom<&CryptoAlgorithmIdentifier> for CoreMac {
    type Error = UnsupportedProtoAlgorithm;

    fn try_from(identifier: &CryptoAlgorithmIdentifier) -> Result<Self, Self::Error> {
        require_known_fields(identifier)?;
        let Some(Identity::Mac(value)) = &identifier.algorithm else {
            return Err(UnsupportedProtoAlgorithm);
        };
        match value.as_known() {
            Some(MacAlgorithm::MAC_ALGORITHM_HMAC_SHA256) => Ok(Self::HmacSha256),
            Some(MacAlgorithm::MAC_ALGORITHM_HMAC_SHA384) => Ok(Self::HmacSha384),
            Some(MacAlgorithm::MAC_ALGORITHM_HMAC_SHA512) => Ok(Self::HmacSha512),
            Some(MacAlgorithm::MAC_ALGORITHM_UNSPECIFIED) | None => Err(UnsupportedProtoAlgorithm),
        }
    }
}

impl TryFrom<&CryptoAlgorithmIdentifier> for CoreKeyWrap {
    type Error = UnsupportedProtoAlgorithm;

    fn try_from(identifier: &CryptoAlgorithmIdentifier) -> Result<Self, Self::Error> {
        require_known_fields(identifier)?;
        let Some(Identity::KeyWrap(value)) = &identifier.algorithm else {
            return Err(UnsupportedProtoAlgorithm);
        };
        match value.as_known() {
            Some(KeyWrapAlgorithm::KEY_WRAP_ALGORITHM_AES_128_KW) => Ok(Self::Aes128Kw),
            Some(KeyWrapAlgorithm::KEY_WRAP_ALGORITHM_AES_192_KW) => Ok(Self::Aes192Kw),
            Some(KeyWrapAlgorithm::KEY_WRAP_ALGORITHM_AES_256_KW) => Ok(Self::Aes256Kw),
            Some(KeyWrapAlgorithm::KEY_WRAP_ALGORITHM_UNSPECIFIED) | None => {
                Err(UnsupportedProtoAlgorithm)
            }
        }
    }
}

impl From<CoreKey> for KeyAlgorithm {
    fn from(value: CoreKey) -> Self {
        match value {
            CoreKey::Ed25519 => Self::KEY_ALGORITHM_ED25519,
            CoreKey::X25519 => Self::KEY_ALGORITHM_X25519,
            CoreKey::P256 => Self::KEY_ALGORITHM_P256,
            CoreKey::P384 => Self::KEY_ALGORITHM_P384,
            CoreKey::P521 => Self::KEY_ALGORITHM_P521,
            CoreKey::Secp256k1 => Self::KEY_ALGORITHM_SECP256K1,
            CoreKey::MlDsa44 => Self::KEY_ALGORITHM_ML_DSA_44,
            CoreKey::MlDsa65 => Self::KEY_ALGORITHM_ML_DSA_65,
            CoreKey::MlDsa87 => Self::KEY_ALGORITHM_ML_DSA_87,
            CoreKey::SlhDsaSha2_128s => Self::KEY_ALGORITHM_SLH_DSA_SHA2_128S,
            CoreKey::MlKem512 => Self::KEY_ALGORITHM_ML_KEM_512,
            CoreKey::MlKem768 => Self::KEY_ALGORITHM_ML_KEM_768,
            CoreKey::MlKem1024 => Self::KEY_ALGORITHM_ML_KEM_1024,
            CoreKey::XWing768 => Self::KEY_ALGORITHM_X_WING_768,
        }
    }
}

impl From<CoreMac> for MacAlgorithm {
    fn from(value: CoreMac) -> Self {
        match value {
            CoreMac::HmacSha256 => Self::MAC_ALGORITHM_HMAC_SHA256,
            CoreMac::HmacSha384 => Self::MAC_ALGORITHM_HMAC_SHA384,
            CoreMac::HmacSha512 => Self::MAC_ALGORITHM_HMAC_SHA512,
        }
    }
}

impl TryFrom<CoreKeyWrap> for KeyWrapAlgorithm {
    type Error = UnsupportedProtoAlgorithm;

    fn try_from(value: CoreKeyWrap) -> Result<Self, Self::Error> {
        match value {
            CoreKeyWrap::Aes128Kw => Ok(Self::KEY_WRAP_ALGORITHM_AES_128_KW),
            CoreKeyWrap::Aes192Kw => Ok(Self::KEY_WRAP_ALGORITHM_AES_192_KW),
            CoreKeyWrap::Aes256Kw => Ok(Self::KEY_WRAP_ALGORITHM_AES_256_KW),
            _ => Err(UnsupportedProtoAlgorithm),
        }
    }
}
