// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! One semantic family vocabulary, preserving existing native ordinals.

use super::OperationFamily;
use buffa::EnumValue;
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::CryptoAlgorithmFamily;
impl TryFrom<EnumValue<CryptoAlgorithmFamily>> for OperationFamily {
    type Error = CryptoError;
    fn try_from(value: EnumValue<CryptoAlgorithmFamily>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(CryptoAlgorithmFamily::CRYPTO_ALGORITHM_FAMILY_HASH) => Ok(Self::Hash),
            Some(CryptoAlgorithmFamily::CRYPTO_ALGORITHM_FAMILY_CONSTANT_TIME) => {
                Ok(Self::ConstantTime)
            }
            Some(CryptoAlgorithmFamily::CRYPTO_ALGORITHM_FAMILY_MAC) => Ok(Self::Mac),
            Some(CryptoAlgorithmFamily::CRYPTO_ALGORITHM_FAMILY_AEAD) => Ok(Self::Aead),
            Some(CryptoAlgorithmFamily::CRYPTO_ALGORITHM_FAMILY_KEY_WRAP) => Ok(Self::KeyWrap),
            Some(CryptoAlgorithmFamily::CRYPTO_ALGORITHM_FAMILY_KDF) => Ok(Self::Kdf),
            Some(CryptoAlgorithmFamily::CRYPTO_ALGORITHM_FAMILY_SIGNATURE) => Ok(Self::Signature),
            Some(CryptoAlgorithmFamily::CRYPTO_ALGORITHM_FAMILY_KEY_AGREEMENT) => {
                Ok(Self::KeyAgreement)
            }
            Some(CryptoAlgorithmFamily::CRYPTO_ALGORITHM_FAMILY_KEM) => Ok(Self::Kem),
            Some(CryptoAlgorithmFamily::CRYPTO_ALGORITHM_FAMILY_HPKE) => Ok(Self::Hpke),
            Some(CryptoAlgorithmFamily::CRYPTO_ALGORITHM_FAMILY_PLATFORM_KEY) => {
                Ok(Self::PlatformKey)
            }
            _ => Err(CryptoError::PRIMITIVE_INVALID_PARAMETER),
        }
    }
}
impl From<OperationFamily> for CryptoAlgorithmFamily {
    fn from(value: OperationFamily) -> Self {
        match value {
            OperationFamily::Hash => Self::CRYPTO_ALGORITHM_FAMILY_HASH,
            OperationFamily::ConstantTime => Self::CRYPTO_ALGORITHM_FAMILY_CONSTANT_TIME,
            OperationFamily::Mac => Self::CRYPTO_ALGORITHM_FAMILY_MAC,
            OperationFamily::Aead => Self::CRYPTO_ALGORITHM_FAMILY_AEAD,
            OperationFamily::KeyWrap => Self::CRYPTO_ALGORITHM_FAMILY_KEY_WRAP,
            OperationFamily::Kdf => Self::CRYPTO_ALGORITHM_FAMILY_KDF,
            OperationFamily::Signature => Self::CRYPTO_ALGORITHM_FAMILY_SIGNATURE,
            OperationFamily::KeyAgreement => Self::CRYPTO_ALGORITHM_FAMILY_KEY_AGREEMENT,
            OperationFamily::Kem => Self::CRYPTO_ALGORITHM_FAMILY_KEM,
            OperationFamily::Hpke => Self::CRYPTO_ALGORITHM_FAMILY_HPKE,
            OperationFamily::PlatformKey => Self::CRYPTO_ALGORITHM_FAMILY_PLATFORM_KEY,
        }
    }
}
