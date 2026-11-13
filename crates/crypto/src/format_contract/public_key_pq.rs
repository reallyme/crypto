// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Delegates preserve each PQ leaf's public-key validation policy.

use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoPublicKeyFormatResult, PublicKeyFormatOperation,
};

#[cfg(all(feature = "ml-dsa-44", any(feature = "native", feature = "wasm")))]
pub(super) fn ml_dsa_44(
    operation: PublicKeyFormatOperation,
    public_key: &[u8],
) -> Result<CryptoPublicKeyFormatResult, CryptoError> {
    match operation {
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ENCODE => {
            let value = zeroize::Zeroizing::new(crypto_ml_dsa_44::encode_public_key(public_key)?);
            super::encoded(&value)
        }
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_DECODE => {
            let value = zeroize::Zeroizing::new(crypto_ml_dsa_44::decode_public_key(public_key)?);
            super::encoded(&value)
        }
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ASSERT => {
            super::encoded(crypto_ml_dsa_44::assert_public_key(public_key)?)
        }
        _ => Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
    }
}

#[cfg(all(feature = "ml-dsa-65", any(feature = "native", feature = "wasm")))]
pub(super) fn ml_dsa_65(
    operation: PublicKeyFormatOperation,
    public_key: &[u8],
) -> Result<CryptoPublicKeyFormatResult, CryptoError> {
    match operation {
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ENCODE => {
            let value = zeroize::Zeroizing::new(crypto_ml_dsa_65::encode_public_key(public_key)?);
            super::encoded(&value)
        }
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_DECODE => {
            let value = zeroize::Zeroizing::new(crypto_ml_dsa_65::decode_public_key(public_key)?);
            super::encoded(&value)
        }
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ASSERT => {
            super::encoded(crypto_ml_dsa_65::assert_public_key(public_key)?)
        }
        _ => Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
    }
}

#[cfg(all(feature = "ml-dsa-87", any(feature = "native", feature = "wasm")))]
pub(super) fn ml_dsa_87(
    operation: PublicKeyFormatOperation,
    public_key: &[u8],
) -> Result<CryptoPublicKeyFormatResult, CryptoError> {
    match operation {
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ENCODE => {
            let value = zeroize::Zeroizing::new(crypto_ml_dsa_87::encode_public_key(public_key)?);
            super::encoded(&value)
        }
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_DECODE => {
            let value = zeroize::Zeroizing::new(crypto_ml_dsa_87::decode_public_key(public_key)?);
            super::encoded(&value)
        }
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ASSERT => {
            super::encoded(crypto_ml_dsa_87::assert_public_key(public_key)?)
        }
        _ => Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
    }
}

#[cfg(all(feature = "ml-kem-512", any(feature = "native", feature = "wasm")))]
pub(super) fn ml_kem_512(
    operation: PublicKeyFormatOperation,
    public_key: &[u8],
) -> Result<CryptoPublicKeyFormatResult, CryptoError> {
    match operation {
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ENCODE => {
            let value = zeroize::Zeroizing::new(crypto_ml_kem_512::encode_ml_kem_512_public_key(
                public_key,
            )?);
            super::encoded(&value)
        }
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_DECODE => {
            let value = zeroize::Zeroizing::new(crypto_ml_kem_512::decode_ml_kem_512_public_key(
                public_key,
            )?);
            super::encoded(&value)
        }
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ASSERT => {
            super::encoded(crypto_ml_kem_512::assert_ml_kem_512_public_key(public_key)?)
        }
        _ => Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
    }
}

#[cfg(all(feature = "ml-kem-768", any(feature = "native", feature = "wasm")))]
pub(super) fn ml_kem_768(
    operation: PublicKeyFormatOperation,
    public_key: &[u8],
) -> Result<CryptoPublicKeyFormatResult, CryptoError> {
    match operation {
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ENCODE => {
            let value = zeroize::Zeroizing::new(crypto_ml_kem_768::encode_ml_kem_768_public_key(
                public_key,
            )?);
            super::encoded(&value)
        }
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_DECODE => {
            let value = zeroize::Zeroizing::new(crypto_ml_kem_768::decode_ml_kem_768_public_key(
                public_key,
            )?);
            super::encoded(&value)
        }
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ASSERT => {
            super::encoded(crypto_ml_kem_768::assert_ml_kem_768_public_key(public_key)?)
        }
        _ => Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
    }
}

#[cfg(all(feature = "ml-kem-1024", any(feature = "native", feature = "wasm")))]
pub(super) fn ml_kem_1024(
    operation: PublicKeyFormatOperation,
    public_key: &[u8],
) -> Result<CryptoPublicKeyFormatResult, CryptoError> {
    match operation {
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ENCODE => {
            let value = zeroize::Zeroizing::new(crypto_ml_kem_1024::encode_ml_kem_1024_public_key(
                public_key,
            )?);
            super::encoded(&value)
        }
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_DECODE => {
            let value = zeroize::Zeroizing::new(crypto_ml_kem_1024::decode_ml_kem_1024_public_key(
                public_key,
            )?);
            super::encoded(&value)
        }
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ASSERT => super::encoded(
            crypto_ml_kem_1024::assert_ml_kem_1024_public_key(public_key)?,
        ),
        _ => Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
    }
}

#[cfg(all(feature = "slh-dsa", any(feature = "native", feature = "wasm")))]
pub(super) fn slh_dsa(
    operation: PublicKeyFormatOperation,
    public_key: &[u8],
) -> Result<CryptoPublicKeyFormatResult, CryptoError> {
    match operation {
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ENCODE => {
            let value = zeroize::Zeroizing::new(
                crypto_slh_dsa::encode_slh_dsa_sha2_128s_public_key(public_key)?,
            );
            super::encoded(&value)
        }
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_DECODE => {
            let value = zeroize::Zeroizing::new(
                crypto_slh_dsa::decode_slh_dsa_sha2_128s_public_key(public_key)?,
            );
            super::encoded(&value)
        }
        _ => Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
    }
}
