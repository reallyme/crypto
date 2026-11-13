// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Exact RSA-PSS verification options; fixed signature suites remain unchanged.

use crate::{RsaHash, RsaPssParams};
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoRsaHashIdentifier, CryptoRsaPssParams,
};

impl TryFrom<&CryptoRsaPssParams> for RsaPssParams {
    type Error = CryptoError;

    fn try_from(value: &CryptoRsaPssParams) -> Result<Self, Self::Error> {
        if !value.__buffa_unknown_fields.is_empty() {
            return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER);
        }
        let message_hash = RsaHash::try_from(&CryptoRsaHashIdentifier {
            hash: value.message_hash,
            __buffa_unknown_fields: Default::default(),
        })?;
        let mgf1_hash = RsaHash::try_from(&CryptoRsaHashIdentifier {
            hash: value.mgf1_hash,
            __buffa_unknown_fields: Default::default(),
        })?;
        let salt_len = usize::try_from(
            value
                .salt_length
                .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?,
        )
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_LENGTH)?;
        Ok(Self {
            message_hash,
            mgf1_hash,
            salt_len,
        })
    }
}

impl TryFrom<&RsaPssParams> for CryptoRsaPssParams {
    type Error = CryptoError;

    fn try_from(value: &RsaPssParams) -> Result<Self, Self::Error> {
        // Preserve explicit zero and reject an unrepresentable native length.
        let salt_length =
            u32::try_from(value.salt_len).map_err(|_| CryptoError::PRIMITIVE_INVALID_LENGTH)?;
        Ok(Self {
            message_hash: CryptoRsaHashIdentifier::from(value.message_hash).hash,
            mgf1_hash: CryptoRsaHashIdentifier::from(value.mgf1_hash).hash,
            salt_length: Some(salt_length),
            __buffa_unknown_fields: Default::default(),
        })
    }
}
