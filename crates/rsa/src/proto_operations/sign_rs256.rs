// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::RsaSigningKey;
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoRsaPkcs1v15Sha256SignRequest, CryptoRsaPkcs1v15Sha256SignResult,
    CryptoRsaSigningKeyImportRequest, CryptoRsaSigningKeyImportResult,
};
use zeroize::{ZeroizeOnDrop, Zeroizing};

impl TryFrom<&CryptoRsaSigningKeyImportRequest> for RsaSigningKey {
    type Error = CryptoError;
    fn try_from(request: &CryptoRsaSigningKeyImportRequest) -> Result<Self, Self::Error> {
        Self::from_pkcs8_der(&request.secret_key)
    }
}

impl RsaSigningKey {
    /// Exports the schema's public-only import result from the validated owner.
    pub fn public_key_proto(&self) -> Result<CryptoRsaSigningKeyImportResult, CryptoError> {
        let mut public = self.public_key()?;
        Ok(CryptoRsaSigningKeyImportResult {
            public_key_spki_der: core::mem::take(&mut public.spki_der).into(),
            modulus: core::mem::take(&mut public.modulus).into(),
            exponent: core::mem::take(&mut public.exponent).into(),
        })
    }
}

/// Owns imported private state and the exact message under drop cleanup.
pub struct RsaPkcs1v15Sha256SignInputs {
    key: RsaSigningKey,
    message: Zeroizing<Vec<u8>>,
}

impl ZeroizeOnDrop for RsaPkcs1v15Sha256SignInputs {}

impl TryFrom<&CryptoRsaPkcs1v15Sha256SignRequest> for RsaPkcs1v15Sha256SignInputs {
    type Error = CryptoError;
    fn try_from(request: &CryptoRsaPkcs1v15Sha256SignRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            key: RsaSigningKey::from_pkcs8_der(&request.secret_key)?,
            message: Zeroizing::new(request.message.to_vec()),
        })
    }
}

impl RsaPkcs1v15Sha256SignInputs {
    /// Executes only the fixed RS256 suite with mandatory entropy-backed blinding.
    pub fn sign(&self) -> Result<CryptoRsaPkcs1v15Sha256SignResult, CryptoError> {
        Ok(CryptoRsaPkcs1v15Sha256SignResult {
            signature: self.key.sign_rs256(&self.message)?.into(),
        })
    }
}
