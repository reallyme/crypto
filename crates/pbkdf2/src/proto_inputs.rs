// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protected standards-level PBKDF2 input; modern execution policy is unchanged.

use crate::{Pbkdf2Iterations, Pbkdf2Output, Pbkdf2Password, Pbkdf2Prf, Pbkdf2Request, Pbkdf2Salt};
use buffa::MessageField;
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm, CryptoAlgorithmIdentifier,
    CryptoKdfDeriveKeyResult, CryptoPbkdf2StandardsDeriveRequest, KdfAlgorithm,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Owns password and salt while borrowing the unchanged native leaf request.
/// This domain includes interoperability vectors below the modern facade floor.
pub struct StandardsDeriveInputs {
    prf: Pbkdf2Prf,
    password: Pbkdf2Password,
    salt: Pbkdf2Salt,
    iterations: Pbkdf2Iterations,
    output_len: usize,
}
impl Zeroize for StandardsDeriveInputs {
    fn zeroize(&mut self) {
        self.password.zeroize();
        self.salt.zeroize();
    }
}
impl ZeroizeOnDrop for StandardsDeriveInputs {}
impl TryFrom<&CryptoPbkdf2StandardsDeriveRequest> for StandardsDeriveInputs {
    type Error = CryptoError;
    fn try_from(request: &CryptoPbkdf2StandardsDeriveRequest) -> Result<Self, Self::Error> {
        let prf = Pbkdf2Prf::try_from(
            request
                .prf
                .as_option()
                .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?,
        )?;
        let password = Pbkdf2Password::from_slice(&request.password, prf)?;
        let salt = Pbkdf2Salt::from_slice(&request.salt, prf)?;
        let iterations = Pbkdf2Iterations::from_u32_conformance_only(request.iterations, prf)?;
        let output_len = usize::try_from(request.output_length)
            .map_err(|_| CryptoError::PRIMITIVE_INVALID_LENGTH)?;
        crate::types::validate_output_len(output_len)?;
        Ok(Self {
            prf,
            password,
            salt,
            iterations,
            output_len,
        })
    }
}
impl StandardsDeriveInputs {
    /// Borrows the original leaf request without normalizing either input.
    pub fn as_request(&self) -> Pbkdf2Request<'_> {
        Pbkdf2Request {
            prf: self.prf,
            password: &self.password,
            salt: &self.salt,
            iterations: self.iterations,
            output_len: self.output_len,
        }
    }
    /// Invoke the existing bounded leaf, retaining its combined-work limit.
    pub fn derive(&self) -> Result<Pbkdf2Output, CryptoError> {
        crate::derive_key(&self.as_request())
    }
    /// Derive directly through the existing leaf and copy into a clearing result.
    pub fn derive_result(&self) -> Result<CryptoKdfDeriveKeyResult, CryptoError> {
        let output = self.derive()?;
        let mut result = CryptoKdfDeriveKeyResult {
            algorithm: MessageField::some(CryptoAlgorithmIdentifier {
                algorithm: Some(Algorithm::Kdf(match self.prf {
                    Pbkdf2Prf::HmacSha256 => KdfAlgorithm::KDF_ALGORITHM_PBKDF2_HMAC_SHA256.into(),
                    Pbkdf2Prf::HmacSha512 => KdfAlgorithm::KDF_ALGORITHM_PBKDF2_HMAC_SHA512.into(),
                })),
            }),
            derived_key: Default::default(),
        };
        result
            .derived_key
            .try_reserve_exact(output.len())
            .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
        result.derived_key.resize(output.len(), 0)?;
        result.derived_key.copy_from_slice(output.as_bytes());
        Ok(result)
    }
}
