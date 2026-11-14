// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::copy_inputs::{copy_text, read_algorithm};
use crate::AlgorithmError;
use crypto_core::Algorithm;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoVerificationMethodMultikeyRequest, CryptoVerificationMethodMultikeyResult,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Owns exact UTF-8 binding metadata for native structural multikey validation.
/// This operation does not verify a signature, establish trust or authorize use.
pub struct VerificationMethodMultikeyInputs {
    algorithm: Algorithm,
    binding_type: Zeroizing<String>,
    public_key_multibase: Zeroizing<String>,
}

impl VerificationMethodMultikeyInputs {
    /// Returns the exact native key identity.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Borrows the unchanged binding label.
    pub fn binding_type(&self) -> &str {
        &self.binding_type
    }

    /// Borrows the unchanged multibase text.
    pub fn public_key_multibase(&self) -> &str {
        &self.public_key_multibase
    }

    /// Delegates structural validation and returns an empty success record.
    pub fn validate(&self) -> Result<CryptoVerificationMethodMultikeyResult, AlgorithmError> {
        crate::validate_verification_method_multikey(
            self.algorithm,
            &self.binding_type,
            &self.public_key_multibase,
        )?;
        Ok(CryptoVerificationMethodMultikeyResult::default())
    }
}

impl TryFrom<&CryptoVerificationMethodMultikeyRequest> for VerificationMethodMultikeyInputs {
    type Error = AlgorithmError;

    fn try_from(value: &CryptoVerificationMethodMultikeyRequest) -> Result<Self, Self::Error> {
        let algorithm = read_algorithm(value.algorithm.as_option())?;
        // The native helper rejects disabled algorithms before parsing. Reuse
        // that same policy before even decoding untrusted UTF-8 metadata.
        crate::validation::expected_public_key_len(algorithm)?;
        Ok(Self {
            algorithm,
            binding_type: copy_text(&value.binding_type)?,
            public_key_multibase: copy_text(&value.public_key_multibase)?,
        })
    }
}

impl Zeroize for VerificationMethodMultikeyInputs {
    fn zeroize(&mut self) {
        self.binding_type.zeroize();
        self.public_key_multibase.zeroize();
    }
}

// The independent clearing string owners also cover partial construction.
impl ZeroizeOnDrop for VerificationMethodMultikeyInputs {}
