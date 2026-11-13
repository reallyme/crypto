// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::copy_inputs::{copy_bytes, copy_into, read_algorithm, require_known};
use crate::AlgorithmError;
use crypto_core::Algorithm;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoPublicKeyToMultikeyRequest, CryptoPublicKeyToMultikeyResult,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Owns an exact public-key copy without adding a provider or encoding policy.
pub struct PublicKeyToMultikeyInputs {
    algorithm: Algorithm,
    public_key: Zeroizing<Vec<u8>>,
}

impl PublicKeyToMultikeyInputs {
    /// Returns the exact native key identity.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Borrows caller bytes without SEC1 normalization or re-encoding.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Uses the existing encoder, including its native key validation and gates.
    pub fn encode(&self) -> Result<CryptoPublicKeyToMultikeyResult, AlgorithmError> {
        let native = Zeroizing::new(crate::public_key_to_multikey(
            self.algorithm,
            &self.public_key,
        )?);
        let mut output = CryptoPublicKeyToMultikeyResult::default();
        copy_into(&mut output.multikey, native.as_bytes())?;
        Ok(output)
    }
}

impl TryFrom<&CryptoPublicKeyToMultikeyRequest> for PublicKeyToMultikeyInputs {
    type Error = AlgorithmError;

    fn try_from(value: &CryptoPublicKeyToMultikeyRequest) -> Result<Self, Self::Error> {
        require_known(value.__buffa_unknown_fields.is_empty())?;
        Ok(Self {
            algorithm: read_algorithm(value.algorithm.as_option())?,
            public_key: copy_bytes(&value.public_key)?,
        })
    }
}

impl Zeroize for PublicKeyToMultikeyInputs {
    fn zeroize(&mut self) {
        self.public_key.zeroize();
    }
}

// Each byte-bearing field is independently a clearing owner, including on a
// partially constructed request's error/unwind path.
impl ZeroizeOnDrop for PublicKeyToMultikeyInputs {}
