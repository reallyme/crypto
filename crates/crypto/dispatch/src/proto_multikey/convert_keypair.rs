// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::copy_inputs::{copy_into, read_algorithm, write_algorithm};
use crate::{AlgorithmError, GeneratedKeypair};
use buffa::MessageField;
use crypto_core::Algorithm;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoGenerateMultikeyKeypairRequest, CryptoGenerateMultikeyKeypairResult,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Validated identity for the existing software-keypair generation operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenerateMultikeyKeypairInputs {
    algorithm: Algorithm,
}

impl GenerateMultikeyKeypairInputs {
    /// Returns the exact native algorithm identity, without selecting a provider.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Generates through the existing native dispatch policy.
    pub fn generate(&self) -> Result<ProtectedGeneratedMultikeyKeypair, AlgorithmError> {
        let native = crate::generate_multikey_keypair(self.algorithm)?;
        Ok(ProtectedGeneratedMultikeyKeypair {
            algorithm: self.algorithm,
            native,
            cleared: false,
        })
    }
}

impl TryFrom<&CryptoGenerateMultikeyKeypairRequest> for GenerateMultikeyKeypairInputs {
    type Error = AlgorithmError;

    fn try_from(value: &CryptoGenerateMultikeyKeypairRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            algorithm: read_algorithm(value.algorithm.as_option())?,
        })
    }
}

/// Owns the existing software keypair and clears its public correlators as well.
///
/// The legacy native record remains unchanged: callers can still move its public
/// fields. This new boundary owner provides borrowed access and never derives
/// `Debug`, `Clone` or serialization traits for its secret-bearing contents.
pub struct ProtectedGeneratedMultikeyKeypair {
    algorithm: Algorithm,
    native: GeneratedKeypair,
    cleared: bool,
}

impl ProtectedGeneratedMultikeyKeypair {
    /// Borrows the unchanged caller-owned software-keypair model.
    pub fn as_native(&self) -> &GeneratedKeypair {
        &self.native
    }

    /// Copies the existing software result through a final clearing DTO owner.
    #[allow(clippy::field_reassign_with_default)]
    pub fn to_result(&self) -> Result<CryptoGenerateMultikeyKeypairResult, AlgorithmError> {
        if self.cleared {
            return Err(AlgorithmError::BACKEND_INVALID_STATE);
        }
        let mut output = CryptoGenerateMultikeyKeypairResult::default();
        output.algorithm = MessageField::some(write_algorithm(self.algorithm));
        copy_into(&mut output.public_key, &self.native.public_key)?;
        copy_into(&mut output.secret_key, &self.native.secret_key)?;
        copy_into(
            &mut output.public_key_multikey,
            self.native.public_key_multikey.as_bytes(),
        )?;
        Ok(output)
    }
}

impl Zeroize for ProtectedGeneratedMultikeyKeypair {
    fn zeroize(&mut self) {
        self.native.public_key.zeroize();
        self.native.secret_key.zeroize();
        self.native.public_key_multikey.zeroize();
        self.cleared = true;
    }
}

impl Drop for ProtectedGeneratedMultikeyKeypair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ProtectedGeneratedMultikeyKeypair {}
