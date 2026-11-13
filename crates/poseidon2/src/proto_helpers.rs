// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Byte-exact request ownership for the existing fixed BN254 Poseidon2 profile.

use crate::{Poseidon2Digest, MAX_INPUT_BYTES};
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoPoseidon2HashRequest, CryptoPoseidon2HashResult,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Owns a validated byte preimage without changing its circuit encoding.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Poseidon2Inputs {
    input: Zeroizing<Vec<u8>>,
}
impl Poseidon2Inputs {
    /// Borrows the exact preimage bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.input
    }
    /// Returns the existing protected canonical digest owner.
    pub fn hash(&self) -> Result<Poseidon2Digest, CryptoError> {
        crate::hash_bytes(&self.input)
    }
}
impl TryFrom<&CryptoPoseidon2HashRequest> for Poseidon2Inputs {
    type Error = CryptoError;
    fn try_from(value: &CryptoPoseidon2HashRequest) -> Result<Self, Self::Error> {
        if !value.__buffa_unknown_fields.is_empty() {
            return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER);
        }
        if value.input.len() > MAX_INPUT_BYTES {
            return Err(CryptoError::PRIMITIVE_RESOURCE_LIMIT_EXCEEDED);
        }
        let mut input = Zeroizing::new(Vec::new());
        input
            .try_reserve_exact(value.input.len())
            .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
        input.extend_from_slice(&value.input);
        Ok(Self { input })
    }
}
impl TryFrom<&Poseidon2Digest> for CryptoPoseidon2HashResult {
    type Error = CryptoError;
    fn try_from(value: &Poseidon2Digest) -> Result<Self, Self::Error> {
        let mut output = Self::default();
        output
            .digest
            .try_reserve_exact(value.as_bytes().len())
            .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
        output.digest.extend_from_slice(value.as_bytes());
        Ok(output)
    }
}
