// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Random requests borrow a native entropy provider; providers are not wire data.

use crate::{
    AeadNonce12, Aes256GcmKeyMaterial, Argon2Salt16, Argon2Salt32, MlDsa87Seed, MlKem1024Seed,
    RandomBytes, SecureRandom,
};
use crypto_core::{CryptoError, RngOutputKind};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoRandomBytesRequest, CryptoRandomBytesResult, RngOutputKind as ProtoKind,
};

/// Validated purpose and length without an implicit entropy-provider choice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RandomBytesRequest {
    purpose: RngOutputKind,
    output_length: usize,
}
impl RandomBytesRequest {
    /// Returns the exact native purpose selector.
    pub fn purpose(&self) -> RngOutputKind {
        self.purpose
    }
    /// Returns the requested byte count.
    pub fn output_length(&self) -> usize {
        self.output_length
    }
    /// Fills caller-owned storage through the explicitly borrowed provider.
    /// The caller retains clearing responsibility on success and failure.
    pub fn fill(&self, rng: &mut impl SecureRandom, output: &mut [u8]) -> Result<(), CryptoError> {
        if output.len() != self.output_length {
            return Err(CryptoError::PRIMITIVE_INVALID_LENGTH);
        }
        rng.fill_secure(output, self.purpose)
    }
    /// Uses the existing const-generic generator and its protected result owner.
    pub fn generate<const N: usize>(
        &self,
        rng: &mut impl SecureRandom,
    ) -> Result<RandomBytes<N>, CryptoError> {
        if N != self.output_length {
            return Err(CryptoError::PRIMITIVE_INVALID_LENGTH);
        }
        crate::generate_bytes::<N>(rng, self.purpose)
    }
    /// Exports a matching generated owner without importing caller bytes as entropy.
    pub fn to_result<const N: usize>(
        &self,
        value: &RandomBytes<N>,
    ) -> Result<CryptoRandomBytesResult, CryptoError> {
        if N != self.output_length {
            return Err(CryptoError::PRIMITIVE_INVALID_LENGTH);
        }
        random_result(self.purpose, value.as_bytes())
    }
}
impl TryFrom<&CryptoRandomBytesRequest> for RandomBytesRequest {
    type Error = CryptoError;
    fn try_from(value: &CryptoRandomBytesRequest) -> Result<Self, Self::Error> {
        if !value.__buffa_unknown_fields.is_empty() {
            return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER);
        }
        Ok(Self {
            purpose: RngOutputKind::try_from(value.purpose)?,
            output_length: usize::try_from(value.output_length)
                .map_err(|_| CryptoError::PRIMITIVE_INVALID_LENGTH)?,
        })
    }
}
impl TryFrom<RandomBytesRequest> for CryptoRandomBytesRequest {
    type Error = CryptoError;
    fn try_from(value: RandomBytesRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            purpose: ProtoKind::from(value.purpose).into(),
            output_length: u32::try_from(value.output_length)
                .map_err(|_| CryptoError::PRIMITIVE_INVALID_LENGTH)?,
            __buffa_unknown_fields: Default::default(),
        })
    }
}
fn random_result(
    purpose: RngOutputKind,
    bytes: &[u8],
) -> Result<CryptoRandomBytesResult, CryptoError> {
    u32::try_from(bytes.len()).map_err(|_| CryptoError::PRIMITIVE_INVALID_LENGTH)?;
    let mut output = CryptoRandomBytesResult {
        purpose: ProtoKind::from(purpose).into(),
        value: Vec::new(),
        __buffa_unknown_fields: Default::default(),
    };
    output
        .value
        .try_reserve_exact(bytes.len())
        .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    output.value.extend_from_slice(bytes);
    Ok(output)
}

impl TryFrom<&AeadNonce12> for CryptoRandomBytesResult {
    type Error = CryptoError;
    fn try_from(value: &AeadNonce12) -> Result<Self, Self::Error> {
        random_result(RngOutputKind::AeadNonce12, value.as_bytes())
    }
}

impl TryFrom<&Argon2Salt16> for CryptoRandomBytesResult {
    type Error = CryptoError;
    fn try_from(value: &Argon2Salt16) -> Result<Self, Self::Error> {
        random_result(RngOutputKind::Argon2Salt16, value.as_bytes())
    }
}

impl TryFrom<&Argon2Salt32> for CryptoRandomBytesResult {
    type Error = CryptoError;
    fn try_from(value: &Argon2Salt32) -> Result<Self, Self::Error> {
        random_result(RngOutputKind::Argon2Salt32, value.as_bytes())
    }
}

impl TryFrom<&Aes256GcmKeyMaterial> for CryptoRandomBytesResult {
    type Error = CryptoError;
    fn try_from(value: &Aes256GcmKeyMaterial) -> Result<Self, Self::Error> {
        random_result(RngOutputKind::Aes256GcmKey, value.as_bytes())
    }
}

impl TryFrom<&MlKem1024Seed> for CryptoRandomBytesResult {
    type Error = CryptoError;
    fn try_from(value: &MlKem1024Seed) -> Result<Self, Self::Error> {
        random_result(RngOutputKind::MlKem1024Seed, value.as_bytes())
    }
}

impl TryFrom<&MlDsa87Seed> for CryptoRandomBytesResult {
    type Error = CryptoError;
    fn try_from(value: &MlDsa87Seed) -> Result<Self, Self::Error> {
        random_result(RngOutputKind::MlDsa87Seed, value.as_bytes())
    }
}
