// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Schema policy descriptors preserve native policy and never authorize execution.

use crate::CryptoError;
use crate::RngOutputKind;
use buffa::EnumValue;
use crypto_proto::generated::proto::reallyme::crypto::v1::RngOutputKind as ProtoRngOutputKind;

impl TryFrom<EnumValue<ProtoRngOutputKind>> for RngOutputKind {
    type Error = CryptoError;

    fn try_from(value: EnumValue<ProtoRngOutputKind>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(ProtoRngOutputKind::RNG_OUTPUT_KIND_GENERIC) => Ok(Self::Generic),
            Some(ProtoRngOutputKind::RNG_OUTPUT_KIND_AEAD_NONCE_12) => Ok(Self::AeadNonce12),
            Some(ProtoRngOutputKind::RNG_OUTPUT_KIND_ARGON2_SALT_16) => Ok(Self::Argon2Salt16),
            Some(ProtoRngOutputKind::RNG_OUTPUT_KIND_ARGON2_SALT_32) => Ok(Self::Argon2Salt32),
            Some(ProtoRngOutputKind::RNG_OUTPUT_KIND_AES_256_GCM_KEY) => Ok(Self::Aes256GcmKey),
            Some(ProtoRngOutputKind::RNG_OUTPUT_KIND_ML_KEM_1024_SEED) => Ok(Self::MlKem1024Seed),
            Some(ProtoRngOutputKind::RNG_OUTPUT_KIND_ML_DSA_87_SEED) => Ok(Self::MlDsa87Seed),
            Some(ProtoRngOutputKind::RNG_OUTPUT_KIND_ED25519_SEED) => Ok(Self::Ed25519Seed),
            Some(ProtoRngOutputKind::RNG_OUTPUT_KIND_SLH_DSA_SHA2_128S_SEED) => {
                Ok(Self::SlhDsaSha2_128sSeed)
            }
            // Zero and unknown future values cannot silently select a policy.
            _ => Err(CryptoError::PRIMITIVE_INVALID_PARAMETER),
        }
    }
}

impl From<RngOutputKind> for ProtoRngOutputKind {
    fn from(value: RngOutputKind) -> Self {
        // Keep this exhaustive so new native variants require a schema decision.
        match value {
            RngOutputKind::Generic => Self::RNG_OUTPUT_KIND_GENERIC,
            RngOutputKind::AeadNonce12 => Self::RNG_OUTPUT_KIND_AEAD_NONCE_12,
            RngOutputKind::Argon2Salt16 => Self::RNG_OUTPUT_KIND_ARGON2_SALT_16,
            RngOutputKind::Argon2Salt32 => Self::RNG_OUTPUT_KIND_ARGON2_SALT_32,
            RngOutputKind::Aes256GcmKey => Self::RNG_OUTPUT_KIND_AES_256_GCM_KEY,
            RngOutputKind::MlKem1024Seed => Self::RNG_OUTPUT_KIND_ML_KEM_1024_SEED,
            RngOutputKind::MlDsa87Seed => Self::RNG_OUTPUT_KIND_ML_DSA_87_SEED,
            RngOutputKind::Ed25519Seed => Self::RNG_OUTPUT_KIND_ED25519_SEED,
            RngOutputKind::SlhDsaSha2_128sSeed => Self::RNG_OUTPUT_KIND_SLH_DSA_SHA2_128S_SEED,
        }
    }
}
