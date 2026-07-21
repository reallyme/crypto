// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "backend-native")]
use crate::constants::{
    HPKE_KEY_SCHEDULE_LABEL_OVERHEAD, HPKE_LABELED_CONTEXT_LIMIT, HPKE_MIN_PSK_LEN,
};
use crate::error::HpkeError;
#[cfg(feature = "backend-native")]
use crate::identifiers::HpkeKdfId;
use crate::identifiers::{HpkeAeadId, HpkeComponentSupport, HpkeKemId, HpkeSuite};
use crate::{
    HPKE_SECP256K1_PRIVATE_KEY_LEN, HPKE_SECP256K1_PUBLIC_KEY_LEN, HPKE_X448_PRIVATE_KEY_LEN,
    HPKE_X448_PUBLIC_KEY_LEN,
};

#[derive(Clone, Copy)]
pub(crate) struct KemParameters {
    pub(crate) public_key_len: usize,
    pub(crate) private_key_len: usize,
    pub(crate) encapsulated_key_len: usize,
    pub(crate) encapsulation_randomness_len: usize,
}

pub(crate) fn require_executable_suite(suite: HpkeSuite) -> Result<(), HpkeError> {
    if suite.kem.support() != HpkeComponentSupport::Executable {
        return Err(HpkeError::UnsupportedKem);
    }

    if suite.kdf.support() != HpkeComponentSupport::Executable {
        return Err(HpkeError::UnsupportedKdf);
    }

    if suite.aead.support() != HpkeComponentSupport::Executable {
        return Err(HpkeError::UnsupportedAead);
    }

    Ok(())
}

#[cfg(feature = "backend-native")]
pub(crate) fn require_sealing_suite(suite: HpkeSuite) -> Result<(), HpkeError> {
    require_executable_suite(suite)?;
    if suite.aead == HpkeAeadId::ExportOnly {
        return Err(HpkeError::UnsupportedSuite);
    }
    Ok(())
}

#[cfg(feature = "backend-native")]
pub(crate) fn require_export_suite(suite: HpkeSuite) -> Result<(), HpkeError> {
    require_executable_suite(suite)?;
    // hpke 0.14's one-stage key schedule uses a fixed internal buffer that is
    // too small for the export-only AEAD's synthetic nonce. Reject this
    // provider combination before setup so untrusted input cannot reach its
    // documented panic path.
    if suite.kdf == HpkeKdfId::Shake256 && suite.aead == HpkeAeadId::ExportOnly {
        return Err(HpkeError::UnsupportedSuite);
    }
    Ok(())
}

pub(crate) fn kem_parameters(kem: HpkeKemId) -> Result<KemParameters, HpkeError> {
    match kem {
        HpkeKemId::DhKemP256HkdfSha256 => Ok(KemParameters {
            public_key_len: 65,
            private_key_len: 32,
            encapsulated_key_len: 65,
            encapsulation_randomness_len: 32,
        }),
        HpkeKemId::DhKemP384HkdfSha384 => Ok(KemParameters {
            public_key_len: 97,
            private_key_len: 48,
            encapsulated_key_len: 97,
            encapsulation_randomness_len: 48,
        }),
        HpkeKemId::DhKemP521HkdfSha512 => Ok(KemParameters {
            public_key_len: 133,
            private_key_len: 66,
            encapsulated_key_len: 133,
            encapsulation_randomness_len: 66,
        }),
        HpkeKemId::DhKemSecp256k1HkdfSha256 => Ok(KemParameters {
            public_key_len: HPKE_SECP256K1_PUBLIC_KEY_LEN,
            private_key_len: HPKE_SECP256K1_PRIVATE_KEY_LEN,
            encapsulated_key_len: HPKE_SECP256K1_PUBLIC_KEY_LEN,
            encapsulation_randomness_len: HPKE_SECP256K1_PRIVATE_KEY_LEN,
        }),
        HpkeKemId::DhKemX25519HkdfSha256 => Ok(KemParameters {
            public_key_len: 32,
            private_key_len: 32,
            encapsulated_key_len: 32,
            encapsulation_randomness_len: 32,
        }),
        HpkeKemId::DhKemX448HkdfSha512 => Ok(KemParameters {
            public_key_len: HPKE_X448_PUBLIC_KEY_LEN,
            private_key_len: HPKE_X448_PRIVATE_KEY_LEN,
            encapsulated_key_len: HPKE_X448_PUBLIC_KEY_LEN,
            encapsulation_randomness_len: HPKE_X448_PRIVATE_KEY_LEN,
        }),
        HpkeKemId::MlKem512 => Ok(KemParameters {
            public_key_len: 800,
            private_key_len: 64,
            encapsulated_key_len: 768,
            encapsulation_randomness_len: 32,
        }),
        HpkeKemId::MlKem768 => Ok(KemParameters {
            public_key_len: 1_184,
            private_key_len: 64,
            encapsulated_key_len: 1_088,
            encapsulation_randomness_len: 32,
        }),
        HpkeKemId::MlKem1024 => Ok(KemParameters {
            public_key_len: 1_568,
            private_key_len: 64,
            encapsulated_key_len: 1_568,
            encapsulation_randomness_len: 32,
        }),
        HpkeKemId::MlKem768P256 => Ok(KemParameters {
            public_key_len: 1_249,
            private_key_len: 32,
            encapsulated_key_len: 1_153,
            encapsulation_randomness_len: 64,
        }),
        HpkeKemId::MlKem1024P384 => Ok(KemParameters {
            public_key_len: 1_665,
            private_key_len: 32,
            encapsulated_key_len: 1_665,
            encapsulation_randomness_len: 80,
        }),
        HpkeKemId::XWing => Ok(KemParameters {
            public_key_len: 1_216,
            private_key_len: 32,
            encapsulated_key_len: 1_120,
            encapsulation_randomness_len: 64,
        }),
        HpkeKemId::DhKemCp256HkdfSha256
        | HpkeKemId::DhKemCp384HkdfSha384
        | HpkeKemId::DhKemCp521HkdfSha512
        | HpkeKemId::DhKemX25519ElligatorHkdfSha256
        | HpkeKemId::X25519Kyber768Draft00 => Err(HpkeError::UnsupportedKem),
    }
}

#[cfg(feature = "backend-native")]
pub(crate) fn validate_public_key(suite: HpkeSuite, public_key: &[u8]) -> Result<(), HpkeError> {
    require_executable_suite(suite)?;
    if public_key.len() != kem_parameters(suite.kem)?.public_key_len {
        return Err(HpkeError::InvalidPublicKey);
    }
    Ok(())
}

#[cfg(feature = "backend-native")]
pub(crate) fn validate_private_key(suite: HpkeSuite, private_key: &[u8]) -> Result<(), HpkeError> {
    require_executable_suite(suite)?;
    if private_key.len() != kem_parameters(suite.kem)?.private_key_len {
        return Err(HpkeError::InvalidPrivateKey);
    }
    Ok(())
}

#[cfg(feature = "backend-native")]
pub(crate) fn validate_encapsulated_key(
    suite: HpkeSuite,
    encapsulated_key: &[u8],
) -> Result<(), HpkeError> {
    require_executable_suite(suite)?;
    if encapsulated_key.len() != kem_parameters(suite.kem)?.encapsulated_key_len {
        return Err(HpkeError::InvalidEncapsulatedKey);
    }
    Ok(())
}

#[cfg(feature = "backend-native")]
pub(crate) fn validate_ciphertext(suite: HpkeSuite, ciphertext: &[u8]) -> Result<(), HpkeError> {
    require_sealing_suite(suite)?;
    if ciphertext.len() < suite.tag_len() {
        return Err(HpkeError::InvalidCiphertext);
    }
    Ok(())
}

#[cfg(feature = "backend-native")]
pub(crate) fn validate_key_schedule_inputs(info: &[u8], psk_id: &[u8]) -> Result<(), HpkeError> {
    let encoded_len = info
        .len()
        .checked_add(psk_id.len())
        .and_then(|length| length.checked_add(HPKE_KEY_SCHEDULE_LABEL_OVERHEAD))
        .ok_or(HpkeError::LengthOverflow)?;
    if encoded_len >= HPKE_LABELED_CONTEXT_LIMIT {
        return Err(HpkeError::InvalidInfoLength);
    }
    Ok(())
}

#[cfg(feature = "backend-native")]
pub(crate) fn validate_psk(psk: &[u8], psk_id: &[u8]) -> Result<(), HpkeError> {
    if psk.len() < HPKE_MIN_PSK_LEN {
        return Err(HpkeError::InvalidPsk);
    }
    if psk_id.is_empty() {
        return Err(HpkeError::InvalidPskIdentifier);
    }
    validate_key_schedule_inputs(&[], psk_id)
}

#[cfg(feature = "backend-native")]
pub(crate) fn validate_export_length(
    suite: HpkeSuite,
    output_length: usize,
) -> Result<(), HpkeError> {
    require_executable_suite(suite)?;
    let maximum = match suite.kdf {
        HpkeKdfId::HkdfSha256 => 32_usize.checked_mul(255).ok_or(HpkeError::LengthOverflow)?,
        HpkeKdfId::HkdfSha384 => 48_usize.checked_mul(255).ok_or(HpkeError::LengthOverflow)?,
        HpkeKdfId::HkdfSha512 => 64_usize.checked_mul(255).ok_or(HpkeError::LengthOverflow)?,
        HpkeKdfId::Shake256 => HPKE_LABELED_CONTEXT_LIMIT
            .checked_sub(1)
            .ok_or(HpkeError::LengthOverflow)?,
        HpkeKdfId::Shake128 | HpkeKdfId::TurboShake128 | HpkeKdfId::TurboShake256 => {
            return Err(HpkeError::UnsupportedKdf);
        }
    };
    if output_length == 0 || output_length > maximum {
        return Err(HpkeError::InvalidExporterLength);
    }
    Ok(())
}

impl HpkeSuite {
    /// Encoded public-key length for this suite's KEM.
    pub fn public_key_len(self) -> Result<usize, HpkeError> {
        require_executable_suite(self)?;
        Ok(kem_parameters(self.kem)?.public_key_len)
    }

    /// Encoded private-key and deterministic IKM length for this suite's KEM.
    pub fn private_key_len(self) -> Result<usize, HpkeError> {
        require_executable_suite(self)?;
        Ok(kem_parameters(self.kem)?.private_key_len)
    }

    /// Encapsulated-key length for this suite's KEM.
    pub fn encapsulated_key_len(self) -> Result<usize, HpkeError> {
        require_executable_suite(self)?;
        Ok(kem_parameters(self.kem)?.encapsulated_key_len)
    }

    /// Randomness consumed by one sender encapsulation.
    pub fn encapsulation_randomness_len(self) -> Result<usize, HpkeError> {
        require_executable_suite(self)?;
        Ok(kem_parameters(self.kem)?.encapsulation_randomness_len)
    }
}
