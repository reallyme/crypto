// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Registry identity conversion without selecting a cryptographic backend.

use buffa::{EnumValue, Enumeration};

use crate::generated::proto::reallyme::crypto::v1::{
    HpkeAeadId, HpkeKdfId, HpkeKemId, HpkeSuiteIdentifier,
};

use super::UnsupportedProtoAlgorithm;

impl TryFrom<&HpkeSuiteIdentifier> for crypto_hpke::HpkeSuite {
    type Error = UnsupportedProtoAlgorithm;

    fn try_from(value: &HpkeSuiteIdentifier) -> Result<Self, Self::Error> {
        if !value.__buffa_unknown_fields.is_empty() {
            return Err(UnsupportedProtoAlgorithm);
        }
        let kem = crypto_hpke::HpkeKemId::try_from(component_number(value.kem)?)
            .map_err(|_| UnsupportedProtoAlgorithm)?;
        let kdf = crypto_hpke::HpkeKdfId::try_from(component_number(value.kdf)?)
            .map_err(|_| UnsupportedProtoAlgorithm)?;
        let aead = crypto_hpke::HpkeAeadId::try_from(component_number(value.aead)?)
            .map_err(|_| UnsupportedProtoAlgorithm)?;
        // Registration is distinct from executable support. The operation's
        // existing provider policy still validates the complete combination.
        Ok(Self::new(kem, kdf, aead))
    }
}

impl TryFrom<crypto_hpke::HpkeSuite> for HpkeSuiteIdentifier {
    type Error = UnsupportedProtoAlgorithm;

    fn try_from(value: crypto_hpke::HpkeSuite) -> Result<Self, Self::Error> {
        let kem =
            HpkeKemId::from_i32(i32::from(value.kem_id())).ok_or(UnsupportedProtoAlgorithm)?;
        let kdf =
            HpkeKdfId::from_i32(i32::from(value.kdf_id())).ok_or(UnsupportedProtoAlgorithm)?;
        let aead =
            HpkeAeadId::from_i32(i32::from(value.aead_id())).ok_or(UnsupportedProtoAlgorithm)?;
        Ok(Self {
            kem: kem.into(),
            kdf: kdf.into(),
            aead: aead.into(),
            __buffa_unknown_fields: Default::default(),
        })
    }
}

fn component_number<E: Enumeration>(value: EnumValue<E>) -> Result<u16, UnsupportedProtoAlgorithm> {
    let number = value.as_known().ok_or(UnsupportedProtoAlgorithm)?.to_i32();
    if number == 0 {
        return Err(UnsupportedProtoAlgorithm);
    }
    u16::try_from(number).map_err(|_| UnsupportedProtoAlgorithm)
}
