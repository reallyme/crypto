// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Registered suite identity without selecting an executable backend.

use crypto_proto::generated::proto::reallyme::crypto::v1::HpkeSuiteIdentifier;

use crate::{HpkeAeadId, HpkeError, HpkeKdfId, HpkeKemId, HpkeSuite};

impl TryFrom<&HpkeSuiteIdentifier> for HpkeSuite {
    type Error = HpkeError;

    fn try_from(value: &HpkeSuiteIdentifier) -> Result<Self, Self::Error> {
        if !value.__buffa_unknown_fields.is_empty()
            || value.kem.as_known().is_none()
            || value.kdf.as_known().is_none()
            || value.aead.as_known().is_none()
        {
            return Err(HpkeError::PROVIDER_UNSUPPORTED_ALGORITHM);
        }
        let kem = HpkeKemId::try_from(component_number(value.kem.to_i32())?)?;
        let kdf = HpkeKdfId::try_from(component_number(value.kdf.to_i32())?)?;
        let aead = HpkeAeadId::try_from(component_number(value.aead.to_i32())?)?;
        // Schema registration establishes identity. Execution retains the
        // existing complete-suite and selected-provider validation.
        Ok(Self::new(kem, kdf, aead))
    }
}

impl TryFrom<HpkeSuite> for HpkeSuiteIdentifier {
    type Error = HpkeError;

    fn try_from(value: HpkeSuite) -> Result<Self, Self::Error> {
        let wire = Self {
            kem: i32::from(value.kem_id()).into(),
            kdf: i32::from(value.kdf_id()).into(),
            aead: i32::from(value.aead_id()).into(),
            __buffa_unknown_fields: Default::default(),
        };
        if wire.kem.as_known().is_none()
            || wire.kdf.as_known().is_none()
            || wire.aead.as_known().is_none()
        {
            return Err(HpkeError::PROVIDER_UNSUPPORTED_ALGORITHM);
        }
        Ok(wire)
    }
}

fn component_number(number: i32) -> Result<u16, HpkeError> {
    if number == 0 {
        return Err(HpkeError::PROVIDER_UNSUPPORTED_ALGORITHM);
    }
    u16::try_from(number).map_err(|_| HpkeError::PROVIDER_UNSUPPORTED_ALGORITHM)
}
