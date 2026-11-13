// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{HpkeComponentSupport, HpkeError};
use buffa::EnumValue;
use crypto_proto::generated::proto::reallyme::crypto::v1::HpkeComponentSupport as ProtoSupport;
impl TryFrom<EnumValue<ProtoSupport>> for HpkeComponentSupport {
    type Error = HpkeError;
    fn try_from(value: EnumValue<ProtoSupport>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(ProtoSupport::HPKE_COMPONENT_SUPPORT_EXECUTABLE) => Ok(Self::Executable),
            Some(ProtoSupport::HPKE_COMPONENT_SUPPORT_REGISTERED_UNAVAILABLE) => {
                Ok(Self::RegisteredUnavailable)
            }
            _ => Err(HpkeError::PRIMITIVE_INVALID_PARAMETER),
        }
    }
}
impl From<HpkeComponentSupport> for ProtoSupport {
    fn from(value: HpkeComponentSupport) -> Self {
        match value {
            HpkeComponentSupport::Executable => Self::HPKE_COMPONENT_SUPPORT_EXECUTABLE,
            HpkeComponentSupport::RegisteredUnavailable => {
                Self::HPKE_COMPONENT_SUPPORT_REGISTERED_UNAVAILABLE
            }
        }
    }
}

use crate::{HpkeAeadId, HpkeKdfId, HpkeKemId};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_hpke_component_capability::Component, CryptoHpkeComponentCapability,
    HpkeAeadId as ProtoAead, HpkeKdfId as ProtoKdf, HpkeKemId as ProtoKem,
};

/// Reports the registered KEM identity and current compiled implementation support.
pub fn kem_capability(value: HpkeKemId) -> Result<CryptoHpkeComponentCapability, HpkeError> {
    let wire = EnumValue::<ProtoKem>::from(i32::from(value as u16));
    if wire.as_known().is_none() {
        return Err(HpkeError::PROVIDER_UNSUPPORTED_ALGORITHM);
    }
    Ok(CryptoHpkeComponentCapability {
        component: Some(Component::Kem(wire)),
        support: ProtoSupport::from(value.support()).into(),
        __buffa_unknown_fields: Default::default(),
    })
}
/// Reports the registered KDF identity without enabling its backend feature.
pub fn kdf_capability(value: HpkeKdfId) -> Result<CryptoHpkeComponentCapability, HpkeError> {
    let wire = EnumValue::<ProtoKdf>::from(i32::from(value as u16));
    if wire.as_known().is_none() {
        return Err(HpkeError::PROVIDER_UNSUPPORTED_ALGORITHM);
    }
    Ok(CryptoHpkeComponentCapability {
        component: Some(Component::Kdf(wire)),
        support: ProtoSupport::from(value.support()).into(),
        __buffa_unknown_fields: Default::default(),
    })
}
/// Reports the registered AEAD identity without selecting a complete suite.
pub fn aead_capability(value: HpkeAeadId) -> Result<CryptoHpkeComponentCapability, HpkeError> {
    let wire = EnumValue::<ProtoAead>::from(i32::from(value as u16));
    if wire.as_known().is_none() {
        return Err(HpkeError::PROVIDER_UNSUPPORTED_ALGORITHM);
    }
    Ok(CryptoHpkeComponentCapability {
        component: Some(Component::Aead(wire)),
        support: ProtoSupport::from(value.support()).into(),
        __buffa_unknown_fields: Default::default(),
    })
}
