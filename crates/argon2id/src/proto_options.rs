// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fixed-profile adapters; reported caps and costs cannot override derivation.

use crate::{
    Argon2Caps, Argon2ParamsProfile, Argon2PlatformClass, Argon2Profile, Argon2Salt, Argon2Secret,
    DeriveKeyRequest,
};
use buffa::{EnumValue, MessageField};
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    Argon2Caps as ProtoArgon2Caps, Argon2ParamsProfile as ProtoArgon2ParamsProfile,
    Argon2PlatformClass as ProtoPlatform, CryptoArgon2FixedDeriveRequest,
    CryptoArgon2idProfileIdentifier,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

impl TryFrom<EnumValue<ProtoPlatform>> for Argon2PlatformClass {
    type Error = CryptoError;
    fn try_from(value: EnumValue<ProtoPlatform>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(ProtoPlatform::ARGON2_PLATFORM_CLASS_MOBILE_MODERN) => Ok(Self::MobileModern),
            Some(ProtoPlatform::ARGON2_PLATFORM_CLASS_DESKTOP_MODERN) => Ok(Self::DesktopModern),
            _ => Err(CryptoError::PRIMITIVE_INVALID_PARAMETER),
        }
    }
}
impl From<Argon2PlatformClass> for ProtoPlatform {
    fn from(value: Argon2PlatformClass) -> Self {
        match value {
            Argon2PlatformClass::MobileModern => Self::ARGON2_PLATFORM_CLASS_MOBILE_MODERN,
            Argon2PlatformClass::DesktopModern => Self::ARGON2_PLATFORM_CLASS_DESKTOP_MODERN,
        }
    }
}
impl From<Argon2Caps> for ProtoArgon2Caps {
    fn from(value: Argon2Caps) -> Self {
        Self {
            mem_cap_kib: value.mem_cap_kib,
            time_cost_cap: value.time_cost_cap,
            lanes_cap: value.lanes_cap,
            __buffa_unknown_fields: Default::default(),
        }
    }
}
impl From<Argon2ParamsProfile> for ProtoArgon2ParamsProfile {
    fn from(value: Argon2ParamsProfile) -> Self {
        Self {
            mem_kib: value.mem_kib,
            time_cost: value.time_cost,
            lanes: value.lanes,
            __buffa_unknown_fields: Default::default(),
        }
    }
}

/// Protected inputs backing the native borrowed fixed-profile request.
pub struct Argon2DeriveInputs {
    profile: Argon2Profile,
    secret: Argon2Secret,
    salt: Argon2Salt,
}
impl Argon2DeriveInputs {
    /// Borrows the existing native request without changing its lifetime model.
    pub fn as_request(&self) -> DeriveKeyRequest<'_> {
        DeriveKeyRequest {
            profile: self.profile,
            secret: &self.secret,
            salt: &self.salt,
        }
    }
}
impl Zeroize for Argon2DeriveInputs {
    fn zeroize(&mut self) {
        self.secret.zeroize();
        self.salt.zeroize();
    }
}
// Both secret fields already clear themselves on every drop path.
impl ZeroizeOnDrop for Argon2DeriveInputs {}

impl TryFrom<&CryptoArgon2FixedDeriveRequest> for Argon2DeriveInputs {
    type Error = CryptoError;
    fn try_from(value: &CryptoArgon2FixedDeriveRequest) -> Result<Self, Self::Error> {
        if !value.__buffa_unknown_fields.is_empty() {
            return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER);
        }
        let profile = Argon2Profile::try_from(
            value
                .profile
                .as_option()
                .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?,
        )?;
        let secret = Argon2Secret::from_slice(&value.secret, profile)?;
        let salt = Argon2Salt::from_slice(&value.salt, profile)?;
        Ok(Self {
            profile,
            secret,
            salt,
        })
    }
}
impl From<&DeriveKeyRequest<'_>> for CryptoArgon2FixedDeriveRequest {
    // Establish the clearing owner before copying either secret input.
    #[allow(clippy::field_reassign_with_default)]
    fn from(value: &DeriveKeyRequest<'_>) -> Self {
        let mut output = Self::default();
        output.profile = MessageField::some(CryptoArgon2idProfileIdentifier::from(value.profile));
        output.secret = value.secret.as_bytes().to_vec();
        output.salt = value.salt.as_bytes().to_vec();
        output
    }
}
