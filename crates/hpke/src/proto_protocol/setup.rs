// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Setup returns the existing opaque native owners, never serialized state.

use super::requests::{copy_bytes, copy_into, require_known};
use crate::validation::{
    require_sealing_suite, validate_encapsulated_key, validate_key_schedule_inputs,
    validate_private_key, validate_psk, validate_public_key,
};
use crate::{
    HpkeError, HpkePskIdRef, HpkePskReceiverSetupRequest, HpkePskRef, HpkePskSenderSetupOutput,
    HpkePskSenderSetupRequest, HpkeReceiverContext, HpkeSuite,
};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoHpkePskReceiverSetupRequest, CryptoHpkePskReceiverSetupResult,
    CryptoHpkePskSenderSetupRequest, CryptoHpkePskSenderSetupResult,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Owns the exact sender-setup request bytes under clearing guards.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HpkePskSenderSetupInputs {
    #[zeroize(skip)]
    suite: HpkeSuite,
    public_key: Zeroizing<Vec<u8>>,
    info: Zeroizing<Vec<u8>>,
    psk: Zeroizing<Vec<u8>>,
    psk_id: Zeroizing<Vec<u8>>,
}
impl HpkePskSenderSetupInputs {
    /// Borrows validated PSK views; erased or invalidated owners fail closed.
    pub fn as_request(&self) -> Result<HpkePskSenderSetupRequest<'_>, HpkeError> {
        Ok(HpkePskSenderSetupRequest {
            suite: self.suite,
            recipient_public_key: &self.public_key,
            info: &self.info,
            psk: HpkePskRef::new(&self.psk)?,
            psk_id: HpkePskIdRef::new(&self.psk_id)?,
        })
    }
    /// Returns the existing native context owner and its public encapsulated key.
    pub fn setup(&self) -> Result<HpkePskSenderSetupOutput, HpkeError> {
        crate::setup_sender_psk(&self.as_request()?)
    }
}
impl TryFrom<&CryptoHpkePskSenderSetupRequest> for HpkePskSenderSetupInputs {
    type Error = HpkeError;
    fn try_from(value: &CryptoHpkePskSenderSetupRequest) -> Result<Self, Self::Error> {
        require_known(value.__buffa_unknown_fields.is_empty())?;
        let suite = HpkeSuite::try_from(
            value
                .suite
                .as_option()
                .ok_or(HpkeError::PRIMITIVE_INVALID_PARAMETER)?,
        )?;
        require_sealing_suite(suite)?;
        validate_public_key(suite, &value.recipient_public_key)?;
        validate_psk(suite.kdf, &value.psk, &value.psk_id)?;
        validate_key_schedule_inputs(suite.kdf, &value.info, &value.psk_id)?;
        Ok(Self {
            suite,
            public_key: copy_bytes(&value.recipient_public_key)?,
            info: copy_bytes(&value.info)?,
            psk: copy_bytes(&value.psk)?,
            psk_id: copy_bytes(&value.psk_id)?,
        })
    }
}
impl From<&HpkePskSenderSetupOutput> for CryptoHpkePskSenderSetupResult {
    fn from(value: &HpkePskSenderSetupOutput) -> Self {
        Self {
            encapsulated_key: value.encapsulated_key.to_vec(),
            __buffa_unknown_fields: Default::default(),
        }
    }
}

/// Owns exact receiver-setup inputs; private bytes are never exposed by accessors.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HpkePskReceiverSetupInputs {
    #[zeroize(skip)]
    suite: HpkeSuite,
    encapsulated_key: Zeroizing<Vec<u8>>,
    private_key: Zeroizing<Vec<u8>>,
    info: Zeroizing<Vec<u8>>,
    psk: Zeroizing<Vec<u8>>,
    psk_id: Zeroizing<Vec<u8>>,
}
impl HpkePskReceiverSetupInputs {
    /// Borrows the unchanged native receiver request from protected storage.
    pub fn as_request(&self) -> Result<HpkePskReceiverSetupRequest<'_>, HpkeError> {
        Ok(HpkePskReceiverSetupRequest {
            suite: self.suite,
            encapsulated_key: &self.encapsulated_key,
            recipient_private_key: &self.private_key,
            info: &self.info,
            psk: HpkePskRef::new(&self.psk)?,
            psk_id: HpkePskIdRef::new(&self.psk_id)?,
        })
    }
    /// Returns the existing Send, non-Sync, non-cloneable native receiver owner.
    pub fn setup(&self) -> Result<HpkeReceiverContext, HpkeError> {
        crate::setup_receiver_psk(&self.as_request()?)
    }
}
impl TryFrom<&CryptoHpkePskReceiverSetupRequest> for HpkePskReceiverSetupInputs {
    type Error = HpkeError;
    fn try_from(value: &CryptoHpkePskReceiverSetupRequest) -> Result<Self, Self::Error> {
        require_known(value.__buffa_unknown_fields.is_empty())?;
        let suite = HpkeSuite::try_from(
            value
                .suite
                .as_option()
                .ok_or(HpkeError::PRIMITIVE_INVALID_PARAMETER)?,
        )?;
        require_sealing_suite(suite)?;
        validate_encapsulated_key(suite, &value.encapsulated_key)?;
        validate_private_key(suite, &value.recipient_private_key)?;
        validate_psk(suite.kdf, &value.psk, &value.psk_id)?;
        validate_key_schedule_inputs(suite.kdf, &value.info, &value.psk_id)?;
        Ok(Self {
            suite,
            encapsulated_key: copy_bytes(&value.encapsulated_key)?,
            private_key: copy_bytes(&value.recipient_private_key)?,
            info: copy_bytes(&value.info)?,
            psk: copy_bytes(&value.psk)?,
            psk_id: copy_bytes(&value.psk_id)?,
        })
    }
}

/// Produces public acknowledgement without exporting any live receiver state.
pub fn receiver_setup_public_result(
    _context: &HpkeReceiverContext,
) -> CryptoHpkePskReceiverSetupResult {
    CryptoHpkePskReceiverSetupResult::default()
}

impl TryFrom<&HpkePskSenderSetupRequest<'_>> for CryptoHpkePskSenderSetupRequest {
    type Error = HpkeError;
    // Establish the final clearing owner before copying any setup material.
    #[allow(clippy::field_reassign_with_default)]
    fn try_from(value: &HpkePskSenderSetupRequest<'_>) -> Result<Self, Self::Error> {
        for bytes in [
            value.recipient_public_key,
            value.info,
            value.psk.as_slice(),
            value.psk_id.as_slice(),
        ] {
            super::requests::check_length(bytes)?;
        }
        let mut output = Self::default();
        output.suite = buffa::MessageField::some(
            crypto_proto::generated::proto::reallyme::crypto::v1::HpkeSuiteIdentifier::try_from(
                value.suite,
            )?,
        );
        copy_into(&mut output.recipient_public_key, value.recipient_public_key)?;
        copy_into(&mut output.info, value.info)?;
        copy_into(&mut output.psk, value.psk.as_slice())?;
        copy_into(&mut output.psk_id, value.psk_id.as_slice())?;
        Ok(output)
    }
}
impl TryFrom<&HpkePskReceiverSetupRequest<'_>> for CryptoHpkePskReceiverSetupRequest {
    type Error = HpkeError;
    // Establish the final clearing owner before copying any setup material.
    #[allow(clippy::field_reassign_with_default)]
    fn try_from(value: &HpkePskReceiverSetupRequest<'_>) -> Result<Self, Self::Error> {
        for bytes in [
            value.encapsulated_key,
            value.recipient_private_key,
            value.info,
            value.psk.as_slice(),
            value.psk_id.as_slice(),
        ] {
            super::requests::check_length(bytes)?;
        }
        let mut output = Self::default();
        output.suite = buffa::MessageField::some(
            crypto_proto::generated::proto::reallyme::crypto::v1::HpkeSuiteIdentifier::try_from(
                value.suite,
            )?,
        );
        copy_into(&mut output.encapsulated_key, value.encapsulated_key)?;
        copy_into(
            &mut output.recipient_private_key,
            value.recipient_private_key,
        )?;
        copy_into(&mut output.info, value.info)?;
        copy_into(&mut output.psk, value.psk.as_slice())?;
        copy_into(&mut output.psk_id, value.psk_id.as_slice())?;
        Ok(output)
    }
}
