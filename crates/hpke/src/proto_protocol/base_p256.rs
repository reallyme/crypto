// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fixed Base-mode requests borrow the non-exportable native recipient owner.

use super::requests::{check_length, copy_bytes, copy_into, require_known};
use crate::base_p256::{
    self, P256BasePlaintext, P256BaseSealed, P256RecipientKey, INFO_MAX_LEN, PLAINTEXT_MAX_LEN,
    PUBLIC_KEY_LEN, TAG_LEN,
};
use crate::{HpkeError, HPKE_DHKEM_P256_HKDF_SHA256_AES128GCM};
use buffa::MessageField;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoHpkeP256BaseCapabilities, CryptoHpkeP256BaseOpenRequest, CryptoHpkeP256BaseOpenResult,
    CryptoHpkeP256BasePublicKey, CryptoHpkeP256BaseSealRequest, CryptoHpkeP256BaseSealedResult,
    HpkeSuiteIdentifier,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
const UNCOMPRESSED_POINT_PREFIX: u8 =
    crypto_core::contract_constants::hpke_internal::UNCOMPRESSED_POINT_PREFIX;

/// Reports the existing compiled profile's public bounds without changing them.
pub fn p256_base_capabilities() -> Result<CryptoHpkeP256BaseCapabilities, HpkeError> {
    Ok(CryptoHpkeP256BaseCapabilities {
        suite: MessageField::some(HpkeSuiteIdentifier::try_from(
            HPKE_DHKEM_P256_HKDF_SHA256_AES128GCM,
        )?),
        info_max_length: u32::try_from(INFO_MAX_LEN)
            .map_err(|_| HpkeError::PRIMITIVE_INVALID_LENGTH)?,
        plaintext_max_length: u32::try_from(PLAINTEXT_MAX_LEN)
            .map_err(|_| HpkeError::PRIMITIVE_INVALID_LENGTH)?,
        public_key_length: u32::try_from(PUBLIC_KEY_LEN)
            .map_err(|_| HpkeError::PRIMITIVE_INVALID_LENGTH)?,
        authentication_tag_length: u32::try_from(TAG_LEN)
            .map_err(|_| HpkeError::PRIMITIVE_INVALID_LENGTH)?,
        empty_aad_only: true,
        private_key_exportable: false,
        __buffa_unknown_fields: Default::default(),
    })
}
impl From<&P256RecipientKey> for CryptoHpkeP256BasePublicKey {
    fn from(value: &P256RecipientKey) -> Self {
        Self {
            public_key: value.public_key().to_vec(),
            __buffa_unknown_fields: Default::default(),
        }
    }
}
/// Protected fixed-profile seal content; AAD remains empty by native contract.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct P256BaseSealInputs {
    public_key: Zeroizing<Vec<u8>>,
    info: Zeroizing<Vec<u8>>,
    plaintext: Zeroizing<Vec<u8>>,
}
impl P256BaseSealInputs {
    /// Calls the unchanged fixed native profile with exact info and plaintext.
    pub fn seal(&self) -> Result<P256BaseSealed, HpkeError> {
        base_p256::seal(&self.public_key, &self.info, &self.plaintext)
    }

    /// Borrows an explicit native entropy provider without serializing its state.
    /// The existing fixed profile receives the same exact info and plaintext.
    pub fn seal_with_rng(
        &self,
        rng: &mut impl crate::base_p256::P256BaseRng,
    ) -> Result<P256BaseSealed, HpkeError> {
        base_p256::seal_with_rng(&self.public_key, &self.info, &self.plaintext, rng)
    }
}
impl TryFrom<&CryptoHpkeP256BaseSealRequest> for P256BaseSealInputs {
    type Error = HpkeError;
    fn try_from(value: &CryptoHpkeP256BaseSealRequest) -> Result<Self, Self::Error> {
        require_known(value.__buffa_unknown_fields.is_empty())?;
        check_bounds(&value.info, value.plaintext.len())?;
        check_point_shape(
            &value.recipient_public_key,
            HpkeError::PRIMITIVE_INVALID_PUBLIC_KEY,
        )?;
        Ok(Self {
            public_key: copy_bytes(&value.recipient_public_key)?,
            info: copy_bytes(&value.info)?,
            plaintext: copy_bytes(&value.plaintext)?,
        })
    }
}
/// Protected open content without any serialized recipient private key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct P256BaseOpenInputs {
    enc: Zeroizing<Vec<u8>>,
    info: Zeroizing<Vec<u8>>,
    ciphertext: Zeroizing<Vec<u8>>,
}
impl P256BaseOpenInputs {
    /// Borrows the existing associated native recipient owner explicitly.
    pub fn open(&self, recipient: &P256RecipientKey) -> Result<P256BasePlaintext, HpkeError> {
        base_p256::open(recipient, &self.enc, &self.info, &self.ciphertext)
    }
}
impl TryFrom<&CryptoHpkeP256BaseOpenRequest> for P256BaseOpenInputs {
    type Error = HpkeError;
    fn try_from(value: &CryptoHpkeP256BaseOpenRequest) -> Result<Self, Self::Error> {
        require_known(value.__buffa_unknown_fields.is_empty())?;
        let plaintext_length = value
            .ciphertext
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(HpkeError::PRIMITIVE_MALFORMED_CIPHERTEXT)?;
        check_bounds(&value.info, plaintext_length)?;
        check_point_shape(
            &value.encapsulated_key,
            HpkeError::PRIMITIVE_MALFORMED_CIPHERTEXT,
        )?;
        Ok(Self {
            enc: copy_bytes(&value.encapsulated_key)?,
            info: copy_bytes(&value.info)?,
            ciphertext: copy_bytes(&value.ciphertext)?,
        })
    }
}
impl TryFrom<&P256BaseSealed> for CryptoHpkeP256BaseSealedResult {
    type Error = HpkeError;
    // Install the final clearing result before either copied byte field.
    #[allow(clippy::field_reassign_with_default)]
    fn try_from(value: &P256BaseSealed) -> Result<Self, Self::Error> {
        check_length(&value.ciphertext)?;
        let mut output = Self::default();
        copy_into(&mut output.encapsulated_key, &value.enc)?;
        copy_into(&mut output.ciphertext, &value.ciphertext)?;
        Ok(output)
    }
}
impl TryFrom<&P256BasePlaintext> for CryptoHpkeP256BaseOpenResult {
    type Error = HpkeError;
    fn try_from(value: &P256BasePlaintext) -> Result<Self, Self::Error> {
        check_length(value.as_slice())?;
        let mut output = Self::default();
        copy_into(&mut output.plaintext, value.as_slice())?;
        Ok(output)
    }
}
fn check_bounds(info: &[u8], plaintext_length: usize) -> Result<(), HpkeError> {
    if info.len() > INFO_MAX_LEN || plaintext_length > PLAINTEXT_MAX_LEN {
        Err(HpkeError::PRIMITIVE_RESOURCE_LIMIT_EXCEEDED)
    } else {
        Ok(())
    }
}
fn check_point_shape(value: &[u8], error: HpkeError) -> Result<(), HpkeError> {
    if value.len() != PUBLIC_KEY_LEN || value.first() != Some(&UNCOMPRESSED_POINT_PREFIX) {
        Err(error)
    } else {
        Ok(())
    }
}
