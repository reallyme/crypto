// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protected adapters for the existing HKDF inputs and fixed domain profile.

use crate::{
    DeriveRequest, DomainKeyPurpose, DomainTag, HkdfInfo, HkdfInputKeyMaterial, HkdfSalt,
    HkdfSha384Prk, HkdfSuite, HKDF_SHA384_MAX_OUTPUT_LENGTH, HKDF_SHA384_PRK_LENGTH,
};
use buffa::{EnumValue, MessageField};
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoHkdfDeriveInputs, CryptoHkdfDomainKey32Request, CryptoHkdfDomainTag,
    CryptoHkdfExpandSha384Request, CryptoHkdfExtractSha384Request, CryptoHkdfExtractSha384Result,
    CryptoHkdfSuiteIdentifier, HkdfDomainKeyPurpose as ProtoPurpose,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

impl TryFrom<EnumValue<ProtoPurpose>> for DomainKeyPurpose {
    type Error = CryptoError;
    fn try_from(value: EnumValue<ProtoPurpose>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(ProtoPurpose::HKDF_DOMAIN_KEY_PURPOSE_AEAD_CONTENT_KEY) => {
                Ok(Self::AeadContentKey)
            }
            Some(ProtoPurpose::HKDF_DOMAIN_KEY_PURPOSE_AEAD_WRAP_KEY) => Ok(Self::AeadWrapKey),
            Some(ProtoPurpose::HKDF_DOMAIN_KEY_PURPOSE_AUTH_PROOF_KEY) => Ok(Self::AuthProofKey),
            Some(ProtoPurpose::HKDF_DOMAIN_KEY_PURPOSE_MANIFEST_COMMITMENT_KEY) => {
                Ok(Self::ManifestCommitmentKey)
            }
            _ => Err(CryptoError::PRIMITIVE_INVALID_PARAMETER),
        }
    }
}
impl From<DomainKeyPurpose> for ProtoPurpose {
    fn from(value: DomainKeyPurpose) -> Self {
        match value {
            DomainKeyPurpose::AeadContentKey => Self::HKDF_DOMAIN_KEY_PURPOSE_AEAD_CONTENT_KEY,
            DomainKeyPurpose::AeadWrapKey => Self::HKDF_DOMAIN_KEY_PURPOSE_AEAD_WRAP_KEY,
            DomainKeyPurpose::AuthProofKey => Self::HKDF_DOMAIN_KEY_PURPOSE_AUTH_PROOF_KEY,
            DomainKeyPurpose::ManifestCommitmentKey => {
                Self::HKDF_DOMAIN_KEY_PURPOSE_MANIFEST_COMMITMENT_KEY
            }
        }
    }
}
impl TryFrom<&CryptoHkdfDomainTag> for DomainTag {
    type Error = CryptoError;
    fn try_from(value: &CryptoHkdfDomainTag) -> Result<Self, Self::Error> {
        require_known(value.__buffa_unknown_fields.is_empty())?;
        Self::from_slice(&value.value)
    }
}
impl From<&DomainTag> for CryptoHkdfDomainTag {
    fn from(value: &DomainTag) -> Self {
        Self {
            value: value.as_bytes().to_vec(),
            __buffa_unknown_fields: Default::default(),
        }
    }
}

/// Protected owners backing the unchanged borrowed native derivation request.
pub struct HkdfDeriveInputs {
    suite: HkdfSuite,
    ikm: HkdfInputKeyMaterial,
    salt: Option<HkdfSalt>,
    info: HkdfInfo,
}
impl HkdfDeriveInputs {
    /// Borrows the original native request with exact context bytes.
    pub fn as_request(&self) -> DeriveRequest<'_> {
        DeriveRequest {
            suite: self.suite,
            ikm: &self.ikm,
            salt: self.salt.as_ref(),
            info: &self.info,
        }
    }
}
impl Zeroize for HkdfDeriveInputs {
    fn zeroize(&mut self) {
        self.ikm.zeroize();
        self.salt.zeroize();
        self.info.zeroize();
    }
}
impl ZeroizeOnDrop for HkdfDeriveInputs {}
impl TryFrom<&CryptoHkdfDeriveInputs> for HkdfDeriveInputs {
    type Error = CryptoError;
    fn try_from(value: &CryptoHkdfDeriveInputs) -> Result<Self, Self::Error> {
        require_known(value.__buffa_unknown_fields.is_empty())?;
        let suite = HkdfSuite::try_from(
            value
                .suite
                .as_option()
                .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?,
        )?;
        Ok(Self {
            suite,
            ikm: read_ikm(&value.input_key_material)?,
            salt: read_salt(value.salt.as_deref())?,
            info: read_info(&value.info)?,
        })
    }
}
impl TryFrom<&DeriveRequest<'_>> for CryptoHkdfDeriveInputs {
    type Error = CryptoError;
    // Establish the clearing owner before copying secret/context fields.
    #[allow(clippy::field_reassign_with_default)]
    fn try_from(value: &DeriveRequest<'_>) -> Result<Self, Self::Error> {
        check_length(value.ikm.as_bytes())?;
        check_length(value.info.as_bytes())?;
        if let Some(salt) = value.salt {
            check_length(salt.as_bytes())?;
        }
        let mut output = Self::default();
        output.suite = MessageField::some(CryptoHkdfSuiteIdentifier::from(value.suite));
        output.input_key_material = value.ikm.as_bytes().to_vec();
        output.salt = value.salt.map(|salt| salt.as_bytes().to_vec());
        output.info = value.info.as_bytes().to_vec();
        Ok(output)
    }
}

/// Protected inputs for the existing SHA-384 extract function.
pub struct HkdfExtractSha384Inputs {
    ikm: HkdfInputKeyMaterial,
    salt: Option<HkdfSalt>,
}
impl HkdfExtractSha384Inputs {
    /// Borrows the exact input key material.
    pub fn ikm(&self) -> &HkdfInputKeyMaterial {
        &self.ikm
    }
    /// Preserves absent versus present-empty salt.
    pub fn salt(&self) -> Option<&HkdfSalt> {
        self.salt.as_ref()
    }
}
impl Zeroize for HkdfExtractSha384Inputs {
    fn zeroize(&mut self) {
        self.ikm.zeroize();
        self.salt.zeroize();
    }
}
impl ZeroizeOnDrop for HkdfExtractSha384Inputs {}
impl TryFrom<&CryptoHkdfExtractSha384Request> for HkdfExtractSha384Inputs {
    type Error = CryptoError;
    fn try_from(value: &CryptoHkdfExtractSha384Request) -> Result<Self, Self::Error> {
        require_known(value.__buffa_unknown_fields.is_empty())?;
        Ok(Self {
            ikm: read_ikm(&value.input_key_material)?,
            salt: read_salt(value.salt.as_deref())?,
        })
    }
}
impl From<&HkdfSha384Prk> for CryptoHkdfExtractSha384Result {
    fn from(value: &HkdfSha384Prk) -> Self {
        Self {
            pseudorandom_key: value.as_bytes().to_vec(),
            __buffa_unknown_fields: Default::default(),
        }
    }
}

/// Protected inputs for one native const-generic SHA-384 expansion.
pub struct HkdfExpandSha384Inputs<const N: usize> {
    prk: HkdfSha384Prk,
    info: HkdfInfo,
}
impl<const N: usize> HkdfExpandSha384Inputs<N> {
    /// Borrows the protected pseudorandom key.
    pub fn prk(&self) -> &HkdfSha384Prk {
        &self.prk
    }
    /// Borrows verbatim application context, including NUL and non-UTF-8 bytes.
    pub fn info(&self) -> &HkdfInfo {
        &self.info
    }
}
impl<const N: usize> Zeroize for HkdfExpandSha384Inputs<N> {
    fn zeroize(&mut self) {
        self.prk.zeroize();
        self.info.zeroize();
    }
}
impl<const N: usize> ZeroizeOnDrop for HkdfExpandSha384Inputs<N> {}
impl<const N: usize> TryFrom<&CryptoHkdfExpandSha384Request> for HkdfExpandSha384Inputs<N> {
    type Error = CryptoError;
    fn try_from(value: &CryptoHkdfExpandSha384Request) -> Result<Self, Self::Error> {
        require_known(value.__buffa_unknown_fields.is_empty())?;
        let length = usize::try_from(value.output_length)
            .map_err(|_| CryptoError::PRIMITIVE_INVALID_LENGTH)?;
        if length != N || N == 0 || N > HKDF_SHA384_MAX_OUTPUT_LENGTH {
            return Err(CryptoError::PRIMITIVE_INVALID_LENGTH);
        }
        if value.pseudorandom_key.len() != HKDF_SHA384_PRK_LENGTH {
            return Err(CryptoError::PRIMITIVE_INVALID_KEY);
        }
        // Copy directly through the final clearing owner, never a raw PRK local.
        let mut prk = HkdfSha384Prk::from_array([0; HKDF_SHA384_PRK_LENGTH]);
        prk.as_mut_bytes().copy_from_slice(&value.pseudorandom_key);
        Ok(Self {
            prk,
            info: read_info(&value.info)?,
        })
    }
}
impl<const N: usize> TryFrom<&HkdfExpandSha384Inputs<N>> for CryptoHkdfExpandSha384Request {
    type Error = CryptoError;
    // Establish the clearing owner before copying secret/context fields.
    #[allow(clippy::field_reassign_with_default)]
    fn try_from(value: &HkdfExpandSha384Inputs<N>) -> Result<Self, Self::Error> {
        check_length(value.info.as_bytes())?;
        let output_length = u32::try_from(N).map_err(|_| CryptoError::PRIMITIVE_INVALID_LENGTH)?;
        let mut output = Self::default();
        output.output_length = output_length;
        output.pseudorandom_key = value.prk.as_bytes().to_vec();
        output.info = value.info.as_bytes().to_vec();
        Ok(output)
    }
}

/// Protected inputs for the existing fixed SHA3-256, 32-byte domain profile.
pub struct HkdfDomainKey32Inputs {
    ikm: HkdfInputKeyMaterial,
    salt: Option<HkdfSalt>,
    purpose: DomainKeyPurpose,
    domain_tag: DomainTag,
}
impl HkdfDomainKey32Inputs {
    /// Borrows the input key material.
    pub fn ikm(&self) -> &HkdfInputKeyMaterial {
        &self.ikm
    }
    /// Borrows the optional exact salt.
    pub fn salt(&self) -> Option<&HkdfSalt> {
        self.salt.as_ref()
    }
    /// Returns the existing domain purpose.
    pub fn purpose(&self) -> DomainKeyPurpose {
        self.purpose
    }
    /// Borrows the validated original tag bytes.
    pub fn domain_tag(&self) -> &DomainTag {
        &self.domain_tag
    }
}
impl Zeroize for HkdfDomainKey32Inputs {
    fn zeroize(&mut self) {
        self.ikm.zeroize();
        self.salt.zeroize();
        self.domain_tag.zeroize();
    }
}
impl ZeroizeOnDrop for HkdfDomainKey32Inputs {}
impl TryFrom<&CryptoHkdfDomainKey32Request> for HkdfDomainKey32Inputs {
    type Error = CryptoError;
    fn try_from(value: &CryptoHkdfDomainKey32Request) -> Result<Self, Self::Error> {
        require_known(value.__buffa_unknown_fields.is_empty())?;
        let purpose = DomainKeyPurpose::try_from(value.purpose)?;
        let domain_tag = DomainTag::try_from(
            value
                .domain_tag
                .as_option()
                .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?,
        )?;
        Ok(Self {
            ikm: read_ikm(&value.input_key_material)?,
            salt: read_salt(value.salt.as_deref())?,
            purpose,
            domain_tag,
        })
    }
}
fn require_known(known: bool) -> Result<(), CryptoError> {
    if known {
        Ok(())
    } else {
        Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    }
}
fn check_length(bytes: &[u8]) -> Result<(), CryptoError> {
    u32::try_from(bytes.len())
        .map(|_| ())
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_LENGTH)
}
fn read_ikm(bytes: &[u8]) -> Result<HkdfInputKeyMaterial, CryptoError> {
    if bytes.is_empty() {
        return Err(CryptoError::PRIMITIVE_INVALID_KEY);
    }
    check_length(bytes)?;
    Ok(HkdfInputKeyMaterial::from_slice(bytes))
}

impl TryFrom<&HkdfExtractSha384Inputs> for CryptoHkdfExtractSha384Request {
    type Error = CryptoError;
    // Establish the clearing owner before copying secret/context fields.
    #[allow(clippy::field_reassign_with_default)]
    fn try_from(value: &HkdfExtractSha384Inputs) -> Result<Self, Self::Error> {
        check_length(value.ikm.as_bytes())?;
        if let Some(salt) = &value.salt {
            check_length(salt.as_bytes())?;
        }
        let mut output = Self::default();
        output.input_key_material = value.ikm.as_bytes().to_vec();
        output.salt = value.salt.as_ref().map(|salt| salt.as_bytes().to_vec());
        Ok(output)
    }
}
impl TryFrom<&HkdfDomainKey32Inputs> for CryptoHkdfDomainKey32Request {
    type Error = CryptoError;
    // Establish the clearing owner before copying secret/context fields.
    #[allow(clippy::field_reassign_with_default)]
    fn try_from(value: &HkdfDomainKey32Inputs) -> Result<Self, Self::Error> {
        check_length(value.ikm.as_bytes())?;
        if let Some(salt) = &value.salt {
            check_length(salt.as_bytes())?;
        }
        let mut output = Self::default();
        output.input_key_material = value.ikm.as_bytes().to_vec();
        output.salt = value.salt.as_ref().map(|salt| salt.as_bytes().to_vec());
        output.purpose = ProtoPurpose::from(value.purpose).into();
        output.domain_tag = MessageField::some(CryptoHkdfDomainTag::from(&value.domain_tag));
        Ok(output)
    }
}

fn read_salt(value: Option<&[u8]>) -> Result<Option<HkdfSalt>, CryptoError> {
    value
        .map(|bytes| {
            check_length(bytes)?;
            Ok(HkdfSalt::from_slice(bytes))
        })
        .transpose()
}
fn read_info(value: &[u8]) -> Result<HkdfInfo, CryptoError> {
    check_length(value)?;
    Ok(HkdfInfo::from_slice(value))
}
