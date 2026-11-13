// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protected content owners for unchanged one-shot and export DTOs.

use crate::validation::{
    require_export_suite, require_sealing_suite, validate_ciphertext, validate_encapsulated_key,
    validate_export_length, validate_key_schedule_inputs, validate_private_key, validate_psk,
    validate_public_key,
};
use crate::{
    HpkeError, HpkeOpenRequest, HpkePskOpenRequest, HpkePskSealRequest, HpkeReceiverExportRequest,
    HpkeSealRequest, HpkeSenderExportRequest, HpkeSuite,
};
use buffa::MessageField;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm, CryptoAlgorithmIdentifier,
    CryptoHpkeOpenRequest, CryptoHpkePskOpenRequest, CryptoHpkePskSealRequest,
    CryptoHpkeReceiverExportRequest, CryptoHpkeSealRequest, CryptoHpkeSenderExportRequest,
    HpkeSuiteIdentifier,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Clearing input owner borrowing the existing `HpkeSealRequest` without byte changes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HpkeSealInputs {
    #[zeroize(skip)]
    suite: HpkeSuite,
    recipient_public_key: Zeroizing<Vec<u8>>,
    info: Zeroizing<Vec<u8>>,
    aad: Zeroizing<Vec<u8>>,
    plaintext: Zeroizing<Vec<u8>>,
}
impl HpkeSealInputs {
    /// Borrows exact caller bytes through the unchanged native request.
    pub fn as_request(&self) -> HpkeSealRequest<'_> {
        HpkeSealRequest {
            suite: self.suite,
            recipient_public_key: &self.recipient_public_key,
            info: &self.info,
            aad: &self.aad,
            plaintext: &self.plaintext,
        }
    }
}
impl TryFrom<&CryptoHpkeSealRequest> for HpkeSealInputs {
    type Error = HpkeError;
    fn try_from(value: &CryptoHpkeSealRequest) -> Result<Self, Self::Error> {
        require_known(value.__buffa_unknown_fields.is_empty())?;
        let suite = read_algorithm(value.algorithm.as_option())?;
        require_sealing_suite(suite)?;
        validate_public_key(suite, &value.recipient_public_key)?;
        validate_key_schedule_inputs(suite.kdf, &value.info, &[])?;
        Ok(Self {
            suite,
            recipient_public_key: copy_bytes(&value.recipient_public_key)?,
            info: copy_bytes(&value.info)?,
            aad: copy_bytes(&value.aad)?,
            plaintext: copy_bytes(&value.plaintext)?,
        })
    }
}
impl TryFrom<&HpkeSealRequest<'_>> for CryptoHpkeSealRequest {
    type Error = HpkeError;
    // Install the final clearing DTO before copying any request bytes.
    #[allow(clippy::field_reassign_with_default)]
    fn try_from(value: &HpkeSealRequest<'_>) -> Result<Self, Self::Error> {
        check_length(value.recipient_public_key)?;
        check_length(value.info)?;
        check_length(value.aad)?;
        check_length(value.plaintext)?;
        let mut output = Self::default();
        output.algorithm = MessageField::some(write_algorithm(value.suite)?);
        copy_into(&mut output.recipient_public_key, value.recipient_public_key)?;
        copy_into(&mut output.info, value.info)?;
        copy_into(&mut output.aad, value.aad)?;
        copy_into(&mut output.plaintext, value.plaintext)?;
        Ok(output)
    }
}

/// Clearing input owner borrowing the existing `HpkeOpenRequest` without byte changes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HpkeOpenInputs {
    #[zeroize(skip)]
    suite: HpkeSuite,
    recipient_private_key: Zeroizing<Vec<u8>>,
    encapsulated_key: Zeroizing<Vec<u8>>,
    info: Zeroizing<Vec<u8>>,
    aad: Zeroizing<Vec<u8>>,
    ciphertext: Zeroizing<Vec<u8>>,
}
impl HpkeOpenInputs {
    /// Borrows exact caller bytes through the unchanged native request.
    pub fn as_request(&self) -> HpkeOpenRequest<'_> {
        HpkeOpenRequest {
            suite: self.suite,
            recipient_private_key: &self.recipient_private_key,
            encapsulated_key: &self.encapsulated_key,
            info: &self.info,
            aad: &self.aad,
            ciphertext: &self.ciphertext,
        }
    }
}
impl TryFrom<&CryptoHpkeOpenRequest> for HpkeOpenInputs {
    type Error = HpkeError;
    fn try_from(value: &CryptoHpkeOpenRequest) -> Result<Self, Self::Error> {
        require_known(value.__buffa_unknown_fields.is_empty())?;
        let suite = read_algorithm(value.algorithm.as_option())?;
        require_sealing_suite(suite)?;
        validate_encapsulated_key(suite, &value.encapsulated_key)?;
        validate_private_key(suite, &value.recipient_secret_key)?;
        validate_ciphertext(suite, &value.ciphertext)?;
        validate_key_schedule_inputs(suite.kdf, &value.info, &[])?;
        Ok(Self {
            suite,
            recipient_private_key: copy_bytes(&value.recipient_secret_key)?,
            encapsulated_key: copy_bytes(&value.encapsulated_key)?,
            info: copy_bytes(&value.info)?,
            aad: copy_bytes(&value.aad)?,
            ciphertext: copy_bytes(&value.ciphertext)?,
        })
    }
}
impl TryFrom<&HpkeOpenRequest<'_>> for CryptoHpkeOpenRequest {
    type Error = HpkeError;
    // Install the final clearing DTO before copying any request bytes.
    #[allow(clippy::field_reassign_with_default)]
    fn try_from(value: &HpkeOpenRequest<'_>) -> Result<Self, Self::Error> {
        check_length(value.recipient_private_key)?;
        check_length(value.encapsulated_key)?;
        check_length(value.info)?;
        check_length(value.aad)?;
        check_length(value.ciphertext)?;
        let mut output = Self::default();
        output.algorithm = MessageField::some(write_algorithm(value.suite)?);
        copy_into(
            &mut output.recipient_secret_key,
            value.recipient_private_key,
        )?;
        copy_into(&mut output.encapsulated_key, value.encapsulated_key)?;
        copy_into(&mut output.info, value.info)?;
        copy_into(&mut output.aad, value.aad)?;
        copy_into(&mut output.ciphertext, value.ciphertext)?;
        Ok(output)
    }
}

/// Clearing input owner borrowing the existing `HpkePskSealRequest` without byte changes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HpkePskSealInputs {
    #[zeroize(skip)]
    suite: HpkeSuite,
    recipient_public_key: Zeroizing<Vec<u8>>,
    info: Zeroizing<Vec<u8>>,
    aad: Zeroizing<Vec<u8>>,
    plaintext: Zeroizing<Vec<u8>>,
    psk: Zeroizing<Vec<u8>>,
    psk_id: Zeroizing<Vec<u8>>,
}
impl HpkePskSealInputs {
    /// Borrows exact caller bytes through the unchanged native request.
    pub fn as_request(&self) -> HpkePskSealRequest<'_> {
        HpkePskSealRequest {
            suite: self.suite,
            recipient_public_key: &self.recipient_public_key,
            info: &self.info,
            aad: &self.aad,
            plaintext: &self.plaintext,
            psk: &self.psk,
            psk_id: &self.psk_id,
        }
    }
}
impl TryFrom<&CryptoHpkePskSealRequest> for HpkePskSealInputs {
    type Error = HpkeError;
    fn try_from(value: &CryptoHpkePskSealRequest) -> Result<Self, Self::Error> {
        require_known(value.__buffa_unknown_fields.is_empty())?;
        let suite = read_algorithm(value.algorithm.as_option())?;
        require_sealing_suite(suite)?;
        validate_public_key(suite, &value.recipient_public_key)?;
        validate_psk(suite.kdf, &value.psk, &value.psk_id)?;
        validate_key_schedule_inputs(suite.kdf, &value.info, &value.psk_id)?;
        Ok(Self {
            suite,
            recipient_public_key: copy_bytes(&value.recipient_public_key)?,
            info: copy_bytes(&value.info)?,
            aad: copy_bytes(&value.aad)?,
            plaintext: copy_bytes(&value.plaintext)?,
            psk: copy_bytes(&value.psk)?,
            psk_id: copy_bytes(&value.psk_id)?,
        })
    }
}
impl TryFrom<&HpkePskSealRequest<'_>> for CryptoHpkePskSealRequest {
    type Error = HpkeError;
    // Install the final clearing DTO before copying any request bytes.
    #[allow(clippy::field_reassign_with_default)]
    fn try_from(value: &HpkePskSealRequest<'_>) -> Result<Self, Self::Error> {
        check_length(value.recipient_public_key)?;
        check_length(value.info)?;
        check_length(value.aad)?;
        check_length(value.plaintext)?;
        check_length(value.psk)?;
        check_length(value.psk_id)?;
        let mut output = Self::default();
        output.algorithm = MessageField::some(write_algorithm(value.suite)?);
        copy_into(&mut output.recipient_public_key, value.recipient_public_key)?;
        copy_into(&mut output.info, value.info)?;
        copy_into(&mut output.aad, value.aad)?;
        copy_into(&mut output.plaintext, value.plaintext)?;
        copy_into(&mut output.psk, value.psk)?;
        copy_into(&mut output.psk_id, value.psk_id)?;
        Ok(output)
    }
}

/// Clearing input owner borrowing the existing `HpkePskOpenRequest` without byte changes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HpkePskOpenInputs {
    #[zeroize(skip)]
    suite: HpkeSuite,
    recipient_private_key: Zeroizing<Vec<u8>>,
    encapsulated_key: Zeroizing<Vec<u8>>,
    info: Zeroizing<Vec<u8>>,
    aad: Zeroizing<Vec<u8>>,
    ciphertext: Zeroizing<Vec<u8>>,
    psk: Zeroizing<Vec<u8>>,
    psk_id: Zeroizing<Vec<u8>>,
}
impl HpkePskOpenInputs {
    /// Borrows exact caller bytes through the unchanged native request.
    pub fn as_request(&self) -> HpkePskOpenRequest<'_> {
        HpkePskOpenRequest {
            suite: self.suite,
            recipient_private_key: &self.recipient_private_key,
            encapsulated_key: &self.encapsulated_key,
            info: &self.info,
            aad: &self.aad,
            ciphertext: &self.ciphertext,
            psk: &self.psk,
            psk_id: &self.psk_id,
        }
    }
}
impl TryFrom<&CryptoHpkePskOpenRequest> for HpkePskOpenInputs {
    type Error = HpkeError;
    fn try_from(value: &CryptoHpkePskOpenRequest) -> Result<Self, Self::Error> {
        require_known(value.__buffa_unknown_fields.is_empty())?;
        let suite = read_algorithm(value.algorithm.as_option())?;
        require_sealing_suite(suite)?;
        validate_encapsulated_key(suite, &value.encapsulated_key)?;
        validate_private_key(suite, &value.recipient_secret_key)?;
        validate_ciphertext(suite, &value.ciphertext)?;
        validate_psk(suite.kdf, &value.psk, &value.psk_id)?;
        validate_key_schedule_inputs(suite.kdf, &value.info, &value.psk_id)?;
        Ok(Self {
            suite,
            recipient_private_key: copy_bytes(&value.recipient_secret_key)?,
            encapsulated_key: copy_bytes(&value.encapsulated_key)?,
            info: copy_bytes(&value.info)?,
            aad: copy_bytes(&value.aad)?,
            ciphertext: copy_bytes(&value.ciphertext)?,
            psk: copy_bytes(&value.psk)?,
            psk_id: copy_bytes(&value.psk_id)?,
        })
    }
}
impl TryFrom<&HpkePskOpenRequest<'_>> for CryptoHpkePskOpenRequest {
    type Error = HpkeError;
    // Install the final clearing DTO before copying any request bytes.
    #[allow(clippy::field_reassign_with_default)]
    fn try_from(value: &HpkePskOpenRequest<'_>) -> Result<Self, Self::Error> {
        check_length(value.recipient_private_key)?;
        check_length(value.encapsulated_key)?;
        check_length(value.info)?;
        check_length(value.aad)?;
        check_length(value.ciphertext)?;
        check_length(value.psk)?;
        check_length(value.psk_id)?;
        let mut output = Self::default();
        output.algorithm = MessageField::some(write_algorithm(value.suite)?);
        copy_into(
            &mut output.recipient_secret_key,
            value.recipient_private_key,
        )?;
        copy_into(&mut output.encapsulated_key, value.encapsulated_key)?;
        copy_into(&mut output.info, value.info)?;
        copy_into(&mut output.aad, value.aad)?;
        copy_into(&mut output.ciphertext, value.ciphertext)?;
        copy_into(&mut output.psk, value.psk)?;
        copy_into(&mut output.psk_id, value.psk_id)?;
        Ok(output)
    }
}

/// Clearing input owner borrowing the existing `HpkeSenderExportRequest` without byte changes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HpkeSenderExportInputs {
    #[zeroize(skip)]
    suite: HpkeSuite,
    recipient_public_key: Zeroizing<Vec<u8>>,
    info: Zeroizing<Vec<u8>>,
    exporter_context: Zeroizing<Vec<u8>>,
    output_length: usize,
}
impl HpkeSenderExportInputs {
    /// Borrows exact caller bytes through the unchanged native request.
    pub fn as_request(&self) -> HpkeSenderExportRequest<'_> {
        HpkeSenderExportRequest {
            suite: self.suite,
            recipient_public_key: &self.recipient_public_key,
            info: &self.info,
            exporter_context: &self.exporter_context,
            output_length: self.output_length,
        }
    }
}
impl TryFrom<&CryptoHpkeSenderExportRequest> for HpkeSenderExportInputs {
    type Error = HpkeError;
    fn try_from(value: &CryptoHpkeSenderExportRequest) -> Result<Self, Self::Error> {
        require_known(value.__buffa_unknown_fields.is_empty())?;
        let suite = read_algorithm(value.algorithm.as_option())?;
        require_export_suite(suite)?;
        validate_public_key(suite, &value.recipient_public_key)?;
        validate_key_schedule_inputs(suite.kdf, &value.info, &[])?;
        let output_length = usize::try_from(value.output_length)
            .map_err(|_| HpkeError::PRIMITIVE_INVALID_LENGTH)?;
        validate_export_length(suite, output_length)?;
        Ok(Self {
            suite,
            recipient_public_key: copy_bytes(&value.recipient_public_key)?,
            info: copy_bytes(&value.info)?,
            exporter_context: copy_bytes(&value.exporter_context)?,
            output_length,
        })
    }
}
impl TryFrom<&HpkeSenderExportRequest<'_>> for CryptoHpkeSenderExportRequest {
    type Error = HpkeError;
    // Install the final clearing DTO before copying any request bytes.
    #[allow(clippy::field_reassign_with_default)]
    fn try_from(value: &HpkeSenderExportRequest<'_>) -> Result<Self, Self::Error> {
        check_length(value.recipient_public_key)?;
        check_length(value.info)?;
        check_length(value.exporter_context)?;
        let output_length =
            u32::try_from(value.output_length).map_err(|_| HpkeError::PRIMITIVE_INVALID_LENGTH)?;
        let mut output = Self::default();
        output.algorithm = MessageField::some(write_algorithm(value.suite)?);
        copy_into(&mut output.recipient_public_key, value.recipient_public_key)?;
        copy_into(&mut output.info, value.info)?;
        copy_into(&mut output.exporter_context, value.exporter_context)?;
        output.output_length = output_length;
        Ok(output)
    }
}

/// Clearing input owner borrowing the existing `HpkeReceiverExportRequest` without byte changes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HpkeReceiverExportInputs {
    #[zeroize(skip)]
    suite: HpkeSuite,
    recipient_private_key: Zeroizing<Vec<u8>>,
    encapsulated_key: Zeroizing<Vec<u8>>,
    info: Zeroizing<Vec<u8>>,
    exporter_context: Zeroizing<Vec<u8>>,
    output_length: usize,
}
impl HpkeReceiverExportInputs {
    /// Borrows exact caller bytes through the unchanged native request.
    pub fn as_request(&self) -> HpkeReceiverExportRequest<'_> {
        HpkeReceiverExportRequest {
            suite: self.suite,
            recipient_private_key: &self.recipient_private_key,
            encapsulated_key: &self.encapsulated_key,
            info: &self.info,
            exporter_context: &self.exporter_context,
            output_length: self.output_length,
        }
    }
}
impl TryFrom<&CryptoHpkeReceiverExportRequest> for HpkeReceiverExportInputs {
    type Error = HpkeError;
    fn try_from(value: &CryptoHpkeReceiverExportRequest) -> Result<Self, Self::Error> {
        require_known(value.__buffa_unknown_fields.is_empty())?;
        let suite = read_algorithm(value.algorithm.as_option())?;
        require_export_suite(suite)?;
        validate_encapsulated_key(suite, &value.encapsulated_key)?;
        validate_private_key(suite, &value.recipient_secret_key)?;
        validate_key_schedule_inputs(suite.kdf, &value.info, &[])?;
        let output_length = usize::try_from(value.output_length)
            .map_err(|_| HpkeError::PRIMITIVE_INVALID_LENGTH)?;
        validate_export_length(suite, output_length)?;
        Ok(Self {
            suite,
            recipient_private_key: copy_bytes(&value.recipient_secret_key)?,
            encapsulated_key: copy_bytes(&value.encapsulated_key)?,
            info: copy_bytes(&value.info)?,
            exporter_context: copy_bytes(&value.exporter_context)?,
            output_length,
        })
    }
}
impl TryFrom<&HpkeReceiverExportRequest<'_>> for CryptoHpkeReceiverExportRequest {
    type Error = HpkeError;
    // Install the final clearing DTO before copying any request bytes.
    #[allow(clippy::field_reassign_with_default)]
    fn try_from(value: &HpkeReceiverExportRequest<'_>) -> Result<Self, Self::Error> {
        check_length(value.recipient_private_key)?;
        check_length(value.encapsulated_key)?;
        check_length(value.info)?;
        check_length(value.exporter_context)?;
        let output_length =
            u32::try_from(value.output_length).map_err(|_| HpkeError::PRIMITIVE_INVALID_LENGTH)?;
        let mut output = Self::default();
        output.algorithm = MessageField::some(write_algorithm(value.suite)?);
        copy_into(
            &mut output.recipient_secret_key,
            value.recipient_private_key,
        )?;
        copy_into(&mut output.encapsulated_key, value.encapsulated_key)?;
        copy_into(&mut output.info, value.info)?;
        copy_into(&mut output.exporter_context, value.exporter_context)?;
        output.output_length = output_length;
        Ok(output)
    }
}

pub(super) fn read_algorithm(
    value: Option<&CryptoAlgorithmIdentifier>,
) -> Result<HpkeSuite, HpkeError> {
    let value = value.ok_or(HpkeError::PRIMITIVE_INVALID_PARAMETER)?;
    require_known(value.__buffa_unknown_fields.is_empty())?;
    match value.algorithm.as_ref() {
        Some(Algorithm::HpkeSuite(suite)) => HpkeSuite::try_from(suite.as_ref()),
        _ => Err(HpkeError::PRIMITIVE_INVALID_PARAMETER),
    }
}
pub(super) fn write_algorithm(suite: HpkeSuite) -> Result<CryptoAlgorithmIdentifier, HpkeError> {
    Ok(CryptoAlgorithmIdentifier {
        algorithm: Some(Algorithm::HpkeSuite(Box::new(
            HpkeSuiteIdentifier::try_from(suite)?,
        ))),
        __buffa_unknown_fields: Default::default(),
    })
}
pub(super) fn require_known(known: bool) -> Result<(), HpkeError> {
    if known {
        Ok(())
    } else {
        Err(HpkeError::PRIMITIVE_INVALID_PARAMETER)
    }
}
pub(super) fn check_length(bytes: &[u8]) -> Result<(), HpkeError> {
    u32::try_from(bytes.len())
        .map(|_| ())
        .map_err(|_| HpkeError::PRIMITIVE_INVALID_LENGTH)
}
pub(super) fn copy_bytes(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, HpkeError> {
    check_length(bytes)?;
    let mut output = Zeroizing::new(Vec::new());
    output
        .try_reserve_exact(bytes.len())
        .map_err(|_| HpkeError::BACKEND_INTERNAL)?;
    output.extend_from_slice(bytes);
    Ok(output)
}

/// Copies one field through its final clearing owner, with fallible allocation.
pub(super) fn copy_into(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), HpkeError> {
    check_length(bytes)?;
    if !output.is_empty() {
        return Err(HpkeError::BACKEND_INVALID_STATE);
    }
    output
        .try_reserve_exact(bytes.len())
        .map_err(|_| HpkeError::BACKEND_INTERNAL)?;
    output.extend_from_slice(bytes);
    Ok(())
}
