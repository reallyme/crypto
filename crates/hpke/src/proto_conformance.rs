// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Standalone deterministic conformance inputs, never serialized live contexts.
//! Existing test-vectors features and native validation remain authoritative.

use crate::{
    HpkeDerandPskSenderSetupRequest, HpkeDerandSealRequest, HpkeDerandSenderExportRequest,
    HpkeError, HpkePskIdRef, HpkePskRef, HpkeSenderContext, HpkeSuite,
};
use buffa::MessageField;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm, CryptoAlgorithmIdentifier,
    CryptoHpkeBaseSealConformanceRequest, CryptoHpkePskSenderSetupConformanceRequest,
    CryptoHpkePskSenderSetupResult, CryptoHpkeSealedMessage,
    CryptoHpkeSenderExportConformanceRequest, CryptoHpkeSenderExportResult, HpkeSuiteIdentifier,
};
use zeroize::Zeroizing;

impl<'a> TryFrom<&'a CryptoHpkeBaseSealConformanceRequest> for HpkeDerandSealRequest<'a> {
    type Error = HpkeError;
    fn try_from(value: &'a CryptoHpkeBaseSealConformanceRequest) -> Result<Self, Self::Error> {
        known(value.__buffa_unknown_fields.is_empty())?;
        Ok(Self {
            suite: suite(value.suite.as_option())?,
            recipient_public_key: &value.recipient_public_key,
            encapsulation_randomness: &value.encapsulation_randomness,
            info: &value.info,
            aad: &value.aad,
            plaintext: &value.plaintext,
        })
    }
}
impl<'a> TryFrom<&'a CryptoHpkeSenderExportConformanceRequest>
    for HpkeDerandSenderExportRequest<'a>
{
    type Error = HpkeError;
    fn try_from(value: &'a CryptoHpkeSenderExportConformanceRequest) -> Result<Self, Self::Error> {
        known(value.__buffa_unknown_fields.is_empty())?;
        Ok(Self {
            suite: suite(value.suite.as_option())?,
            recipient_public_key: &value.recipient_public_key,
            encapsulation_randomness: &value.encapsulation_randomness,
            info: &value.info,
            exporter_context: &value.exporter_context,
            output_length: usize::try_from(value.output_length)
                .map_err(|_| HpkeError::PRIMITIVE_INVALID_LENGTH)?,
        })
    }
}
impl<'a> TryFrom<&'a CryptoHpkePskSenderSetupConformanceRequest>
    for HpkeDerandPskSenderSetupRequest<'a>
{
    type Error = HpkeError;
    fn try_from(
        value: &'a CryptoHpkePskSenderSetupConformanceRequest,
    ) -> Result<Self, Self::Error> {
        known(value.__buffa_unknown_fields.is_empty())?;
        Ok(Self {
            suite: suite(value.suite.as_option())?,
            recipient_public_key: &value.recipient_public_key,
            encapsulation_randomness: &value.encapsulation_randomness,
            info: &value.info,
            psk: HpkePskRef::new(&value.psk)?,
            psk_id: HpkePskIdRef::new(&value.psk_id)?,
        })
    }
}

/// Seal with exactly the supplied KEM randomness and complete suite identity.
/// Empty/binary info, AAD and plaintext remain unchanged.
pub fn seal_base(
    request: &CryptoHpkeBaseSealConformanceRequest,
) -> Result<CryptoHpkeSealedMessage, HpkeError> {
    let native = HpkeDerandSealRequest::try_from(request)?;
    let sealed = crate::seal_base_derand(&native)?;
    // Move existing allocations directly into clearing owners before the first
    // fallible output construction. No intermediate byte copy is introduced.
    let encapsulated = Zeroizing::new(sealed.encapsulated_key);
    let ciphertext = Zeroizing::new(sealed.ciphertext);
    let mut output = CryptoHpkeSealedMessage {
        algorithm: MessageField::some(identifier(native.suite)?),
        encapsulated_key: Vec::new(),
        ciphertext: Vec::new(),
        __buffa_unknown_fields: Default::default(),
    };
    copy_into(&mut output.encapsulated_key, &encapsulated)?;
    copy_into(&mut output.ciphertext, &ciphertext)?;
    Ok(output)
}

/// Export with exact caller-provided setup randomness and exporter context.
/// The native secret stays guarded while copying into the clearing DTO.
pub fn sender_export(
    request: &CryptoHpkeSenderExportConformanceRequest,
) -> Result<CryptoHpkeSenderExportResult, HpkeError> {
    let native = HpkeDerandSenderExportRequest::try_from(request)?;
    let mut exported = crate::sender_export_derand(&native)?;
    let encapsulated = Zeroizing::new(core::mem::take(&mut exported.encapsulated_key));
    let mut output = CryptoHpkeSenderExportResult {
        algorithm: MessageField::some(identifier(native.suite)?),
        encapsulated_key: Vec::new(),
        exporter_secret: Vec::new(),
        __buffa_unknown_fields: Default::default(),
    };
    copy_into(&mut output.encapsulated_key, &encapsulated)?;
    copy_into(&mut output.exporter_secret, exported.exporter_secret())?;
    Ok(output)
}

/// Return the existing non-serializable sender context and its public descriptor.
/// Every call performs existing native setup; no reset or context import exists.
pub fn setup_sender_psk(
    request: &CryptoHpkePskSenderSetupConformanceRequest,
) -> Result<(HpkeSenderContext, CryptoHpkePskSenderSetupResult), HpkeError> {
    let native = HpkeDerandPskSenderSetupRequest::try_from(request)?;
    let setup = crate::setup_sender_psk_derand(&native)?;
    let encapsulated = Zeroizing::new(setup.encapsulated_key);
    let mut output = CryptoHpkePskSenderSetupResult::default();
    copy_into(&mut output.encapsulated_key, &encapsulated)?;
    Ok((setup.context, output))
}

fn known(value: bool) -> Result<(), HpkeError> {
    if value {
        Ok(())
    } else {
        Err(HpkeError::PRIMITIVE_INVALID_PARAMETER)
    }
}
fn suite(value: Option<&HpkeSuiteIdentifier>) -> Result<HpkeSuite, HpkeError> {
    HpkeSuite::try_from(value.ok_or(HpkeError::PRIMITIVE_INVALID_PARAMETER)?)
}
fn identifier(value: HpkeSuite) -> Result<CryptoAlgorithmIdentifier, HpkeError> {
    Ok(CryptoAlgorithmIdentifier {
        algorithm: Some(Algorithm::HpkeSuite(Box::new(
            HpkeSuiteIdentifier::try_from(value)?,
        ))),
        __buffa_unknown_fields: Default::default(),
    })
}
fn copy_into(output: &mut Vec<u8>, value: &[u8]) -> Result<(), HpkeError> {
    if !output.is_empty() {
        return Err(HpkeError::BACKEND_INVALID_STATE);
    }
    output
        .try_reserve_exact(value.len())
        .map_err(|_| HpkeError::BACKEND_INTERNAL)?;
    output.resize(value.len(), 0);
    output.copy_from_slice(value);
    Ok(())
}
