// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use hpke::aead::Aead as HpkeAead;
use hpke::kdf::Kdf as HpkeKdf;
use hpke::{Deserializable, Kem as HpkeKem, OpModeS, Serializable};
use zeroize::Zeroizing;

use crate::error::HpkeError;
use crate::random::FixedRandomness;
#[cfg(feature = "test-vectors")]
use crate::types::HpkeDerandSenderExportRequest;
use crate::types::{HpkeSenderExportOutput, HpkeSenderExportRequest};
use crate::validation::{
    kem_parameters, require_export_suite, validate_export_length, validate_key_schedule_inputs,
    validate_public_key,
};

/// Establishes a Base-mode sender context and exports a bound secret.
pub fn sender_export(
    request: &HpkeSenderExportRequest<'_>,
) -> Result<HpkeSenderExportOutput, HpkeError> {
    let randomness_length = request.suite.encapsulation_randomness_len()?;
    let mut randomness = Zeroizing::new(vec![0_u8; randomness_length]);
    getrandom::fill(randomness.as_mut_slice()).map_err(|_| HpkeError::RandomnessUnavailable)?;
    sender_export_with_randomness(request, randomness.as_slice())
}

/// Establishes a Base-mode sender context with deterministic KEM randomness
/// and exports a bound secret for conformance vectors.
#[cfg(feature = "test-vectors")]
pub fn sender_export_derand(
    request: &HpkeDerandSenderExportRequest<'_>,
) -> Result<HpkeSenderExportOutput, HpkeError> {
    let export_request = HpkeSenderExportRequest {
        suite: request.suite,
        recipient_public_key: request.recipient_public_key,
        info: request.info,
        exporter_context: request.exporter_context,
        output_length: request.output_length,
    };
    sender_export_with_randomness(&export_request, request.encapsulation_randomness)
}

fn sender_export_with_randomness(
    request: &HpkeSenderExportRequest<'_>,
    randomness: &[u8],
) -> Result<HpkeSenderExportOutput, HpkeError> {
    require_export_suite(request.suite)?;
    validate_public_key(request.suite, request.recipient_public_key)?;
    validate_key_schedule_inputs(request.info, &[])?;
    validate_export_length(request.suite, request.output_length)?;
    if randomness.len() != request.suite.encapsulation_randomness_len()? {
        return Err(HpkeError::InvalidRandomness);
    }

    dispatch_kem!(
        request.suite.kem,
        sender_export_for_kem,
        request,
        randomness
    )
}

fn sender_export_for_kem<Kem>(
    request: &HpkeSenderExportRequest<'_>,
    randomness: &[u8],
) -> Result<HpkeSenderExportOutput, HpkeError>
where
    Kem: HpkeKem,
{
    dispatch_kdf!(
        request.suite.kdf,
        sender_export_for_kdf,
        Kem,
        request,
        randomness
    )
}

fn sender_export_for_kdf<Kem, Kdf>(
    request: &HpkeSenderExportRequest<'_>,
    randomness: &[u8],
) -> Result<HpkeSenderExportOutput, HpkeError>
where
    Kem: HpkeKem,
    Kdf: HpkeKdf,
{
    dispatch_export_aead!(
        request.suite.aead,
        sender_export_for,
        Kdf,
        Kem,
        request,
        randomness
    )
}

fn sender_export_for<Aead, Kdf, Kem>(
    request: &HpkeSenderExportRequest<'_>,
    randomness: &[u8],
) -> Result<HpkeSenderExportOutput, HpkeError>
where
    Aead: HpkeAead,
    Kdf: HpkeKdf,
    Kem: HpkeKem,
{
    let recipient_public_key =
        <Kem::PublicKey as Deserializable>::from_bytes(request.recipient_public_key)
            .map_err(|_| HpkeError::InvalidPublicKey)?;
    let mut rng = FixedRandomness::new(randomness);
    let (encapsulated_key, context) = hpke::setup_sender_with_rng::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &recipient_public_key,
        request.info,
        &mut rng,
    )
    .map_err(map_sender_setup_error)?;
    if !rng.was_consumed_exactly() {
        return Err(HpkeError::InvalidRandomness);
    }

    let encapsulated_key = encapsulated_key.to_bytes().as_slice().to_vec();
    if encapsulated_key.len() != kem_parameters(request.suite.kem)?.encapsulated_key_len {
        return Err(HpkeError::ExportFailed);
    }
    let mut exporter_secret = Zeroizing::new(vec![0_u8; request.output_length]);
    context
        .export(request.exporter_context, exporter_secret.as_mut_slice())
        .map_err(map_export_error)?;

    Ok(HpkeSenderExportOutput::new(
        encapsulated_key,
        exporter_secret,
    ))
}

fn map_sender_setup_error(error: hpke::HpkeError) -> HpkeError {
    match error {
        hpke::HpkeError::ValidationError | hpke::HpkeError::IncorrectInputLength(_, _) => {
            HpkeError::InvalidPublicKey
        }
        hpke::HpkeError::InvalidPskBundle
        | hpke::HpkeError::DecapError
        | hpke::HpkeError::EncapError
        | hpke::HpkeError::KdfOutputTooLong
        | hpke::HpkeError::MessageLimitReached
        | hpke::HpkeError::OpenError
        | hpke::HpkeError::SealError => HpkeError::ExportFailed,
    }
}

fn map_export_error(error: hpke::HpkeError) -> HpkeError {
    match error {
        hpke::HpkeError::KdfOutputTooLong => HpkeError::InvalidExporterLength,
        hpke::HpkeError::ValidationError
        | hpke::HpkeError::IncorrectInputLength(_, _)
        | hpke::HpkeError::InvalidPskBundle
        | hpke::HpkeError::DecapError
        | hpke::HpkeError::EncapError
        | hpke::HpkeError::MessageLimitReached
        | hpke::HpkeError::OpenError
        | hpke::HpkeError::SealError => HpkeError::ExportFailed,
    }
}
