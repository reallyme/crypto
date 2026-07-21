// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use hpke::aead::Aead as HpkeAead;
use hpke::kdf::Kdf as HpkeKdf;
use hpke::{Deserializable, Kem as HpkeKem, OpModeR};
use zeroize::Zeroizing;

use crate::error::HpkeError;
use crate::types::{HpkeExporterSecret, HpkeReceiverExportRequest};
use crate::validation::{
    require_export_suite, validate_encapsulated_key, validate_export_length,
    validate_key_schedule_inputs, validate_private_key,
};

/// Establishes a Base-mode receiver context and exports a bound secret.
pub fn receiver_export(
    request: &HpkeReceiverExportRequest<'_>,
) -> Result<HpkeExporterSecret, HpkeError> {
    require_export_suite(request.suite)?;
    validate_encapsulated_key(request.suite, request.encapsulated_key)?;
    validate_private_key(request.suite, request.recipient_private_key)?;
    validate_key_schedule_inputs(request.info, &[])?;
    validate_export_length(request.suite, request.output_length)?;

    dispatch_kem!(request.suite.kem, receiver_export_for_kem, request)
}

fn receiver_export_for_kem<Kem>(
    request: &HpkeReceiverExportRequest<'_>,
) -> Result<HpkeExporterSecret, HpkeError>
where
    Kem: HpkeKem,
{
    dispatch_kdf!(request.suite.kdf, receiver_export_for_kdf, Kem, request)
}

fn receiver_export_for_kdf<Kem, Kdf>(
    request: &HpkeReceiverExportRequest<'_>,
) -> Result<HpkeExporterSecret, HpkeError>
where
    Kem: HpkeKem,
    Kdf: HpkeKdf,
{
    dispatch_export_aead!(request.suite.aead, receiver_export_for, Kdf, Kem, request)
}

fn receiver_export_for<Aead, Kdf, Kem>(
    request: &HpkeReceiverExportRequest<'_>,
) -> Result<HpkeExporterSecret, HpkeError>
where
    Aead: HpkeAead,
    Kdf: HpkeKdf,
    Kem: HpkeKem,
{
    let recipient_private_key =
        <Kem::PrivateKey as Deserializable>::from_bytes(request.recipient_private_key)
            .map_err(|_| HpkeError::InvalidPrivateKey)?;
    let encapsulated_key =
        <Kem::EncappedKey as Deserializable>::from_bytes(request.encapsulated_key)
            .map_err(|_| HpkeError::InvalidEncapsulatedKey)?;
    let context = hpke::setup_receiver::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &recipient_private_key,
        &encapsulated_key,
        request.info,
    )
    .map_err(map_receiver_setup_error)?;

    let mut exporter_secret = Zeroizing::new(vec![0_u8; request.output_length]);
    context
        .export(request.exporter_context, exporter_secret.as_mut_slice())
        .map_err(map_export_error)?;
    Ok(HpkeExporterSecret::new(exporter_secret))
}

fn map_receiver_setup_error(error: hpke::HpkeError) -> HpkeError {
    match error {
        hpke::HpkeError::ValidationError | hpke::HpkeError::IncorrectInputLength(_, _) => {
            HpkeError::InvalidEncapsulatedKey
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
