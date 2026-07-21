// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use hpke::aead::{Aead as HpkeAead, AesGcm128, AesGcm256, ChaCha20Poly1305, ExportOnlyAead};
use hpke::kdf::{HkdfSha256, HkdfSha384, HkdfSha512, Kdf as HpkeKdf, KdfShake256};
use hpke::kem::{
    DhP256HkdfSha256, DhP384HkdfSha384, DhP521HkdfSha512, MlKem1024, MlKem1024P384, MlKem768,
    MlKem768P256, X25519HkdfSha256, XWing,
};
use hpke::{Deserializable, Kem as HpkeKem, OpModeR};
use zeroize::Zeroizing;

use crate::error::HpkeError;
use crate::identifiers::{HpkeAeadId, HpkeKdfId, HpkeKemId};
use crate::mlkem512::MlKem512;
use crate::secp256k1::DhKemSecp256k1HkdfSha256;
use crate::types::{HpkeExporterSecret, HpkeReceiverExportRequest};
use crate::validation::{
    require_export_suite, validate_encapsulated_key, validate_export_length,
    validate_key_schedule_inputs, validate_private_key,
};
use crate::x448::DhKemX448HkdfSha512;

/// Establishes a Base-mode receiver context and exports a bound secret.
pub fn receiver_export(
    request: &HpkeReceiverExportRequest<'_>,
) -> Result<HpkeExporterSecret, HpkeError> {
    require_export_suite(request.suite)?;
    validate_encapsulated_key(request.suite, request.encapsulated_key)?;
    validate_private_key(request.suite, request.recipient_private_key)?;
    validate_key_schedule_inputs(request.info, &[])?;
    validate_export_length(request.suite, request.output_length)?;

    match request.suite.kem {
        HpkeKemId::DhKemP256HkdfSha256 => receiver_export_for_kem::<DhP256HkdfSha256>(request),
        HpkeKemId::DhKemP384HkdfSha384 => receiver_export_for_kem::<DhP384HkdfSha384>(request),
        HpkeKemId::DhKemP521HkdfSha512 => receiver_export_for_kem::<DhP521HkdfSha512>(request),
        HpkeKemId::DhKemSecp256k1HkdfSha256 => {
            receiver_export_for_kem::<DhKemSecp256k1HkdfSha256>(request)
        }
        HpkeKemId::DhKemX25519HkdfSha256 => receiver_export_for_kem::<X25519HkdfSha256>(request),
        HpkeKemId::DhKemX448HkdfSha512 => receiver_export_for_kem::<DhKemX448HkdfSha512>(request),
        HpkeKemId::MlKem512 => receiver_export_for_kem::<MlKem512>(request),
        HpkeKemId::MlKem768 => receiver_export_for_kem::<MlKem768>(request),
        HpkeKemId::MlKem1024 => receiver_export_for_kem::<MlKem1024>(request),
        HpkeKemId::MlKem768P256 => receiver_export_for_kem::<MlKem768P256>(request),
        HpkeKemId::MlKem1024P384 => receiver_export_for_kem::<MlKem1024P384>(request),
        HpkeKemId::XWing => receiver_export_for_kem::<XWing>(request),
        HpkeKemId::DhKemCp256HkdfSha256
        | HpkeKemId::DhKemCp384HkdfSha384
        | HpkeKemId::DhKemCp521HkdfSha512
        | HpkeKemId::DhKemX25519ElligatorHkdfSha256
        | HpkeKemId::X25519Kyber768Draft00 => Err(HpkeError::UnsupportedKem),
    }
}

fn receiver_export_for_kem<Kem>(
    request: &HpkeReceiverExportRequest<'_>,
) -> Result<HpkeExporterSecret, HpkeError>
where
    Kem: HpkeKem,
{
    match request.suite.kdf {
        HpkeKdfId::HkdfSha256 => receiver_export_for_kdf::<Kem, HkdfSha256>(request),
        HpkeKdfId::HkdfSha384 => receiver_export_for_kdf::<Kem, HkdfSha384>(request),
        HpkeKdfId::HkdfSha512 => receiver_export_for_kdf::<Kem, HkdfSha512>(request),
        HpkeKdfId::Shake256 => receiver_export_for_kdf::<Kem, KdfShake256>(request),
        HpkeKdfId::Shake128 | HpkeKdfId::TurboShake128 | HpkeKdfId::TurboShake256 => {
            Err(HpkeError::UnsupportedKdf)
        }
    }
}

fn receiver_export_for_kdf<Kem, Kdf>(
    request: &HpkeReceiverExportRequest<'_>,
) -> Result<HpkeExporterSecret, HpkeError>
where
    Kem: HpkeKem,
    Kdf: HpkeKdf,
{
    match request.suite.aead {
        HpkeAeadId::Aes128Gcm => receiver_export_for::<AesGcm128, Kdf, Kem>(request),
        HpkeAeadId::Aes256Gcm => receiver_export_for::<AesGcm256, Kdf, Kem>(request),
        HpkeAeadId::ChaCha20Poly1305 => receiver_export_for::<ChaCha20Poly1305, Kdf, Kem>(request),
        HpkeAeadId::ExportOnly => receiver_export_for::<ExportOnlyAead, Kdf, Kem>(request),
    }
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
