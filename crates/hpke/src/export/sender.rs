// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use hpke::aead::{Aead as HpkeAead, AesGcm128, AesGcm256, ChaCha20Poly1305, ExportOnlyAead};
use hpke::kdf::{HkdfSha256, HkdfSha384, HkdfSha512, Kdf as HpkeKdf, KdfShake256};
use hpke::kem::{
    DhP256HkdfSha256, DhP384HkdfSha384, DhP521HkdfSha512, MlKem1024, MlKem1024P384, MlKem768,
    MlKem768P256, X25519HkdfSha256, XWing,
};
use hpke::{Deserializable, Kem as HpkeKem, OpModeS, Serializable};
use zeroize::Zeroizing;

use crate::error::HpkeError;
use crate::identifiers::{HpkeAeadId, HpkeKdfId, HpkeKemId};
use crate::mlkem512::MlKem512;
use crate::random::FixedRandomness;
use crate::secp256k1::DhKemSecp256k1HkdfSha256;
#[cfg(feature = "test-vectors")]
use crate::types::HpkeDerandSenderExportRequest;
use crate::types::{HpkeSenderExportOutput, HpkeSenderExportRequest};
use crate::validation::{
    kem_parameters, require_export_suite, validate_export_length, validate_key_schedule_inputs,
    validate_public_key,
};
use crate::x448::DhKemX448HkdfSha512;

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

    match request.suite.kem {
        HpkeKemId::DhKemP256HkdfSha256 => {
            sender_export_for_kem::<DhP256HkdfSha256>(request, randomness)
        }
        HpkeKemId::DhKemP384HkdfSha384 => {
            sender_export_for_kem::<DhP384HkdfSha384>(request, randomness)
        }
        HpkeKemId::DhKemP521HkdfSha512 => {
            sender_export_for_kem::<DhP521HkdfSha512>(request, randomness)
        }
        HpkeKemId::DhKemSecp256k1HkdfSha256 => {
            sender_export_for_kem::<DhKemSecp256k1HkdfSha256>(request, randomness)
        }
        HpkeKemId::DhKemX25519HkdfSha256 => {
            sender_export_for_kem::<X25519HkdfSha256>(request, randomness)
        }
        HpkeKemId::DhKemX448HkdfSha512 => {
            sender_export_for_kem::<DhKemX448HkdfSha512>(request, randomness)
        }
        HpkeKemId::MlKem512 => sender_export_for_kem::<MlKem512>(request, randomness),
        HpkeKemId::MlKem768 => sender_export_for_kem::<MlKem768>(request, randomness),
        HpkeKemId::MlKem1024 => sender_export_for_kem::<MlKem1024>(request, randomness),
        HpkeKemId::MlKem768P256 => sender_export_for_kem::<MlKem768P256>(request, randomness),
        HpkeKemId::MlKem1024P384 => sender_export_for_kem::<MlKem1024P384>(request, randomness),
        HpkeKemId::XWing => sender_export_for_kem::<XWing>(request, randomness),
        HpkeKemId::DhKemCp256HkdfSha256
        | HpkeKemId::DhKemCp384HkdfSha384
        | HpkeKemId::DhKemCp521HkdfSha512
        | HpkeKemId::DhKemX25519ElligatorHkdfSha256
        | HpkeKemId::X25519Kyber768Draft00 => Err(HpkeError::UnsupportedKem),
    }
}

fn sender_export_for_kem<Kem>(
    request: &HpkeSenderExportRequest<'_>,
    randomness: &[u8],
) -> Result<HpkeSenderExportOutput, HpkeError>
where
    Kem: HpkeKem,
{
    match request.suite.kdf {
        HpkeKdfId::HkdfSha256 => sender_export_for_kdf::<Kem, HkdfSha256>(request, randomness),
        HpkeKdfId::HkdfSha384 => sender_export_for_kdf::<Kem, HkdfSha384>(request, randomness),
        HpkeKdfId::HkdfSha512 => sender_export_for_kdf::<Kem, HkdfSha512>(request, randomness),
        HpkeKdfId::Shake256 => sender_export_for_kdf::<Kem, KdfShake256>(request, randomness),
        HpkeKdfId::Shake128 | HpkeKdfId::TurboShake128 | HpkeKdfId::TurboShake256 => {
            Err(HpkeError::UnsupportedKdf)
        }
    }
}

fn sender_export_for_kdf<Kem, Kdf>(
    request: &HpkeSenderExportRequest<'_>,
    randomness: &[u8],
) -> Result<HpkeSenderExportOutput, HpkeError>
where
    Kem: HpkeKem,
    Kdf: HpkeKdf,
{
    match request.suite.aead {
        HpkeAeadId::Aes128Gcm => sender_export_for::<AesGcm128, Kdf, Kem>(request, randomness),
        HpkeAeadId::Aes256Gcm => sender_export_for::<AesGcm256, Kdf, Kem>(request, randomness),
        HpkeAeadId::ChaCha20Poly1305 => {
            sender_export_for::<ChaCha20Poly1305, Kdf, Kem>(request, randomness)
        }
        HpkeAeadId::ExportOnly => {
            sender_export_for::<ExportOnlyAead, Kdf, Kem>(request, randomness)
        }
    }
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
