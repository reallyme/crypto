// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use hpke::aead::{Aead as HpkeAead, AesGcm128, AesGcm256, ChaCha20Poly1305};
use hpke::kdf::{HkdfSha256, HkdfSha384, HkdfSha512, Kdf as HpkeKdf, KdfShake256};
use hpke::kem::{
    DhP256HkdfSha256, DhP384HkdfSha384, DhP521HkdfSha512, MlKem1024, MlKem1024P384, MlKem768,
    MlKem768P256, X25519HkdfSha256, XWing,
};
use hpke::{Deserializable, Kem as HpkeKem, OpModeR, OpModeS, Serializable};
use zeroize::Zeroizing;

use crate::error::HpkeError;
use crate::identifiers::{HpkeAeadId, HpkeKdfId, HpkeKemId};
use crate::mlkem512::MlKem512;
use crate::random::FixedRandomness;
use crate::secp256k1::DhKemSecp256k1HkdfSha256;
use crate::setup_receiver::{setup_receiver_psk, HpkePskReceiverSetupRequest};
use crate::setup_sender::{setup_sender_psk, HpkePskSenderSetupRequest};
#[cfg(feature = "test-vectors")]
use crate::types::HpkeDerandSealRequest;
use crate::types::{
    HpkeOpenOutput, HpkeOpenRequest, HpkePskIdRef, HpkePskOpenRequest, HpkePskRef,
    HpkePskSealRequest, HpkeSealOutput, HpkeSealRequest,
};
use crate::validation::{
    kem_parameters, require_sealing_suite, validate_ciphertext, validate_encapsulated_key,
    validate_key_schedule_inputs, validate_private_key, validate_public_key,
};
use crate::x448::DhKemX448HkdfSha512;

/// Encrypts one message with RFC 9180 HPKE Base mode.
pub fn seal_base(request: &HpkeSealRequest<'_>) -> Result<HpkeSealOutput, HpkeError> {
    let randomness_length = request.suite.encapsulation_randomness_len()?;
    let mut randomness = Zeroizing::new(vec![0_u8; randomness_length]);
    getrandom::fill(randomness.as_mut_slice()).map_err(|_| HpkeError::RandomnessUnavailable)?;
    seal_with_randomness(request, randomness.as_slice())
}

/// Decrypts one message with RFC 9180 HPKE Base mode.
pub fn open_base(request: &HpkeOpenRequest<'_>) -> Result<HpkeOpenOutput, HpkeError> {
    open_base_inner(request)
}

/// Encrypts one message with RFC 9180 HPKE PSK mode.
pub fn seal_psk(request: &HpkePskSealRequest<'_>) -> Result<HpkeSealOutput, HpkeError> {
    let mut setup = setup_sender_psk(&HpkePskSenderSetupRequest {
        suite: request.suite,
        recipient_public_key: request.recipient_public_key,
        info: request.info,
        psk: HpkePskRef::new(request.psk)?,
        psk_id: HpkePskIdRef::new(request.psk_id)?,
    })?;
    let ciphertext = setup.context.seal(request.aad, request.plaintext)?;
    Ok(HpkeSealOutput {
        encapsulated_key: setup.encapsulated_key,
        ciphertext,
    })
}

/// Decrypts one message with RFC 9180 HPKE PSK mode.
pub fn open_psk(request: &HpkePskOpenRequest<'_>) -> Result<HpkeOpenOutput, HpkeError> {
    // Reject structurally impossible ciphertext before the comparatively
    // expensive receiver KEM setup, especially for post-quantum suites.
    validate_ciphertext(request.suite, request.ciphertext)?;
    let mut context = setup_receiver_psk(&HpkePskReceiverSetupRequest {
        suite: request.suite,
        encapsulated_key: request.encapsulated_key,
        recipient_private_key: request.recipient_private_key,
        info: request.info,
        psk: HpkePskRef::new(request.psk)?,
        psk_id: HpkePskIdRef::new(request.psk_id)?,
    })?;
    context.open(request.aad, request.ciphertext)
}

/// Encrypts one Base-mode message with deterministic KEM randomness.
#[cfg(feature = "test-vectors")]
pub fn seal_base_derand(request: &HpkeDerandSealRequest<'_>) -> Result<HpkeSealOutput, HpkeError> {
    if request.encapsulation_randomness.len() != request.suite.encapsulation_randomness_len()? {
        return Err(HpkeError::InvalidRandomness);
    }
    let seal_request = HpkeSealRequest {
        suite: request.suite,
        recipient_public_key: request.recipient_public_key,
        info: request.info,
        aad: request.aad,
        plaintext: request.plaintext,
    };
    seal_with_randomness(&seal_request, request.encapsulation_randomness)
}

fn seal_with_randomness(
    request: &HpkeSealRequest<'_>,
    randomness: &[u8],
) -> Result<HpkeSealOutput, HpkeError> {
    require_sealing_suite(request.suite)?;
    validate_public_key(request.suite, request.recipient_public_key)?;
    validate_key_schedule_inputs(request.info, &[])?;
    if randomness.len() != kem_parameters(request.suite.kem)?.encapsulation_randomness_len {
        return Err(HpkeError::InvalidRandomness);
    }

    match request.suite.kem {
        HpkeKemId::DhKemP256HkdfSha256 => seal_for_kem::<DhP256HkdfSha256>(request, randomness),
        HpkeKemId::DhKemP384HkdfSha384 => seal_for_kem::<DhP384HkdfSha384>(request, randomness),
        HpkeKemId::DhKemP521HkdfSha512 => seal_for_kem::<DhP521HkdfSha512>(request, randomness),
        HpkeKemId::DhKemSecp256k1HkdfSha256 => {
            seal_for_kem::<DhKemSecp256k1HkdfSha256>(request, randomness)
        }
        HpkeKemId::DhKemX25519HkdfSha256 => seal_for_kem::<X25519HkdfSha256>(request, randomness),
        HpkeKemId::DhKemX448HkdfSha512 => seal_for_kem::<DhKemX448HkdfSha512>(request, randomness),
        HpkeKemId::MlKem512 => seal_for_kem::<MlKem512>(request, randomness),
        HpkeKemId::MlKem768 => seal_for_kem::<MlKem768>(request, randomness),
        HpkeKemId::MlKem1024 => seal_for_kem::<MlKem1024>(request, randomness),
        HpkeKemId::MlKem768P256 => seal_for_kem::<MlKem768P256>(request, randomness),
        HpkeKemId::MlKem1024P384 => seal_for_kem::<MlKem1024P384>(request, randomness),
        HpkeKemId::XWing => seal_for_kem::<XWing>(request, randomness),
        HpkeKemId::DhKemCp256HkdfSha256
        | HpkeKemId::DhKemCp384HkdfSha384
        | HpkeKemId::DhKemCp521HkdfSha512
        | HpkeKemId::DhKemX25519ElligatorHkdfSha256
        | HpkeKemId::X25519Kyber768Draft00 => Err(HpkeError::UnsupportedKem),
    }
}

fn seal_for_kem<Kem>(
    request: &HpkeSealRequest<'_>,
    randomness: &[u8],
) -> Result<HpkeSealOutput, HpkeError>
where
    Kem: HpkeKem,
{
    match request.suite.kdf {
        HpkeKdfId::HkdfSha256 => seal_for_kdf::<Kem, HkdfSha256>(request, randomness),
        HpkeKdfId::HkdfSha384 => seal_for_kdf::<Kem, HkdfSha384>(request, randomness),
        HpkeKdfId::HkdfSha512 => seal_for_kdf::<Kem, HkdfSha512>(request, randomness),
        HpkeKdfId::Shake256 => seal_for_kdf::<Kem, KdfShake256>(request, randomness),
        HpkeKdfId::Shake128 | HpkeKdfId::TurboShake128 | HpkeKdfId::TurboShake256 => {
            Err(HpkeError::UnsupportedKdf)
        }
    }
}

fn seal_for_kdf<Kem, Kdf>(
    request: &HpkeSealRequest<'_>,
    randomness: &[u8],
) -> Result<HpkeSealOutput, HpkeError>
where
    Kem: HpkeKem,
    Kdf: HpkeKdf,
{
    match request.suite.aead {
        HpkeAeadId::Aes128Gcm => seal_for::<AesGcm128, Kdf, Kem>(request, randomness),
        HpkeAeadId::Aes256Gcm => seal_for::<AesGcm256, Kdf, Kem>(request, randomness),
        HpkeAeadId::ChaCha20Poly1305 => seal_for::<ChaCha20Poly1305, Kdf, Kem>(request, randomness),
        HpkeAeadId::ExportOnly => Err(HpkeError::UnsupportedSuite),
    }
}

fn seal_for<Aead, Kdf, Kem>(
    request: &HpkeSealRequest<'_>,
    randomness: &[u8],
) -> Result<HpkeSealOutput, HpkeError>
where
    Aead: HpkeAead,
    Kdf: HpkeKdf,
    Kem: HpkeKem,
{
    let expected_ciphertext_length = request
        .plaintext
        .len()
        .checked_add(request.suite.tag_len())
        .ok_or(HpkeError::LengthOverflow)?;
    let recipient_public_key =
        <Kem::PublicKey as Deserializable>::from_bytes(request.recipient_public_key)
            .map_err(|_| HpkeError::InvalidPublicKey)?;
    let mut rng = FixedRandomness::new(randomness);
    let (encapsulated_key, ciphertext) = hpke::single_shot_seal_with_rng::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &recipient_public_key,
        request.info,
        request.plaintext,
        request.aad,
        &mut rng,
    )
    .map_err(map_seal_error)?;

    if !rng.was_consumed_exactly() {
        return Err(HpkeError::InvalidRandomness);
    }
    let encapsulated_key = encapsulated_key.to_bytes().as_slice().to_vec();
    let parameters = kem_parameters(request.suite.kem)?;
    if encapsulated_key.len() != parameters.encapsulated_key_len
        || ciphertext.len() != expected_ciphertext_length
    {
        return Err(HpkeError::SealFailed);
    }
    Ok(HpkeSealOutput {
        encapsulated_key,
        ciphertext,
    })
}

fn open_base_inner(request: &HpkeOpenRequest<'_>) -> Result<HpkeOpenOutput, HpkeError> {
    require_sealing_suite(request.suite)?;
    validate_encapsulated_key(request.suite, request.encapsulated_key)?;
    validate_private_key(request.suite, request.recipient_private_key)?;
    validate_ciphertext(request.suite, request.ciphertext)?;
    validate_key_schedule_inputs(request.info, &[])?;

    match request.suite.kem {
        HpkeKemId::DhKemP256HkdfSha256 => open_for_kem::<DhP256HkdfSha256>(request),
        HpkeKemId::DhKemP384HkdfSha384 => open_for_kem::<DhP384HkdfSha384>(request),
        HpkeKemId::DhKemP521HkdfSha512 => open_for_kem::<DhP521HkdfSha512>(request),
        HpkeKemId::DhKemSecp256k1HkdfSha256 => open_for_kem::<DhKemSecp256k1HkdfSha256>(request),
        HpkeKemId::DhKemX25519HkdfSha256 => open_for_kem::<X25519HkdfSha256>(request),
        HpkeKemId::DhKemX448HkdfSha512 => open_for_kem::<DhKemX448HkdfSha512>(request),
        HpkeKemId::MlKem512 => open_for_kem::<MlKem512>(request),
        HpkeKemId::MlKem768 => open_for_kem::<MlKem768>(request),
        HpkeKemId::MlKem1024 => open_for_kem::<MlKem1024>(request),
        HpkeKemId::MlKem768P256 => open_for_kem::<MlKem768P256>(request),
        HpkeKemId::MlKem1024P384 => open_for_kem::<MlKem1024P384>(request),
        HpkeKemId::XWing => open_for_kem::<XWing>(request),
        HpkeKemId::DhKemCp256HkdfSha256
        | HpkeKemId::DhKemCp384HkdfSha384
        | HpkeKemId::DhKemCp521HkdfSha512
        | HpkeKemId::DhKemX25519ElligatorHkdfSha256
        | HpkeKemId::X25519Kyber768Draft00 => Err(HpkeError::UnsupportedKem),
    }
}

fn open_for_kem<Kem>(request: &HpkeOpenRequest<'_>) -> Result<HpkeOpenOutput, HpkeError>
where
    Kem: HpkeKem,
{
    match request.suite.kdf {
        HpkeKdfId::HkdfSha256 => open_for_kdf::<Kem, HkdfSha256>(request),
        HpkeKdfId::HkdfSha384 => open_for_kdf::<Kem, HkdfSha384>(request),
        HpkeKdfId::HkdfSha512 => open_for_kdf::<Kem, HkdfSha512>(request),
        HpkeKdfId::Shake256 => open_for_kdf::<Kem, KdfShake256>(request),
        HpkeKdfId::Shake128 | HpkeKdfId::TurboShake128 | HpkeKdfId::TurboShake256 => {
            Err(HpkeError::UnsupportedKdf)
        }
    }
}

fn open_for_kdf<Kem, Kdf>(request: &HpkeOpenRequest<'_>) -> Result<HpkeOpenOutput, HpkeError>
where
    Kem: HpkeKem,
    Kdf: HpkeKdf,
{
    match request.suite.aead {
        HpkeAeadId::Aes128Gcm => open_for::<AesGcm128, Kdf, Kem>(request),
        HpkeAeadId::Aes256Gcm => open_for::<AesGcm256, Kdf, Kem>(request),
        HpkeAeadId::ChaCha20Poly1305 => open_for::<ChaCha20Poly1305, Kdf, Kem>(request),
        HpkeAeadId::ExportOnly => Err(HpkeError::UnsupportedSuite),
    }
}

fn open_for<Aead, Kdf, Kem>(request: &HpkeOpenRequest<'_>) -> Result<HpkeOpenOutput, HpkeError>
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
    let plaintext = hpke::single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &recipient_private_key,
        &encapsulated_key,
        request.info,
        request.ciphertext,
        request.aad,
    )
    .map_err(map_open_error)?;

    Ok(HpkeOpenOutput {
        plaintext: Zeroizing::new(plaintext),
    })
}

fn map_seal_error(error: hpke::HpkeError) -> HpkeError {
    match error {
        hpke::HpkeError::ValidationError | hpke::HpkeError::IncorrectInputLength(_, _) => {
            HpkeError::InvalidPublicKey
        }
        hpke::HpkeError::InvalidPskBundle => HpkeError::InvalidPsk,
        hpke::HpkeError::EncapError
        | hpke::HpkeError::KdfOutputTooLong
        | hpke::HpkeError::MessageLimitReached
        | hpke::HpkeError::OpenError
        | hpke::HpkeError::SealError
        | hpke::HpkeError::DecapError => HpkeError::SealFailed,
    }
}

fn map_open_error(error: hpke::HpkeError) -> HpkeError {
    match error {
        hpke::HpkeError::ValidationError | hpke::HpkeError::IncorrectInputLength(_, _) => {
            HpkeError::InvalidEncapsulatedKey
        }
        hpke::HpkeError::InvalidPskBundle => HpkeError::InvalidPsk,
        hpke::HpkeError::DecapError
        | hpke::HpkeError::EncapError
        | hpke::HpkeError::KdfOutputTooLong
        | hpke::HpkeError::MessageLimitReached
        | hpke::HpkeError::OpenError
        | hpke::HpkeError::SealError => HpkeError::OpenFailed,
    }
}
