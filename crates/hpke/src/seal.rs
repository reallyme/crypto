// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#[cfg(any(
    feature = "aead-aes128-gcm",
    feature = "aead-aes256-gcm",
    feature = "aead-chacha20-poly1305"
))]
use hpke::aead::Aead as HpkeAead;
use hpke::kdf::Kdf as HpkeKdf;
use hpke::Kem as HpkeKem;
#[cfg(any(
    feature = "aead-aes128-gcm",
    feature = "aead-aes256-gcm",
    feature = "aead-chacha20-poly1305"
))]
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
use zeroize::Zeroizing;

use crate::error::HpkeError;
#[cfg(any(
    feature = "aead-aes128-gcm",
    feature = "aead-aes256-gcm",
    feature = "aead-chacha20-poly1305"
))]
use crate::random::FixedRandomness;
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

    dispatch_kem!(request.suite.kem, seal_for_kem, request, randomness)
}

fn seal_for_kem<Kem>(
    request: &HpkeSealRequest<'_>,
    randomness: &[u8],
) -> Result<HpkeSealOutput, HpkeError>
where
    Kem: HpkeKem,
{
    dispatch_kdf!(request.suite.kdf, seal_for_kdf, Kem, request, randomness)
}

fn seal_for_kdf<Kem, Kdf>(
    request: &HpkeSealRequest<'_>,
    _randomness: &[u8],
) -> Result<HpkeSealOutput, HpkeError>
where
    Kem: HpkeKem,
    Kdf: HpkeKdf,
{
    dispatch_sealing_aead!(request.suite.aead, seal_for, Kdf, Kem, request, _randomness)
}

#[cfg(any(
    feature = "aead-aes128-gcm",
    feature = "aead-aes256-gcm",
    feature = "aead-chacha20-poly1305"
))]
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

    dispatch_kem!(request.suite.kem, open_for_kem, request)
}

fn open_for_kem<Kem>(request: &HpkeOpenRequest<'_>) -> Result<HpkeOpenOutput, HpkeError>
where
    Kem: HpkeKem,
{
    dispatch_kdf!(request.suite.kdf, open_for_kdf, Kem, request)
}

fn open_for_kdf<Kem, Kdf>(request: &HpkeOpenRequest<'_>) -> Result<HpkeOpenOutput, HpkeError>
where
    Kem: HpkeKem,
    Kdf: HpkeKdf,
{
    dispatch_sealing_aead!(request.suite.aead, open_for, Kdf, Kem, request)
}

#[cfg(any(
    feature = "aead-aes128-gcm",
    feature = "aead-aes256-gcm",
    feature = "aead-chacha20-poly1305"
))]
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

#[cfg(any(
    feature = "aead-aes128-gcm",
    feature = "aead-aes256-gcm",
    feature = "aead-chacha20-poly1305"
))]
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

#[cfg(any(
    feature = "aead-aes128-gcm",
    feature = "aead-aes256-gcm",
    feature = "aead-chacha20-poly1305"
))]
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
