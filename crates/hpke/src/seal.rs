// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use hpke::aead::{Aead as HpkeAead, AesGcm128, AesGcm256, ChaCha20Poly1305};
use hpke::kdf::{HkdfSha256, HkdfSha384, HkdfSha512, Kdf as HpkeKdf, KdfShake256};
use hpke::kem::{
    DhP256HkdfSha256, DhP384HkdfSha384, DhP521HkdfSha512, MlKem1024, MlKem1024P384, MlKem768,
    MlKem768P256, X25519HkdfSha256, XWing,
};
use hpke::{Deserializable, Kem as HpkeKem, OpModeR, OpModeS, PskBundle, Serializable};
use zeroize::Zeroizing;

use crate::error::HpkeError;
use crate::identifiers::{HpkeAeadId, HpkeKdfId, HpkeKemId};
use crate::mlkem512::MlKem512;
use crate::random::FixedRandomness;
use crate::secp256k1::DhKemSecp256k1HkdfSha256;
#[cfg(feature = "test-vectors")]
use crate::types::HpkeDerandSealRequest;
use crate::types::{
    HpkeOpenOutput, HpkeOpenRequest, HpkePskOpenRequest, HpkePskSealRequest, HpkeSealOutput,
    HpkeSealRequest,
};
use crate::validation::{
    kem_parameters, require_sealing_suite, validate_ciphertext, validate_encapsulated_key,
    validate_key_schedule_inputs, validate_private_key, validate_psk, validate_public_key,
};
use crate::x448::DhKemX448HkdfSha512;

#[derive(Clone, Copy)]
enum PskMode<'a> {
    Base,
    Psk { psk: &'a [u8], psk_id: &'a [u8] },
}

/// Encrypts one message with RFC 9180 HPKE Base mode.
pub fn seal_base(request: &HpkeSealRequest<'_>) -> Result<HpkeSealOutput, HpkeError> {
    let randomness_length = request.suite.encapsulation_randomness_len()?;
    let mut randomness = Zeroizing::new(vec![0_u8; randomness_length]);
    getrandom::fill(randomness.as_mut_slice()).map_err(|_| HpkeError::RandomnessUnavailable)?;
    seal_with_randomness(request, PskMode::Base, randomness.as_slice())
}

/// Decrypts one message with RFC 9180 HPKE Base mode.
pub fn open_base(request: &HpkeOpenRequest<'_>) -> Result<HpkeOpenOutput, HpkeError> {
    open_with_mode(request, PskMode::Base)
}

/// Encrypts one message with RFC 9180 HPKE PSK mode.
pub fn seal_psk(request: &HpkePskSealRequest<'_>) -> Result<HpkeSealOutput, HpkeError> {
    validate_psk(request.psk, request.psk_id)?;
    let randomness_length = request.suite.encapsulation_randomness_len()?;
    let mut randomness = Zeroizing::new(vec![0_u8; randomness_length]);
    getrandom::fill(randomness.as_mut_slice()).map_err(|_| HpkeError::RandomnessUnavailable)?;
    let base_request = HpkeSealRequest {
        suite: request.suite,
        recipient_public_key: request.recipient_public_key,
        info: request.info,
        aad: request.aad,
        plaintext: request.plaintext,
    };
    seal_with_randomness(
        &base_request,
        PskMode::Psk {
            psk: request.psk,
            psk_id: request.psk_id,
        },
        randomness.as_slice(),
    )
}

/// Decrypts one message with RFC 9180 HPKE PSK mode.
pub fn open_psk(request: &HpkePskOpenRequest<'_>) -> Result<HpkeOpenOutput, HpkeError> {
    validate_psk(request.psk, request.psk_id)?;
    let base_request = HpkeOpenRequest {
        suite: request.suite,
        encapsulated_key: request.encapsulated_key,
        recipient_private_key: request.recipient_private_key,
        info: request.info,
        aad: request.aad,
        ciphertext: request.ciphertext,
    };
    open_with_mode(
        &base_request,
        PskMode::Psk {
            psk: request.psk,
            psk_id: request.psk_id,
        },
    )
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
    seal_with_randomness(
        &seal_request,
        PskMode::Base,
        request.encapsulation_randomness,
    )
}

fn seal_with_randomness(
    request: &HpkeSealRequest<'_>,
    mode: PskMode<'_>,
    randomness: &[u8],
) -> Result<HpkeSealOutput, HpkeError> {
    require_sealing_suite(request.suite)?;
    validate_public_key(request.suite, request.recipient_public_key)?;
    validate_key_schedule_inputs(request.info, psk_id(mode))?;
    if randomness.len() != kem_parameters(request.suite.kem)?.encapsulation_randomness_len {
        return Err(HpkeError::InvalidRandomness);
    }

    match request.suite.kem {
        HpkeKemId::DhKemP256HkdfSha256 => {
            seal_for_kem::<DhP256HkdfSha256>(request, mode, randomness)
        }
        HpkeKemId::DhKemP384HkdfSha384 => {
            seal_for_kem::<DhP384HkdfSha384>(request, mode, randomness)
        }
        HpkeKemId::DhKemP521HkdfSha512 => {
            seal_for_kem::<DhP521HkdfSha512>(request, mode, randomness)
        }
        HpkeKemId::DhKemSecp256k1HkdfSha256 => {
            seal_for_kem::<DhKemSecp256k1HkdfSha256>(request, mode, randomness)
        }
        HpkeKemId::DhKemX25519HkdfSha256 => {
            seal_for_kem::<X25519HkdfSha256>(request, mode, randomness)
        }
        HpkeKemId::DhKemX448HkdfSha512 => {
            seal_for_kem::<DhKemX448HkdfSha512>(request, mode, randomness)
        }
        HpkeKemId::MlKem512 => seal_for_kem::<MlKem512>(request, mode, randomness),
        HpkeKemId::MlKem768 => seal_for_kem::<MlKem768>(request, mode, randomness),
        HpkeKemId::MlKem1024 => seal_for_kem::<MlKem1024>(request, mode, randomness),
        HpkeKemId::MlKem768P256 => seal_for_kem::<MlKem768P256>(request, mode, randomness),
        HpkeKemId::MlKem1024P384 => seal_for_kem::<MlKem1024P384>(request, mode, randomness),
        HpkeKemId::XWing => seal_for_kem::<XWing>(request, mode, randomness),
        HpkeKemId::DhKemCp256HkdfSha256
        | HpkeKemId::DhKemCp384HkdfSha384
        | HpkeKemId::DhKemCp521HkdfSha512
        | HpkeKemId::DhKemX25519ElligatorHkdfSha256
        | HpkeKemId::X25519Kyber768Draft00 => Err(HpkeError::UnsupportedKem),
    }
}

fn seal_for_kem<Kem>(
    request: &HpkeSealRequest<'_>,
    mode: PskMode<'_>,
    randomness: &[u8],
) -> Result<HpkeSealOutput, HpkeError>
where
    Kem: HpkeKem,
{
    match request.suite.kdf {
        HpkeKdfId::HkdfSha256 => seal_for_kdf::<Kem, HkdfSha256>(request, mode, randomness),
        HpkeKdfId::HkdfSha384 => seal_for_kdf::<Kem, HkdfSha384>(request, mode, randomness),
        HpkeKdfId::HkdfSha512 => seal_for_kdf::<Kem, HkdfSha512>(request, mode, randomness),
        HpkeKdfId::Shake256 => seal_for_kdf::<Kem, KdfShake256>(request, mode, randomness),
        HpkeKdfId::Shake128 | HpkeKdfId::TurboShake128 | HpkeKdfId::TurboShake256 => {
            Err(HpkeError::UnsupportedKdf)
        }
    }
}

fn seal_for_kdf<Kem, Kdf>(
    request: &HpkeSealRequest<'_>,
    mode: PskMode<'_>,
    randomness: &[u8],
) -> Result<HpkeSealOutput, HpkeError>
where
    Kem: HpkeKem,
    Kdf: HpkeKdf,
{
    match request.suite.aead {
        HpkeAeadId::Aes128Gcm => seal_for::<AesGcm128, Kdf, Kem>(request, mode, randomness),
        HpkeAeadId::Aes256Gcm => seal_for::<AesGcm256, Kdf, Kem>(request, mode, randomness),
        HpkeAeadId::ChaCha20Poly1305 => {
            seal_for::<ChaCha20Poly1305, Kdf, Kem>(request, mode, randomness)
        }
        HpkeAeadId::ExportOnly => Err(HpkeError::UnsupportedSuite),
    }
}

fn seal_for<Aead, Kdf, Kem>(
    request: &HpkeSealRequest<'_>,
    mode: PskMode<'_>,
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
    let psk_bundle = psk_bundle(mode)?;
    let operation_mode = match psk_bundle {
        Some(bundle) => OpModeS::Psk(bundle),
        None => OpModeS::Base,
    };
    let mut rng = FixedRandomness::new(randomness);
    let (encapsulated_key, ciphertext) = hpke::single_shot_seal_with_rng::<Aead, Kdf, Kem>(
        &operation_mode,
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

fn open_with_mode(
    request: &HpkeOpenRequest<'_>,
    mode: PskMode<'_>,
) -> Result<HpkeOpenOutput, HpkeError> {
    require_sealing_suite(request.suite)?;
    validate_encapsulated_key(request.suite, request.encapsulated_key)?;
    validate_private_key(request.suite, request.recipient_private_key)?;
    validate_ciphertext(request.suite, request.ciphertext)?;
    validate_key_schedule_inputs(request.info, psk_id(mode))?;

    match request.suite.kem {
        HpkeKemId::DhKemP256HkdfSha256 => open_for_kem::<DhP256HkdfSha256>(request, mode),
        HpkeKemId::DhKemP384HkdfSha384 => open_for_kem::<DhP384HkdfSha384>(request, mode),
        HpkeKemId::DhKemP521HkdfSha512 => open_for_kem::<DhP521HkdfSha512>(request, mode),
        HpkeKemId::DhKemSecp256k1HkdfSha256 => {
            open_for_kem::<DhKemSecp256k1HkdfSha256>(request, mode)
        }
        HpkeKemId::DhKemX25519HkdfSha256 => open_for_kem::<X25519HkdfSha256>(request, mode),
        HpkeKemId::DhKemX448HkdfSha512 => open_for_kem::<DhKemX448HkdfSha512>(request, mode),
        HpkeKemId::MlKem512 => open_for_kem::<MlKem512>(request, mode),
        HpkeKemId::MlKem768 => open_for_kem::<MlKem768>(request, mode),
        HpkeKemId::MlKem1024 => open_for_kem::<MlKem1024>(request, mode),
        HpkeKemId::MlKem768P256 => open_for_kem::<MlKem768P256>(request, mode),
        HpkeKemId::MlKem1024P384 => open_for_kem::<MlKem1024P384>(request, mode),
        HpkeKemId::XWing => open_for_kem::<XWing>(request, mode),
        HpkeKemId::DhKemCp256HkdfSha256
        | HpkeKemId::DhKemCp384HkdfSha384
        | HpkeKemId::DhKemCp521HkdfSha512
        | HpkeKemId::DhKemX25519ElligatorHkdfSha256
        | HpkeKemId::X25519Kyber768Draft00 => Err(HpkeError::UnsupportedKem),
    }
}

fn open_for_kem<Kem>(
    request: &HpkeOpenRequest<'_>,
    mode: PskMode<'_>,
) -> Result<HpkeOpenOutput, HpkeError>
where
    Kem: HpkeKem,
{
    match request.suite.kdf {
        HpkeKdfId::HkdfSha256 => open_for_kdf::<Kem, HkdfSha256>(request, mode),
        HpkeKdfId::HkdfSha384 => open_for_kdf::<Kem, HkdfSha384>(request, mode),
        HpkeKdfId::HkdfSha512 => open_for_kdf::<Kem, HkdfSha512>(request, mode),
        HpkeKdfId::Shake256 => open_for_kdf::<Kem, KdfShake256>(request, mode),
        HpkeKdfId::Shake128 | HpkeKdfId::TurboShake128 | HpkeKdfId::TurboShake256 => {
            Err(HpkeError::UnsupportedKdf)
        }
    }
}

fn open_for_kdf<Kem, Kdf>(
    request: &HpkeOpenRequest<'_>,
    mode: PskMode<'_>,
) -> Result<HpkeOpenOutput, HpkeError>
where
    Kem: HpkeKem,
    Kdf: HpkeKdf,
{
    match request.suite.aead {
        HpkeAeadId::Aes128Gcm => open_for::<AesGcm128, Kdf, Kem>(request, mode),
        HpkeAeadId::Aes256Gcm => open_for::<AesGcm256, Kdf, Kem>(request, mode),
        HpkeAeadId::ChaCha20Poly1305 => open_for::<ChaCha20Poly1305, Kdf, Kem>(request, mode),
        HpkeAeadId::ExportOnly => Err(HpkeError::UnsupportedSuite),
    }
}

fn open_for<Aead, Kdf, Kem>(
    request: &HpkeOpenRequest<'_>,
    mode: PskMode<'_>,
) -> Result<HpkeOpenOutput, HpkeError>
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
    let psk_bundle = psk_bundle(mode)?;
    let operation_mode = match psk_bundle {
        Some(bundle) => OpModeR::Psk(bundle),
        None => OpModeR::Base,
    };
    let plaintext = hpke::single_shot_open::<Aead, Kdf, Kem>(
        &operation_mode,
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

fn psk_id(mode: PskMode<'_>) -> &[u8] {
    match mode {
        PskMode::Base => &[],
        PskMode::Psk { psk_id, .. } => psk_id,
    }
}

fn psk_bundle(mode: PskMode<'_>) -> Result<Option<PskBundle<'_>>, HpkeError> {
    match mode {
        PskMode::Base => Ok(None),
        PskMode::Psk { psk, psk_id } => PskBundle::new(psk, psk_id)
            .map(Some)
            .map_err(|_| HpkeError::InvalidPsk),
    }
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
