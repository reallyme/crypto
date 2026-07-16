// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use core::convert::Infallible;

use hpke::{
    aead::{Aead as HpkeAead, AesGcm256, ChaCha20Poly1305},
    kdf::{HkdfSha256, Kdf as HpkeKdf},
    kem::{DhP256HkdfSha256, X25519HkdfSha256},
    rand_core::{utils::next_word_via_fill, TryCryptoRng, TryRng},
    Deserializable, Kem as HpkeKem, OpModeR, OpModeS, Serializable,
};
use zeroize::Zeroizing;

use crate::error::HpkeError;
#[cfg(feature = "test-vectors")]
use crate::types::HpkeDerandSealRequest;
use crate::types::{HpkeOpenOutput, HpkeOpenRequest, HpkeSealOutput, HpkeSealRequest};

/// Encrypts one message with RFC 9180 HPKE Base mode.
pub fn seal_base(request: &HpkeSealRequest<'_>) -> Result<HpkeSealOutput, HpkeError> {
    validate_public_key(request.suite, request.recipient_public_key)?;

    let mut randomness = Zeroizing::new(vec![0_u8; request.suite.private_key_len()]);
    getrandom::fill(randomness.as_mut_slice()).map_err(|_| HpkeError::SealFailed)?;

    match request.suite {
        crate::types::HpkeSuite::P256Sha256Aes256Gcm => {
            seal_base_for::<AesGcm256, HkdfSha256, DhP256HkdfSha256>(request, &randomness)
        }
        crate::types::HpkeSuite::X25519Sha256ChaCha20Poly1305 => {
            seal_base_for::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(request, &randomness)
        }
    }
}

/// Decrypts one message with RFC 9180 HPKE Base mode.
pub fn open_base(request: &HpkeOpenRequest<'_>) -> Result<HpkeOpenOutput, HpkeError> {
    validate_encapsulated_key(request.suite, request.encapsulated_key)?;
    validate_private_key(request.suite, request.recipient_private_key)?;
    validate_ciphertext(request.suite, request.ciphertext)?;

    match request.suite {
        crate::types::HpkeSuite::P256Sha256Aes256Gcm => {
            open_base_for::<AesGcm256, HkdfSha256, DhP256HkdfSha256>(request)
        }
        crate::types::HpkeSuite::X25519Sha256ChaCha20Poly1305 => {
            open_base_for::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(request)
        }
    }
}

/// Encrypts one Base-mode message with deterministic KEM randomness.
///
/// This function is compiled only for vector generation. HPKE production
/// callers must rely on provider randomness so KEM nonces cannot be reused.
#[cfg(feature = "test-vectors")]
pub fn seal_base_derand(request: &HpkeDerandSealRequest<'_>) -> Result<HpkeSealOutput, HpkeError> {
    if request.encapsulation_randomness.len() != request.suite.private_key_len() {
        return Err(HpkeError::InvalidRandomness);
    }
    validate_public_key(request.suite, request.recipient_public_key)?;

    let seal_request = HpkeSealRequest {
        suite: request.suite,
        recipient_public_key: request.recipient_public_key,
        info: request.info,
        aad: request.aad,
        plaintext: request.plaintext,
    };

    match request.suite {
        crate::types::HpkeSuite::P256Sha256Aes256Gcm => {
            seal_base_for::<AesGcm256, HkdfSha256, DhP256HkdfSha256>(
                &seal_request,
                request.encapsulation_randomness,
            )
        }
        crate::types::HpkeSuite::X25519Sha256ChaCha20Poly1305 => {
            seal_base_for::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
                &seal_request,
                request.encapsulation_randomness,
            )
        }
    }
}

fn seal_base_for<Aead, Kdf, Kem>(
    request: &HpkeSealRequest<'_>,
    randomness: &[u8],
) -> Result<HpkeSealOutput, HpkeError>
where
    Aead: HpkeAead,
    Kdf: HpkeKdf,
    Kem: HpkeKem,
{
    let ciphertext_len = request
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

    if rng.was_exhausted() {
        return Err(HpkeError::InvalidRandomness);
    }

    let encapsulated_key = encapsulated_key.to_bytes().as_slice().to_vec();
    if encapsulated_key.len() != request.suite.public_key_len()
        || ciphertext.len() != ciphertext_len
    {
        return Err(HpkeError::SealFailed);
    }
    Ok(HpkeSealOutput {
        encapsulated_key,
        ciphertext,
    })
}

fn open_base_for<Aead, Kdf, Kem>(request: &HpkeOpenRequest<'_>) -> Result<HpkeOpenOutput, HpkeError>
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

struct FixedRandomness<'a> {
    remaining: &'a [u8],
    exhausted: bool,
}

impl<'a> FixedRandomness<'a> {
    fn new(randomness: &'a [u8]) -> Self {
        Self {
            remaining: randomness,
            exhausted: false,
        }
    }

    fn was_exhausted(&self) -> bool {
        self.exhausted
    }
}

impl TryRng for FixedRandomness<'_> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        next_word_via_fill(self)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        next_word_via_fill(self)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        if dest.len() > self.remaining.len() {
            self.exhausted = true;
            dest.fill(0);
            return Ok(());
        }

        let (taken, rest) = self.remaining.split_at(dest.len());
        dest.copy_from_slice(taken);
        self.remaining = rest;
        Ok(())
    }
}

impl TryCryptoRng for FixedRandomness<'_> {}

fn validate_public_key(suite: crate::types::HpkeSuite, public_key: &[u8]) -> Result<(), HpkeError> {
    if public_key.len() != suite.public_key_len() {
        return Err(HpkeError::InvalidPublicKey);
    }
    Ok(())
}

fn validate_private_key(
    suite: crate::types::HpkeSuite,
    private_key: &[u8],
) -> Result<(), HpkeError> {
    if private_key.len() != suite.private_key_len() {
        return Err(HpkeError::InvalidPrivateKey);
    }
    Ok(())
}

fn validate_encapsulated_key(
    suite: crate::types::HpkeSuite,
    encapsulated_key: &[u8],
) -> Result<(), HpkeError> {
    if encapsulated_key.len() != suite.public_key_len() {
        return Err(HpkeError::InvalidEncapsulatedKey);
    }
    Ok(())
}

fn validate_ciphertext(suite: crate::types::HpkeSuite, ciphertext: &[u8]) -> Result<(), HpkeError> {
    if ciphertext.len() < suite.tag_len() {
        return Err(HpkeError::InvalidCiphertext);
    }
    Ok(())
}

fn map_seal_error(error: hpke::HpkeError) -> HpkeError {
    match error {
        hpke::HpkeError::ValidationError | hpke::HpkeError::IncorrectInputLength(_, _) => {
            HpkeError::InvalidPublicKey
        }
        hpke::HpkeError::EncapError
        | hpke::HpkeError::InvalidPskBundle
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
        hpke::HpkeError::DecapError
        | hpke::HpkeError::EncapError
        | hpke::HpkeError::InvalidPskBundle
        | hpke::HpkeError::KdfOutputTooLong
        | hpke::HpkeError::MessageLimitReached
        | hpke::HpkeError::OpenError
        | hpke::HpkeError::SealError => HpkeError::OpenFailed,
    }
}
