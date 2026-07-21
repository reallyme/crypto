// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#[cfg(any(
    feature = "aead-aes128-gcm",
    feature = "aead-aes256-gcm",
    feature = "aead-chacha20-poly1305"
))]
use hpke::aead::{Aead as HpkeAead, AeadCtxS};
use hpke::kdf::Kdf as HpkeKdf;
use hpke::Kem as HpkeKem;
#[cfg(any(
    feature = "aead-aes128-gcm",
    feature = "aead-aes256-gcm",
    feature = "aead-chacha20-poly1305"
))]
use hpke::{Deserializable, OpModeS, PskBundle, Serializable};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::error::HpkeError;
use crate::identifiers::HpkeSuite;
#[cfg(any(
    feature = "aead-aes128-gcm",
    feature = "aead-aes256-gcm",
    feature = "aead-chacha20-poly1305"
))]
use crate::random::FixedRandomness;
use crate::types::{HpkePskIdRef, HpkePskRef};
use crate::validation::{
    kem_parameters, require_sealing_suite, validate_key_schedule_inputs, validate_psk,
    validate_public_key,
};

/// Inputs required to establish an RFC 9180 PSK-mode sender context.
pub struct HpkePskSenderSetupRequest<'a> {
    /// Ciphersuite to use.
    pub suite: HpkeSuite,
    /// Encoded recipient public key.
    pub recipient_public_key: &'a [u8],
    /// RFC 9180 `info` value.
    pub info: &'a [u8],
    /// High-entropy pre-shared key.
    pub psk: HpkePskRef<'a>,
    /// Application identifier for the pre-shared key.
    pub psk_id: HpkePskIdRef<'a>,
}

/// Deterministic PSK-mode sender setup request for conformance vectors.
#[cfg(feature = "test-vectors")]
pub struct HpkeDerandPskSenderSetupRequest<'a> {
    /// Ciphersuite to use.
    pub suite: HpkeSuite,
    /// Encoded recipient public key.
    pub recipient_public_key: &'a [u8],
    /// Suite-specific randomness consumed by the HPKE KEM.
    pub encapsulation_randomness: &'a [u8],
    /// RFC 9180 `info` value.
    pub info: &'a [u8],
    /// High-entropy pre-shared key.
    pub psk: HpkePskRef<'a>,
    /// Application identifier for the pre-shared key.
    pub psk_id: HpkePskIdRef<'a>,
}

/// Result of establishing an HPKE PSK-mode sender context.
pub struct HpkePskSenderSetupOutput {
    /// Encapsulated key that the caller can bind into message AAD.
    pub encapsulated_key: Vec<u8>,
    /// Live sender context containing traffic key, nonce, and sequence state.
    pub context: HpkePskSenderContext,
}

trait SenderContextBackend {
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, hpke::HpkeError>;
}

#[cfg(any(
    feature = "aead-aes128-gcm",
    feature = "aead-aes256-gcm",
    feature = "aead-chacha20-poly1305"
))]
struct TypedSenderContext<Aead, Kdf, Kem>
where
    Aead: HpkeAead,
    Kdf: HpkeKdf,
    Kem: HpkeKem,
{
    inner: AeadCtxS<Aead, Kdf, Kem>,
}

#[cfg(any(
    feature = "aead-aes128-gcm",
    feature = "aead-aes256-gcm",
    feature = "aead-chacha20-poly1305"
))]
impl<Aead, Kdf, Kem> SenderContextBackend for TypedSenderContext<Aead, Kdf, Kem>
where
    Aead: HpkeAead,
    Kdf: HpkeKdf,
    Kem: HpkeKem,
{
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, hpke::HpkeError> {
        self.inner.seal(plaintext, aad)
    }
}

/// Owned HPKE PSK-mode sender context.
///
/// The context is deliberately neither cloneable nor serializable. Its backend
/// owns the traffic key, base nonce, exporter secret, and sequence counter; the
/// backend zeroizes those values during destruction. Keeping this owner opaque
/// prevents adapters from exporting or reconstructing live HPKE state.
pub struct HpkeSenderContext {
    backend: Box<dyn SenderContextBackend>,
    authentication_tag_len: usize,
}

// The erased backend retains the concrete HPKE context, whose key, nonce,
// exporter secret, and counter fields each zeroize on drop. This marker records
// that destruction contract without exposing those fields through this API.
impl ZeroizeOnDrop for HpkeSenderContext {}

impl HpkeSenderContext {
    /// Encrypts one message and advances the context sequence number.
    ///
    /// `aad` is accepted at seal time so callers can construct it after they
    /// receive the encapsulated key from sender setup.
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, HpkeError> {
        let expected_length = plaintext
            .len()
            .checked_add(self.authentication_tag_len)
            .ok_or(HpkeError::LengthOverflow)?;
        let ciphertext = self
            .backend
            .seal(aad, plaintext)
            .map_err(map_context_seal_error)?;
        if ciphertext.len() != expected_length {
            return Err(HpkeError::SealFailed);
        }
        Ok(ciphertext)
    }
}

/// Compatibility name for the PSK-mode sender context.
pub type HpkePskSenderContext = HpkeSenderContext;

/// Establishes an RFC 9180 PSK-mode sender context with fresh KEM randomness.
pub fn setup_sender_psk(
    request: &HpkePskSenderSetupRequest<'_>,
) -> Result<HpkePskSenderSetupOutput, HpkeError> {
    let randomness_length = request.suite.encapsulation_randomness_len()?;
    let mut randomness = Zeroizing::new(vec![0_u8; randomness_length]);
    getrandom::fill(randomness.as_mut_slice()).map_err(|_| HpkeError::RandomnessUnavailable)?;
    setup_sender_psk_with_randomness(request, randomness.as_slice())
}

/// Establishes a PSK-mode sender context with deterministic KEM randomness.
#[cfg(feature = "test-vectors")]
pub fn setup_sender_psk_derand(
    request: &HpkeDerandPskSenderSetupRequest<'_>,
) -> Result<HpkePskSenderSetupOutput, HpkeError> {
    let setup_request = HpkePskSenderSetupRequest {
        suite: request.suite,
        recipient_public_key: request.recipient_public_key,
        info: request.info,
        psk: HpkePskRef::new(request.psk.as_slice())?,
        psk_id: HpkePskIdRef::new(request.psk_id.as_slice())?,
    };
    setup_sender_psk_with_randomness(&setup_request, request.encapsulation_randomness)
}

pub(crate) fn setup_sender_psk_with_randomness(
    request: &HpkePskSenderSetupRequest<'_>,
    randomness: &[u8],
) -> Result<HpkePskSenderSetupOutput, HpkeError> {
    require_sealing_suite(request.suite)?;
    validate_public_key(request.suite, request.recipient_public_key)?;
    validate_psk(request.psk.as_slice(), request.psk_id.as_slice())?;
    validate_key_schedule_inputs(request.info, request.psk_id.as_slice())?;
    if randomness.len() != kem_parameters(request.suite.kem)?.encapsulation_randomness_len {
        return Err(HpkeError::InvalidRandomness);
    }

    dispatch_kem!(request.suite.kem, setup_for_kem, request, randomness)
}

fn setup_for_kem<Kem>(
    request: &HpkePskSenderSetupRequest<'_>,
    randomness: &[u8],
) -> Result<HpkePskSenderSetupOutput, HpkeError>
where
    Kem: HpkeKem + 'static,
{
    dispatch_kdf!(request.suite.kdf, setup_for_kdf, Kem, request, randomness)
}

fn setup_for_kdf<Kem, Kdf>(
    request: &HpkePskSenderSetupRequest<'_>,
    _randomness: &[u8],
) -> Result<HpkePskSenderSetupOutput, HpkeError>
where
    Kem: HpkeKem + 'static,
    Kdf: HpkeKdf + 'static,
{
    dispatch_sealing_aead!(
        request.suite.aead,
        setup_for,
        Kdf,
        Kem,
        request,
        _randomness
    )
}

#[cfg(any(
    feature = "aead-aes128-gcm",
    feature = "aead-aes256-gcm",
    feature = "aead-chacha20-poly1305"
))]
fn setup_for<Aead, Kdf, Kem>(
    request: &HpkePskSenderSetupRequest<'_>,
    randomness: &[u8],
) -> Result<HpkePskSenderSetupOutput, HpkeError>
where
    Aead: HpkeAead + 'static,
    Kdf: HpkeKdf + 'static,
    Kem: HpkeKem + 'static,
{
    let recipient_public_key =
        <Kem::PublicKey as Deserializable>::from_bytes(request.recipient_public_key)
            .map_err(|_| HpkeError::InvalidPublicKey)?;
    let psk_bundle = PskBundle::new(request.psk.as_slice(), request.psk_id.as_slice())
        .map_err(|_| HpkeError::InvalidPsk)?;
    let operation_mode = OpModeS::Psk(psk_bundle);
    let mut rng = FixedRandomness::new(randomness);
    let (encapsulated_key, context) = hpke::setup_sender_with_rng::<Aead, Kdf, Kem>(
        &operation_mode,
        &recipient_public_key,
        request.info,
        &mut rng,
    )
    .map_err(map_setup_error)?;

    if !rng.was_consumed_exactly() {
        return Err(HpkeError::InvalidRandomness);
    }
    let encapsulated_key = encapsulated_key.to_bytes().as_slice().to_vec();
    if encapsulated_key.len() != kem_parameters(request.suite.kem)?.encapsulated_key_len {
        return Err(HpkeError::SealFailed);
    }

    Ok(HpkePskSenderSetupOutput {
        encapsulated_key,
        context: HpkeSenderContext {
            backend: Box::new(TypedSenderContext { inner: context }),
            authentication_tag_len: request.suite.tag_len(),
        },
    })
}

#[cfg(any(
    feature = "aead-aes128-gcm",
    feature = "aead-aes256-gcm",
    feature = "aead-chacha20-poly1305"
))]
fn map_setup_error(error: hpke::HpkeError) -> HpkeError {
    match error {
        hpke::HpkeError::ValidationError | hpke::HpkeError::IncorrectInputLength(_, _) => {
            HpkeError::InvalidPublicKey
        }
        hpke::HpkeError::InvalidPskBundle => HpkeError::InvalidPsk,
        hpke::HpkeError::EncapError
        | hpke::HpkeError::DecapError
        | hpke::HpkeError::KdfOutputTooLong
        | hpke::HpkeError::MessageLimitReached
        | hpke::HpkeError::OpenError
        | hpke::HpkeError::SealError => HpkeError::SealFailed,
    }
}

fn map_context_seal_error(error: hpke::HpkeError) -> HpkeError {
    match error {
        hpke::HpkeError::InvalidPskBundle
        | hpke::HpkeError::ValidationError
        | hpke::HpkeError::IncorrectInputLength(_, _)
        | hpke::HpkeError::EncapError
        | hpke::HpkeError::DecapError
        | hpke::HpkeError::KdfOutputTooLong
        | hpke::HpkeError::MessageLimitReached
        | hpke::HpkeError::OpenError
        | hpke::HpkeError::SealError => HpkeError::SealFailed,
    }
}
