// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#[cfg(any(
    feature = "aead-aes128-gcm",
    feature = "aead-aes256-gcm",
    feature = "aead-chacha20-poly1305"
))]
use hpke::aead::{Aead as HpkeAead, AeadCtxR};
use hpke::kdf::Kdf as HpkeKdf;
use hpke::Kem as HpkeKem;
#[cfg(any(
    feature = "aead-aes128-gcm",
    feature = "aead-aes256-gcm",
    feature = "aead-chacha20-poly1305"
))]
use hpke::{Deserializable, OpModeR, PskBundle};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::error::HpkeError;
use crate::identifiers::HpkeSuite;
use crate::types::{HpkeOpenOutput, HpkePskIdRef, HpkePskRef};
use crate::validation::{
    require_sealing_suite, validate_encapsulated_key, validate_key_schedule_inputs,
    validate_private_key, validate_psk,
};

/// Inputs required to establish an RFC 9180 PSK-mode receiver context.
pub struct HpkePskReceiverSetupRequest<'a> {
    /// Ciphersuite to use.
    pub suite: HpkeSuite,
    /// Encapsulated key produced by sender setup.
    pub encapsulated_key: &'a [u8],
    /// Encoded recipient private key.
    pub recipient_private_key: &'a [u8],
    /// RFC 9180 `info` value.
    pub info: &'a [u8],
    /// Validated high-entropy pre-shared key.
    pub psk: HpkePskRef<'a>,
    /// Validated application identifier for the pre-shared key.
    pub psk_id: HpkePskIdRef<'a>,
}

trait ReceiverContextBackend {
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, hpke::HpkeError>;
}

#[cfg(any(
    feature = "aead-aes128-gcm",
    feature = "aead-aes256-gcm",
    feature = "aead-chacha20-poly1305"
))]
struct TypedReceiverContext<Aead, Kdf, Kem>
where
    Aead: HpkeAead,
    Kdf: HpkeKdf,
    Kem: HpkeKem,
{
    inner: AeadCtxR<Aead, Kdf, Kem>,
}

#[cfg(any(
    feature = "aead-aes128-gcm",
    feature = "aead-aes256-gcm",
    feature = "aead-chacha20-poly1305"
))]
impl<Aead, Kdf, Kem> ReceiverContextBackend for TypedReceiverContext<Aead, Kdf, Kem>
where
    Aead: HpkeAead,
    Kdf: HpkeKdf,
    Kem: HpkeKem,
{
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, hpke::HpkeError> {
        self.inner.open(ciphertext, aad)
    }
}

/// Owned HPKE receiver context.
///
/// The context is deliberately neither cloneable nor serializable. Its erased
/// backend owns the traffic key, base nonce, exporter secret, and sequence
/// counter and zeroizes that state during destruction.
pub struct HpkeReceiverContext {
    backend: Box<dyn ReceiverContextBackend>,
    authentication_tag_len: usize,
}

// The erased backend retains the concrete HPKE context, whose secret state
// zeroizes on drop. The marker exposes that destruction contract to adapters
// without making the underlying state accessible.
impl ZeroizeOnDrop for HpkeReceiverContext {}

impl HpkeReceiverContext {
    /// Authenticates and decrypts one message and advances the sequence number.
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<HpkeOpenOutput, HpkeError> {
        let expected_plaintext_length = ciphertext
            .len()
            .checked_sub(self.authentication_tag_len)
            .ok_or(HpkeError::InvalidCiphertext)?;
        let plaintext = self
            .backend
            .open(aad, ciphertext)
            .map_err(map_context_open_error)?;
        if plaintext.len() != expected_plaintext_length {
            return Err(HpkeError::OpenFailed);
        }
        Ok(HpkeOpenOutput {
            plaintext: Zeroizing::new(plaintext),
        })
    }
}

/// Establishes an RFC 9180 PSK-mode receiver context.
pub fn setup_receiver_psk(
    request: &HpkePskReceiverSetupRequest<'_>,
) -> Result<HpkeReceiverContext, HpkeError> {
    require_sealing_suite(request.suite)?;
    validate_encapsulated_key(request.suite, request.encapsulated_key)?;
    validate_private_key(request.suite, request.recipient_private_key)?;
    validate_psk(request.psk.as_slice(), request.psk_id.as_slice())?;
    validate_key_schedule_inputs(request.info, request.psk_id.as_slice())?;

    dispatch_kem!(request.suite.kem, setup_for_kem, request)
}

fn setup_for_kem<Kem>(
    request: &HpkePskReceiverSetupRequest<'_>,
) -> Result<HpkeReceiverContext, HpkeError>
where
    Kem: HpkeKem + 'static,
{
    dispatch_kdf!(request.suite.kdf, setup_for_kdf, Kem, request)
}

fn setup_for_kdf<Kem, Kdf>(
    request: &HpkePskReceiverSetupRequest<'_>,
) -> Result<HpkeReceiverContext, HpkeError>
where
    Kem: HpkeKem + 'static,
    Kdf: HpkeKdf + 'static,
{
    dispatch_sealing_aead!(request.suite.aead, setup_for, Kdf, Kem, request)
}

#[cfg(any(
    feature = "aead-aes128-gcm",
    feature = "aead-aes256-gcm",
    feature = "aead-chacha20-poly1305"
))]
fn setup_for<Aead, Kdf, Kem>(
    request: &HpkePskReceiverSetupRequest<'_>,
) -> Result<HpkeReceiverContext, HpkeError>
where
    Aead: HpkeAead + 'static,
    Kdf: HpkeKdf + 'static,
    Kem: HpkeKem + 'static,
{
    let recipient_private_key =
        <Kem::PrivateKey as Deserializable>::from_bytes(request.recipient_private_key)
            .map_err(|_| HpkeError::InvalidPrivateKey)?;
    let encapsulated_key =
        <Kem::EncappedKey as Deserializable>::from_bytes(request.encapsulated_key)
            .map_err(|_| HpkeError::InvalidEncapsulatedKey)?;
    let psk_bundle = PskBundle::new(request.psk.as_slice(), request.psk_id.as_slice())
        .map_err(|_| HpkeError::InvalidPsk)?;
    let context = hpke::setup_receiver::<Aead, Kdf, Kem>(
        &OpModeR::Psk(psk_bundle),
        &recipient_private_key,
        &encapsulated_key,
        request.info,
    )
    .map_err(map_setup_error)?;

    Ok(HpkeReceiverContext {
        backend: Box::new(TypedReceiverContext { inner: context }),
        authentication_tag_len: request.suite.tag_len(),
    })
}

#[cfg(any(
    feature = "aead-aes128-gcm",
    feature = "aead-aes256-gcm",
    feature = "aead-chacha20-poly1305"
))]
fn map_setup_error(error: hpke::HpkeError) -> HpkeError {
    match error {
        hpke::HpkeError::ValidationError
        | hpke::HpkeError::IncorrectInputLength(_, _)
        | hpke::HpkeError::DecapError => HpkeError::InvalidEncapsulatedKey,
        hpke::HpkeError::InvalidPskBundle => HpkeError::InvalidPsk,
        hpke::HpkeError::EncapError
        | hpke::HpkeError::KdfOutputTooLong
        | hpke::HpkeError::MessageLimitReached
        | hpke::HpkeError::OpenError
        | hpke::HpkeError::SealError => HpkeError::OpenFailed,
    }
}

fn map_context_open_error(error: hpke::HpkeError) -> HpkeError {
    match error {
        hpke::HpkeError::InvalidPskBundle
        | hpke::HpkeError::ValidationError
        | hpke::HpkeError::IncorrectInputLength(_, _)
        | hpke::HpkeError::EncapError
        | hpke::HpkeError::DecapError
        | hpke::HpkeError::KdfOutputTooLong
        | hpke::HpkeError::MessageLimitReached
        | hpke::HpkeError::OpenError
        | hpke::HpkeError::SealError => HpkeError::OpenFailed,
    }
}
