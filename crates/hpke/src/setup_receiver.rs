// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use hpke::aead::{Aead as HpkeAead, AeadCtxR, AesGcm128, AesGcm256, ChaCha20Poly1305};
use hpke::kdf::{HkdfSha256, HkdfSha384, HkdfSha512, Kdf as HpkeKdf, KdfShake256};
use hpke::kem::{
    DhP256HkdfSha256, DhP384HkdfSha384, DhP521HkdfSha512, MlKem1024, MlKem1024P384, MlKem768,
    MlKem768P256, X25519HkdfSha256, XWing,
};
use hpke::{Deserializable, Kem as HpkeKem, OpModeR, PskBundle};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::error::HpkeError;
use crate::identifiers::{HpkeAeadId, HpkeKdfId, HpkeKemId, HpkeSuite};
use crate::mlkem512::MlKem512;
use crate::secp256k1::DhKemSecp256k1HkdfSha256;
use crate::types::{HpkeOpenOutput, HpkePskIdRef, HpkePskRef};
use crate::validation::{
    require_sealing_suite, validate_encapsulated_key, validate_key_schedule_inputs,
    validate_private_key, validate_psk,
};
use crate::x448::DhKemX448HkdfSha512;

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

struct TypedReceiverContext<Aead, Kdf, Kem>
where
    Aead: HpkeAead,
    Kdf: HpkeKdf,
    Kem: HpkeKem,
{
    inner: AeadCtxR<Aead, Kdf, Kem>,
}

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

    match request.suite.kem {
        HpkeKemId::DhKemP256HkdfSha256 => setup_for_kem::<DhP256HkdfSha256>(request),
        HpkeKemId::DhKemP384HkdfSha384 => setup_for_kem::<DhP384HkdfSha384>(request),
        HpkeKemId::DhKemP521HkdfSha512 => setup_for_kem::<DhP521HkdfSha512>(request),
        HpkeKemId::DhKemSecp256k1HkdfSha256 => setup_for_kem::<DhKemSecp256k1HkdfSha256>(request),
        HpkeKemId::DhKemX25519HkdfSha256 => setup_for_kem::<X25519HkdfSha256>(request),
        HpkeKemId::DhKemX448HkdfSha512 => setup_for_kem::<DhKemX448HkdfSha512>(request),
        HpkeKemId::MlKem512 => setup_for_kem::<MlKem512>(request),
        HpkeKemId::MlKem768 => setup_for_kem::<MlKem768>(request),
        HpkeKemId::MlKem1024 => setup_for_kem::<MlKem1024>(request),
        HpkeKemId::MlKem768P256 => setup_for_kem::<MlKem768P256>(request),
        HpkeKemId::MlKem1024P384 => setup_for_kem::<MlKem1024P384>(request),
        HpkeKemId::XWing => setup_for_kem::<XWing>(request),
        HpkeKemId::DhKemCp256HkdfSha256
        | HpkeKemId::DhKemCp384HkdfSha384
        | HpkeKemId::DhKemCp521HkdfSha512
        | HpkeKemId::DhKemX25519ElligatorHkdfSha256
        | HpkeKemId::X25519Kyber768Draft00 => Err(HpkeError::UnsupportedKem),
    }
}

fn setup_for_kem<Kem>(
    request: &HpkePskReceiverSetupRequest<'_>,
) -> Result<HpkeReceiverContext, HpkeError>
where
    Kem: HpkeKem + 'static,
{
    match request.suite.kdf {
        HpkeKdfId::HkdfSha256 => setup_for_kdf::<Kem, HkdfSha256>(request),
        HpkeKdfId::HkdfSha384 => setup_for_kdf::<Kem, HkdfSha384>(request),
        HpkeKdfId::HkdfSha512 => setup_for_kdf::<Kem, HkdfSha512>(request),
        HpkeKdfId::Shake256 => setup_for_kdf::<Kem, KdfShake256>(request),
        HpkeKdfId::Shake128 | HpkeKdfId::TurboShake128 | HpkeKdfId::TurboShake256 => {
            Err(HpkeError::UnsupportedKdf)
        }
    }
}

fn setup_for_kdf<Kem, Kdf>(
    request: &HpkePskReceiverSetupRequest<'_>,
) -> Result<HpkeReceiverContext, HpkeError>
where
    Kem: HpkeKem + 'static,
    Kdf: HpkeKdf + 'static,
{
    match request.suite.aead {
        HpkeAeadId::Aes128Gcm => setup_for::<AesGcm128, Kdf, Kem>(request),
        HpkeAeadId::Aes256Gcm => setup_for::<AesGcm256, Kdf, Kem>(request),
        HpkeAeadId::ChaCha20Poly1305 => setup_for::<ChaCha20Poly1305, Kdf, Kem>(request),
        HpkeAeadId::ExportOnly => Err(HpkeError::UnsupportedSuite),
    }
}

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
