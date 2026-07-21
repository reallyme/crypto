// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use hpke::aead::{Aead as HpkeAead, AeadCtxS, AesGcm128, AesGcm256, ChaCha20Poly1305};
use hpke::kdf::{HkdfSha256, HkdfSha384, HkdfSha512, Kdf as HpkeKdf, KdfShake256};
use hpke::kem::{
    DhP256HkdfSha256, DhP384HkdfSha384, DhP521HkdfSha512, MlKem1024, MlKem1024P384, MlKem768,
    MlKem768P256, X25519HkdfSha256, XWing,
};
use hpke::{Deserializable, Kem as HpkeKem, OpModeS, PskBundle, Serializable};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::error::HpkeError;
use crate::identifiers::{HpkeAeadId, HpkeKdfId, HpkeKemId, HpkeSuite};
use crate::mlkem512::MlKem512;
use crate::random::FixedRandomness;
use crate::secp256k1::DhKemSecp256k1HkdfSha256;
use crate::types::{HpkePskIdRef, HpkePskRef};
use crate::validation::{
    kem_parameters, require_sealing_suite, validate_key_schedule_inputs, validate_psk,
    validate_public_key,
};
use crate::x448::DhKemX448HkdfSha512;

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

struct TypedSenderContext<Aead, Kdf, Kem>
where
    Aead: HpkeAead,
    Kdf: HpkeKdf,
    Kem: HpkeKem,
{
    inner: AeadCtxS<Aead, Kdf, Kem>,
}

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

    match request.suite.kem {
        HpkeKemId::DhKemP256HkdfSha256 => setup_for_kem::<DhP256HkdfSha256>(request, randomness),
        HpkeKemId::DhKemP384HkdfSha384 => setup_for_kem::<DhP384HkdfSha384>(request, randomness),
        HpkeKemId::DhKemP521HkdfSha512 => setup_for_kem::<DhP521HkdfSha512>(request, randomness),
        HpkeKemId::DhKemSecp256k1HkdfSha256 => {
            setup_for_kem::<DhKemSecp256k1HkdfSha256>(request, randomness)
        }
        HpkeKemId::DhKemX25519HkdfSha256 => setup_for_kem::<X25519HkdfSha256>(request, randomness),
        HpkeKemId::DhKemX448HkdfSha512 => setup_for_kem::<DhKemX448HkdfSha512>(request, randomness),
        HpkeKemId::MlKem512 => setup_for_kem::<MlKem512>(request, randomness),
        HpkeKemId::MlKem768 => setup_for_kem::<MlKem768>(request, randomness),
        HpkeKemId::MlKem1024 => setup_for_kem::<MlKem1024>(request, randomness),
        HpkeKemId::MlKem768P256 => setup_for_kem::<MlKem768P256>(request, randomness),
        HpkeKemId::MlKem1024P384 => setup_for_kem::<MlKem1024P384>(request, randomness),
        HpkeKemId::XWing => setup_for_kem::<XWing>(request, randomness),
        HpkeKemId::DhKemCp256HkdfSha256
        | HpkeKemId::DhKemCp384HkdfSha384
        | HpkeKemId::DhKemCp521HkdfSha512
        | HpkeKemId::DhKemX25519ElligatorHkdfSha256
        | HpkeKemId::X25519Kyber768Draft00 => Err(HpkeError::UnsupportedKem),
    }
}

fn setup_for_kem<Kem>(
    request: &HpkePskSenderSetupRequest<'_>,
    randomness: &[u8],
) -> Result<HpkePskSenderSetupOutput, HpkeError>
where
    Kem: HpkeKem + 'static,
{
    match request.suite.kdf {
        HpkeKdfId::HkdfSha256 => setup_for_kdf::<Kem, HkdfSha256>(request, randomness),
        HpkeKdfId::HkdfSha384 => setup_for_kdf::<Kem, HkdfSha384>(request, randomness),
        HpkeKdfId::HkdfSha512 => setup_for_kdf::<Kem, HkdfSha512>(request, randomness),
        HpkeKdfId::Shake256 => setup_for_kdf::<Kem, KdfShake256>(request, randomness),
        HpkeKdfId::Shake128 | HpkeKdfId::TurboShake128 | HpkeKdfId::TurboShake256 => {
            Err(HpkeError::UnsupportedKdf)
        }
    }
}

fn setup_for_kdf<Kem, Kdf>(
    request: &HpkePskSenderSetupRequest<'_>,
    randomness: &[u8],
) -> Result<HpkePskSenderSetupOutput, HpkeError>
where
    Kem: HpkeKem + 'static,
    Kdf: HpkeKdf + 'static,
{
    match request.suite.aead {
        HpkeAeadId::Aes128Gcm => setup_for::<AesGcm128, Kdf, Kem>(request, randomness),
        HpkeAeadId::Aes256Gcm => setup_for::<AesGcm256, Kdf, Kem>(request, randomness),
        HpkeAeadId::ChaCha20Poly1305 => {
            setup_for::<ChaCha20Poly1305, Kdf, Kem>(request, randomness)
        }
        HpkeAeadId::ExportOnly => Err(HpkeError::UnsupportedSuite),
    }
}

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
