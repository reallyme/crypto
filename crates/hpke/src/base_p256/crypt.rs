// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use hpke::{aead::AeadTag, Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
use zeroize::Zeroizing;

use super::{
    storage, Aead, Kdf, Kem, P256BaseError, P256BasePlaintext, P256BaseRng, P256RecipientKey,
    SystemRandom, INFO_MAX_LEN, PLAINTEXT_MAX_LEN, PRIVATE_KEY_LEN, PUBLIC_KEY_LEN, TAG_LEN,
};
use crate::random::FixedRandomness;

const UNCOMPRESSED_POINT_PREFIX: u8 = 0x04;

/// Separate RFC 9180 `enc` and ciphertext-with-tag; no application envelope.
pub struct P256BaseSealed {
    /// A 65-byte uncompressed ephemeral P-256 public key.
    pub enc: [u8; PUBLIC_KEY_LEN],
    /// AES-128-GCM ciphertext followed by its 16-byte tag.
    pub ciphertext: Vec<u8>,
}

/// Encrypt one record with fresh OS entropy, exact `info`, and empty AAD.
pub fn seal(public: &[u8], info: &[u8], plaintext: &[u8]) -> Result<P256BaseSealed, P256BaseError> {
    seal_with_rng(public, info, plaintext, &mut SystemRandom)
}

/// Encrypt one record with injected entropy. Inputs are validated before
/// entropy is requested or plaintext is copied into clearing storage.
pub fn seal_with_rng(
    public: &[u8],
    info: &[u8],
    plaintext: &[u8],
    rng: &mut impl P256BaseRng,
) -> Result<P256BaseSealed, P256BaseError> {
    validate_bounds(info, plaintext.len())?;
    validate_point_encoding(public).map_err(|_| P256BaseError::InvalidPublicKey)?;
    let public = <Kem as KemTrait>::PublicKey::from_bytes(public)
        .map_err(|_| P256BaseError::InvalidPublicKey)?;
    let ciphertext_length = plaintext
        .len()
        .checked_add(TAG_LEN)
        .ok_or(P256BaseError::InputTooLong)?;
    let mut ciphertext = storage::buffer(ciphertext_length)?;
    let mut randomness = Zeroizing::new([0; PRIVATE_KEY_LEN]);
    rng.fill(randomness.as_mut_slice())
        .map_err(|_| P256BaseError::RandomnessUnavailable)?;
    let mut fixed = FixedRandomness::new(randomness.as_slice());
    let (enc, mut context) =
        hpke::setup_sender_with_rng::<Aead, Kdf, Kem>(&OpModeS::Base, &public, info, &mut fixed)
            .map_err(|_| P256BaseError::ProviderFailed)?;
    if !fixed.was_consumed_exactly() {
        return Err(P256BaseError::ProviderFailed);
    }
    let (message, tag_storage) = ciphertext.split_at_mut(plaintext.len());
    message.copy_from_slice(plaintext);
    let tag = context
        .seal_inout_detached(message.into(), &[])
        .map_err(|_| P256BaseError::ProviderFailed)?;
    tag_storage.copy_from_slice(tag.to_bytes().as_slice());
    let mut encoded = [0; PUBLIC_KEY_LEN];
    enc.write_exact(&mut encoded);
    Ok(P256BaseSealed {
        enc: encoded,
        ciphertext: core::mem::take(&mut *ciphertext),
    })
}

/// Open one record, exposing plaintext only after the complete tag verifies.
/// Clearing storage owns the copied ciphertext before the backend can write
/// unauthenticated plaintext, including on authentication failure or unwind.
pub fn open(
    recipient: &P256RecipientKey,
    enc: &[u8],
    info: &[u8],
    ciphertext: &[u8],
) -> Result<P256BasePlaintext, P256BaseError> {
    let plaintext_length = ciphertext
        .len()
        .checked_sub(TAG_LEN)
        .ok_or(P256BaseError::TruncatedCiphertext)?;
    validate_bounds(info, plaintext_length)?;
    validate_point_encoding(enc)?;
    let enc = <Kem as KemTrait>::EncappedKey::from_bytes(enc)
        .map_err(|_| P256BaseError::InvalidEncapsulatedKey)?;
    let private = <Kem as KemTrait>::PrivateKey::from_bytes(recipient.private_key())
        .map_err(|_| P256BaseError::InvalidPrivateKey)?;
    let tag = AeadTag::<Aead>::from_bytes(&ciphertext[plaintext_length..])
        .map_err(|_| P256BaseError::TruncatedCiphertext)?;
    let mut context = hpke::setup_receiver::<Aead, Kdf, Kem>(&OpModeR::Base, &private, &enc, info)
        .map_err(|_| P256BaseError::AuthenticationFailed)?;
    let mut plaintext = storage::buffer(plaintext_length)?;
    plaintext.copy_from_slice(&ciphertext[..plaintext_length]);
    context
        .open_inout_detached(plaintext.as_mut_slice().into(), &[], &tag)
        .map_err(|_| P256BaseError::AuthenticationFailed)?;
    Ok(P256BasePlaintext::new(plaintext))
}

fn validate_point_encoding(point: &[u8]) -> Result<(), P256BaseError> {
    if point.len() != PUBLIC_KEY_LEN || point.first() != Some(&UNCOMPRESSED_POINT_PREFIX) {
        return Err(P256BaseError::InvalidEncapsulatedKey);
    }
    Ok(())
}

fn validate_bounds(info: &[u8], plaintext_length: usize) -> Result<(), P256BaseError> {
    if info.len() > INFO_MAX_LEN || plaintext_length > PLAINTEXT_MAX_LEN {
        return Err(P256BaseError::InputTooLong);
    }
    Ok(())
}
