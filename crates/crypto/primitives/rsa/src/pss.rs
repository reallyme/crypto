// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_bigint::BoxedUint;
use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use subtle::{Choice, ConstantTimeEq};

use crate::hash::{digest_len, digest_message, mgf1_xor};
use crate::key::validate_signature_length;
use crate::key::RsaPublicKey;
use crate::types::{RsaHash, RsaPssParams};

pub(crate) fn verify_pss(
    key: &RsaPublicKey,
    params: RsaPssParams,
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    validate_signature_length(key, signature)?;

    let m_hash = digest_message(params.message_hash, message);
    let em = recover_encoded_message(key, signature)?;
    verify_encoded_message(&m_hash, &em, key, params)
}

pub(crate) fn recover_encoded_message(
    key: &RsaPublicKey,
    signature: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let precision_bits = key
        .size()
        .checked_mul(8)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(signature_error)?;
    let sig_int =
        BoxedUint::from_be_slice(signature, precision_bits).map_err(|_| signature_error())?;
    if sig_int >= key.modulus() {
        return Err(signature_error());
    }

    let raw = sig_int.pow_mod(key.exponent(), &key.modulus_odd()?);
    let mut em = raw.to_be_bytes();
    let key_size = key.size();
    if em.len() > key_size {
        return Err(signature_error());
    }
    if em.len() < key_size {
        let pad_len = key_size.checked_sub(em.len()).ok_or_else(signature_error)?;
        let mut padded = Vec::with_capacity(key_size);
        padded.resize(pad_len, 0);
        padded.extend_from_slice(&em);
        em = padded.into_boxed_slice();
    }
    Ok(em.into_vec())
}

fn verify_encoded_message(
    m_hash: &[u8],
    em: &[u8],
    key: &RsaPublicKey,
    params: RsaPssParams,
) -> Result<(), CryptoError> {
    let h_len = digest_len(params.message_hash);
    if m_hash.len() != h_len {
        return Err(signature_error());
    }

    let em_bits = key
        .modulus_bits()
        .checked_sub(1)
        .ok_or_else(signature_error)?;
    let em_len = em.len();
    let min_len = h_len
        .checked_add(params.salt_len)
        .and_then(|value| value.checked_add(2))
        .ok_or_else(signature_error)?;
    if em_len < min_len || em.last().copied() != Some(0xbc) {
        return Err(signature_error());
    }

    let masked_db_len = em_len
        .checked_sub(h_len)
        .and_then(|value| value.checked_sub(1))
        .ok_or_else(signature_error)?;
    let (masked_db, h_and_trailer) = em.split_at(masked_db_len);
    let h = h_and_trailer.get(..h_len).ok_or_else(signature_error)?;

    let unused_bits = em_len
        .checked_mul(8)
        .and_then(|value| value.checked_sub(em_bits))
        .ok_or_else(signature_error)?;
    if unused_bits >= 8 {
        return Err(signature_error());
    }
    if unused_bits > 0 {
        let left_mask = 0xffu8
            .checked_shl(
                u32::try_from(
                    8usize
                        .checked_sub(unused_bits)
                        .ok_or_else(signature_error)?,
                )
                .map_err(|_| signature_error())?,
            )
            .ok_or_else(signature_error)?;
        let first_masked_byte = masked_db.first().copied().ok_or_else(signature_error)?;
        if first_masked_byte & left_mask != 0 {
            return Err(signature_error());
        }
    }

    let mut db = masked_db.to_vec();
    mgf1_xor(&mut db, params.mgf1_hash, h)?;
    if unused_bits > 0 {
        let keep_mask = 0xffu8
            .checked_shr(u32::try_from(unused_bits).map_err(|_| signature_error())?)
            .ok_or_else(signature_error)?;
        if let Some(first) = db.first_mut() {
            *first &= keep_mask;
        }
    }

    let ps_len = em_len
        .checked_sub(h_len)
        .and_then(|value| value.checked_sub(params.salt_len))
        .and_then(|value| value.checked_sub(2))
        .ok_or_else(signature_error)?;
    if db.get(ps_len).copied() != Some(0x01) {
        return Err(signature_error());
    }
    let padding_is_zero = bool::from(all_zero(&db[..ps_len]));
    if !padding_is_zero {
        return Err(signature_error());
    }
    let salt_start = ps_len.checked_add(1).ok_or_else(signature_error)?;
    let salt = db.get(salt_start..).ok_or_else(signature_error)?;
    if salt.len() != params.salt_len {
        return Err(signature_error());
    }

    let expected = pss_hash(params.message_hash, m_hash, salt);
    if bool::from(expected.ct_eq(h)) {
        Ok(())
    } else {
        Err(signature_error())
    }
}

fn pss_hash(hash: RsaHash, m_hash: &[u8], salt: &[u8]) -> Vec<u8> {
    let prefix = [0u8; 8];
    match hash {
        RsaHash::Sha1 => {
            let mut digest = Sha1::new();
            digest.update(prefix);
            digest.update(m_hash);
            digest.update(salt);
            digest.finalize().to_vec()
        }
        RsaHash::Sha256 => {
            let mut digest = Sha256::new();
            digest.update(prefix);
            digest.update(m_hash);
            digest.update(salt);
            digest.finalize().to_vec()
        }
        RsaHash::Sha384 => {
            let mut digest = Sha384::new();
            digest.update(prefix);
            digest.update(m_hash);
            digest.update(salt);
            digest.finalize().to_vec()
        }
        RsaHash::Sha512 => {
            let mut digest = Sha512::new();
            digest.update(prefix);
            digest.update(m_hash);
            digest.update(salt);
            digest.finalize().to_vec()
        }
    }
}

fn all_zero(bytes: &[u8]) -> Choice {
    bytes
        .iter()
        .fold(Choice::from(1), |acc, byte| acc & byte.ct_eq(&0))
}

fn signature_error() -> CryptoError {
    CryptoError::Signature {
        backend: SignatureBackend::Native,
        operation: SignatureOperation::Verify,
        kind: SignatureFailureKind::InvalidSignature,
    }
}
