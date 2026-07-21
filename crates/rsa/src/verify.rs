// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::hash::digest_message;
use crate::key::{parse_public_key, validate_signature_length, RsaPublicKey};
use crate::pss::verify_pss;
use crate::types::{RsaHash, RsaPssParams, RsaPublicKeyDerEncoding};

/// Verifies an RSASSA-PKCS1-v1_5 signature.
pub fn verify_rsa_pkcs1v15(
    public_key_der: &[u8],
    encoding: RsaPublicKeyDerEncoding,
    hash: RsaHash,
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let key = parse_public_key(public_key_der, encoding)?;
    validate_signature_length(&key, signature)?;
    verify_pkcs1v15_with_key(&key, hash, message, signature)
}

/// Verifies an RSASSA-PSS signature.
///
/// PSS allows the message hash and MGF1 hash to be encoded independently in
/// X.509/CMS parameters. This function preserves that distinction instead of
/// silently assuming they are identical.
pub fn verify_rsa_pss(
    public_key_der: &[u8],
    encoding: RsaPublicKeyDerEncoding,
    params: RsaPssParams,
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let key = parse_public_key(public_key_der, encoding)?;
    verify_pss(&key, params, message, signature)
}

fn verify_pkcs1v15_with_key(
    key: &RsaPublicKey,
    hash: RsaHash,
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let digest = Zeroizing::new(digest_message(hash, message));
    let encoded_message = crate::pss::recover_encoded_message(key, signature)?;
    verify_pkcs1v15_encoded_message(hash, &digest, &encoded_message)
}

fn verify_pkcs1v15_encoded_message(
    hash: RsaHash,
    digest: &[u8],
    encoded_message: &[u8],
) -> Result<(), CryptoError> {
    let digest_info_prefix = digest_info_prefix(hash);
    let digest_info_len = digest_info_prefix
        .len()
        .checked_add(digest.len())
        .ok_or_else(signature_error)?;
    let minimum_len = digest_info_len
        .checked_add(11)
        .ok_or_else(signature_error)?;
    if encoded_message.len() < minimum_len {
        return Err(signature_error());
    }
    if encoded_message.first().copied() != Some(0x00)
        || encoded_message.get(1).copied() != Some(0x01)
    {
        return Err(signature_error());
    }

    let padding_end = encoded_message
        .len()
        .checked_sub(digest_info_len)
        .and_then(|value| value.checked_sub(1))
        .ok_or_else(signature_error)?;
    if padding_end < 10 {
        return Err(signature_error());
    }
    let padding = encoded_message
        .get(2..padding_end)
        .ok_or_else(signature_error)?;
    if padding.iter().any(|byte| *byte != 0xff) {
        return Err(signature_error());
    }
    if encoded_message.get(padding_end).copied() != Some(0x00) {
        return Err(signature_error());
    }

    let digest_info_start = padding_end.checked_add(1).ok_or_else(signature_error)?;
    let digest_info = encoded_message
        .get(digest_info_start..)
        .ok_or_else(signature_error)?;
    let expected_len = digest_info_prefix
        .len()
        .checked_add(digest.len())
        .ok_or_else(signature_error)?;
    if digest_info.len() != expected_len {
        return Err(signature_error());
    }
    let (actual_prefix, actual_digest) = digest_info.split_at(digest_info_prefix.len());
    if bool::from(actual_prefix.ct_eq(digest_info_prefix))
        && bool::from(actual_digest.ct_eq(digest))
    {
        Ok(())
    } else {
        Err(signature_error())
    }
}

fn digest_info_prefix(hash: RsaHash) -> &'static [u8] {
    match hash {
        RsaHash::Sha1 => &[
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
            0x14,
        ],
        RsaHash::Sha256 => &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ],
        RsaHash::Sha384 => &[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x02, 0x05, 0x00, 0x04, 0x30,
        ],
        RsaHash::Sha512 => &[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
        ],
    }
}

fn signature_error() -> CryptoError {
    CryptoError::Signature {
        backend: SignatureBackend::Native,
        operation: SignatureOperation::Verify,
        kind: SignatureFailureKind::InvalidSignature,
    }
}
