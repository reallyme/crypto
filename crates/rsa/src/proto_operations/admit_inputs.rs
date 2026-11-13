// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Native RSA size admission before allocating copied request ownership.

use crate::{
    RsaPublicKeyDerEncoding, RSA_MIN_MODULUS_BITS, RSA_PUBLIC_KEY_DER_MAX_LEN,
    RSA_SIGNATURE_MAX_LEN,
};
use crypto_core::CryptoError;

pub(super) fn representatives(
    public_key_der: &[u8],
    encoding: RsaPublicKeyDerEncoding,
    signature: &[u8],
) -> Result<(), CryptoError> {
    admit(
        public_key_der,
        encoding,
        signature,
        CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY,
        CryptoError::PRIMITIVE_INVALID_LENGTH,
    )
}

pub(super) fn pss(
    public_key_der: &[u8],
    encoding: RsaPublicKeyDerEncoding,
    signature: &[u8],
) -> Result<(), CryptoError> {
    admit(
        public_key_der,
        encoding,
        signature,
        CryptoError::PRIMITIVE_INVALID_KEY,
        CryptoError::PRIMITIVE_INVALID_SIGNATURE,
    )
}

fn admit(
    public_key_der: &[u8],
    encoding: RsaPublicKeyDerEncoding,
    signature: &[u8],
    public_key_error: CryptoError,
    signature_error: CryptoError,
) -> Result<(), CryptoError> {
    if public_key_der.is_empty() || public_key_der.len() > RSA_PUBLIC_KEY_DER_MAX_LEN {
        return Err(public_key_error);
    }
    let bits_per_octet = usize::try_from(u8::BITS).map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    let rounding = bits_per_octet
        .checked_sub(1)
        .ok_or(CryptoError::BACKEND_INTERNAL)?;
    let minimum_signature_len = RSA_MIN_MODULUS_BITS
        .checked_add(rounding)
        .and_then(|bits| bits.checked_div(bits_per_octet))
        .ok_or(CryptoError::BACKEND_INTERNAL)?;
    if !(minimum_signature_len..=RSA_SIGNATURE_MAX_LEN).contains(&signature.len()) {
        // A malformed bounded DER key must retain precedence over an impossible
        // signature width. Reuse the existing bounded parser on this rejection
        // path; it may allocate bounded bigint storage, but no request bytes
        // are copied into adapter owners. Ordinary admission avoids parsing
        // twice, and the native operation still owns complete key validation.
        crate::key::parse_public_key(public_key_der, encoding).map_err(|error| {
            if error == CryptoError::PRIMITIVE_INVALID_KEY {
                public_key_error
            } else {
                error
            }
        })?;
        return Err(signature_error);
    }
    Ok(())
}
