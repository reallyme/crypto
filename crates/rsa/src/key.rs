// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use const_oid::db::rfc5912::RSA_ENCRYPTION;
use crypto_bigint::{BoxedUint, Odd};
use crypto_core::CryptoError;
use spki::{
    der::{asn1::UintRef, Decode, DecodeValue, Header, Reader, Sequence},
    SubjectPublicKeyInfoRef,
};
use zeroize::Zeroize;

use crate::constants::{
    RSA_MAX_EXPONENT_BITS, RSA_MAX_MODULUS_BITS, RSA_MIN_EXPONENT_BITS, RSA_MIN_MODULUS_BITS,
    RSA_PUBLIC_KEY_DER_MAX_LEN,
};
use crate::types::RsaPublicKeyDerEncoding;

pub(crate) struct RsaPublicKey {
    modulus: BoxedUint,
    exponent: BoxedUint,
    modulus_bits: usize,
    size: usize,
}

impl RsaPublicKey {
    pub(crate) fn modulus(&self) -> &BoxedUint {
        &self.modulus
    }

    pub(crate) fn modulus_odd(&self) -> Result<Odd<BoxedUint>, CryptoError> {
        Option::<Odd<BoxedUint>>::from(Odd::new(self.modulus.clone()))
            .ok_or(CryptoError::PRIMITIVE_INVALID_KEY)
    }

    pub(crate) fn exponent(&self) -> &BoxedUint {
        &self.exponent
    }

    pub(crate) fn modulus_bits(&self) -> usize {
        self.modulus_bits
    }

    pub(crate) fn size(&self) -> usize {
        self.size
    }
}

impl Drop for RsaPublicKey {
    fn drop(&mut self) {
        self.modulus.zeroize();
        self.exponent.zeroize();
    }
}
impl zeroize::ZeroizeOnDrop for RsaPublicKey {}

struct DerRsaPublicKey<'a> {
    modulus: UintRef<'a>,
    public_exponent: UintRef<'a>,
}

impl<'a> DecodeValue<'a> for DerRsaPublicKey<'a> {
    type Error = spki::der::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> spki::der::Result<Self> {
        Ok(Self {
            modulus: reader.decode()?,
            public_exponent: reader.decode()?,
        })
    }
}

impl<'a> Sequence<'a> for DerRsaPublicKey<'a> {}

pub(crate) fn parse_public_key(
    public_key_der: &[u8],
    encoding: RsaPublicKeyDerEncoding,
) -> Result<RsaPublicKey, CryptoError> {
    if public_key_der.is_empty() || public_key_der.len() > RSA_PUBLIC_KEY_DER_MAX_LEN {
        return Err(CryptoError::PRIMITIVE_INVALID_KEY);
    }

    let key_der = match encoding {
        RsaPublicKeyDerEncoding::Pkcs1 => public_key_der,
        RsaPublicKeyDerEncoding::Spki => parse_spki_subject_public_key(public_key_der)?,
    };
    let parsed =
        DerRsaPublicKey::from_der(key_der).map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;

    build_public_key(parsed.modulus.as_bytes(), parsed.public_exponent.as_bytes())
}

pub(crate) fn validate_signature_length(
    key: &RsaPublicKey,
    signature: &[u8],
) -> Result<(), CryptoError> {
    if signature.len() != key.size() {
        return Err(signature_error());
    }
    Ok(())
}

fn parse_spki_subject_public_key(public_key_der: &[u8]) -> Result<&[u8], CryptoError> {
    let spki = SubjectPublicKeyInfoRef::try_from(public_key_der)
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;
    if spki.algorithm.oid != RSA_ENCRYPTION {
        return Err(CryptoError::PRIMITIVE_INVALID_KEY);
    }
    if let Some(parameters) = spki.algorithm.parameters {
        if !parameters.is_null() {
            return Err(CryptoError::PRIMITIVE_INVALID_KEY);
        }
    }
    spki.subject_public_key
        .as_bytes()
        .ok_or(CryptoError::PRIMITIVE_INVALID_KEY)
}

fn build_public_key(
    modulus_bytes: &[u8],
    exponent_bytes: &[u8],
) -> Result<RsaPublicKey, CryptoError> {
    if modulus_bytes.is_empty() || exponent_bytes.is_empty() {
        return Err(CryptoError::PRIMITIVE_INVALID_KEY);
    }
    if modulus_bytes.last().map(|byte| byte & 1) != Some(1) {
        return Err(CryptoError::PRIMITIVE_INVALID_KEY);
    }
    if exponent_bytes.last().map(|byte| byte & 1) != Some(1) {
        return Err(CryptoError::PRIMITIVE_INVALID_KEY);
    }

    let modulus_bits = usize::try_from(unsigned_bit_len(modulus_bytes)?)
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;
    if !(RSA_MIN_MODULUS_BITS..=RSA_MAX_MODULUS_BITS).contains(&modulus_bits) {
        return Err(CryptoError::PRIMITIVE_INVALID_KEY);
    }

    let exponent_bits = usize::try_from(unsigned_bit_len(exponent_bytes)?)
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;
    if !(RSA_MIN_EXPONENT_BITS..=RSA_MAX_EXPONENT_BITS).contains(&exponent_bits) {
        return Err(CryptoError::PRIMITIVE_INVALID_KEY);
    }

    let size = modulus_bits
        .checked_add(7)
        .and_then(|value| value.checked_div(8))
        .ok_or(CryptoError::PRIMITIVE_INVALID_KEY)?;
    let precision_bits = size
        .checked_mul(8)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(CryptoError::PRIMITIVE_INVALID_KEY)?;
    let modulus = BoxedUint::from_be_slice(modulus_bytes, precision_bits)
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;
    // The exponent is public and bounded independently of the modulus. Using
    // modulus-sized precision makes modular exponentiation scan thousands of
    // leading zero bits on every verification (including hostile signatures).
    let exponent_precision =
        u32::try_from(exponent_bits).map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;
    let exponent = BoxedUint::from_be_slice(exponent_bytes, exponent_precision)
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;

    Ok(RsaPublicKey {
        modulus,
        exponent,
        modulus_bits,
        size,
    })
}

fn unsigned_bit_len(bytes: &[u8]) -> Result<u32, CryptoError> {
    let Some(first_nonzero_index) = bytes.iter().position(|byte| *byte != 0) else {
        return Ok(0);
    };
    let first_nonzero = bytes
        .get(first_nonzero_index)
        .copied()
        .ok_or(CryptoError::PRIMITIVE_INVALID_KEY)?;
    let consumed_bytes = first_nonzero_index
        .checked_add(1)
        .ok_or(CryptoError::PRIMITIVE_INVALID_KEY)?;
    let remaining_bytes = bytes
        .len()
        .checked_sub(consumed_bytes)
        .ok_or(CryptoError::PRIMITIVE_INVALID_KEY)?;
    let remaining_bits = u32::try_from(remaining_bytes)
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?
        .checked_mul(8)
        .ok_or(CryptoError::PRIMITIVE_INVALID_KEY)?;
    let first_byte_bits = 8u32
        .checked_sub(first_nonzero.leading_zeros())
        .ok_or(CryptoError::PRIMITIVE_INVALID_KEY)?;
    remaining_bits
        .checked_add(first_byte_bits)
        .ok_or(CryptoError::PRIMITIVE_INVALID_KEY)
}

fn signature_error() -> CryptoError {
    crypto_core::CryptoError::PRIMITIVE_INVALID_SIGNATURE
}

#[cfg(test)]
#[path = "key_tests.rs"]
mod tests;
