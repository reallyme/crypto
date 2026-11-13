// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_bigint::{
    modular::{BoxedMontyForm, BoxedMontyParams},
    BoxedUint, CtAssign, MontyForm, MontyMultiplier, Odd,
};
use secrecy::SecretSlice;
use zeroize::Zeroizing;

use super::{secret, CryptoError};

// A local bound on secret reduction inputs, not a group-standard constraint.
pub(super) const MAX_REDUCTION_BYTES: usize =
    crypto_core::contract_constants::prime_groups::MAX_REDUCTION_BYTES;

pub(super) fn precision(length: usize) -> Result<u32, CryptoError> {
    u32::try_from(length)
        .ok()
        .and_then(|value| value.checked_mul(u8::BITS))
        .ok_or(CryptoError::BACKEND_INTERNAL)
}

pub(super) fn integer(bytes: &[u8], bits: u32) -> Result<Zeroizing<BoxedUint>, CryptoError> {
    BoxedUint::from_be_slice(bytes, bits)
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::BACKEND_INTERNAL)
}

pub(super) fn params(modulus: &[u8]) -> Result<BoxedMontyParams, CryptoError> {
    let value = BoxedUint::from_be_slice(modulus, precision(modulus.len())?)
        .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    let odd =
        Option::<Odd<BoxedUint>>::from(Odd::new(value)).ok_or(CryptoError::BACKEND_INTERNAL)?;
    // The modulus is one of the built-in public constants. Its preprocessing
    // may vary with that public value, never with a private scalar or nonce.
    Ok(BoxedMontyParams::new_vartime(odd))
}

pub(super) fn reduce(
    bytes: &[u8],
    params: &BoxedMontyParams,
) -> Result<Zeroizing<BoxedUint>, CryptoError> {
    if bytes.is_empty() || bytes.len() > MAX_REDUCTION_BYTES {
        return Err(CryptoError::PRIMITIVE_INVALID_LENGTH);
    }
    let input_bits = precision(bytes.len())?.max(params.bits_precision());
    let input = integer(bytes, input_bits)?;
    // Keep both division outputs in erasing owners: discarding the quotient
    // inside `rem` would leave a secret-bearing heap allocation unprotected.
    let (quotient, remainder) = input.div_rem(params.modulus().as_nz_ref());
    let _quotient = Zeroizing::new(quotient);
    Ok(Zeroizing::new(remainder))
}

pub(super) fn form(
    bytes: &[u8],
    params: &BoxedMontyParams,
) -> Result<Zeroizing<BoxedMontyForm>, CryptoError> {
    let reduced = reduce(bytes, params)?;
    Ok(Zeroizing::new(BoxedMontyForm::new(
        (*reduced).clone(),
        params,
    )))
}

pub(super) fn encode(value: &BoxedUint, length: usize) -> Result<SecretSlice<u8>, CryptoError> {
    let bytes = Zeroizing::new(value.to_be_bytes());
    let start = bytes
        .len()
        .checked_sub(length)
        .ok_or(CryptoError::BACKEND_INTERNAL)?;
    let prefix = bytes.get(..start).ok_or(CryptoError::BACKEND_INTERNAL)?;
    // A fixed public-width encoding must never silently truncate a value.
    if prefix.iter().fold(0u8, |acc, byte| acc | byte) != 0 {
        return Err(CryptoError::BACKEND_INTERNAL);
    }
    secret::copy(bytes.get(start..).ok_or(CryptoError::BACKEND_INTERNAL)?)
}

pub(super) fn encode_form(
    value: &BoxedMontyForm,
    length: usize,
) -> Result<SecretSlice<u8>, CryptoError> {
    let integer = Zeroizing::new(value.retrieve());
    encode(&integer, length)
}

/// Fixed-public-width exponentiation over the existing Montgomery engine.
/// Each accumulator and selected product has an erasing owner; the backend's
/// multiplier clears its owned scratch on drop under the required zeroize
/// feature. No unguarded table or exponent-window buffer is constructed.
pub(super) fn pow(base: &BoxedMontyForm, exponent: &BoxedUint) -> Zeroizing<BoxedMontyForm> {
    let mut result = Zeroizing::new(BoxedMontyForm::one(base.params()));
    let mut multiplier = <BoxedMontyForm as MontyForm>::Multiplier::from(base.params());
    for bit in (0..exponent.bits_precision()).rev() {
        MontyMultiplier::square_assign(&mut multiplier, &mut result);
        let mut product = Zeroizing::new((*result).clone());
        MontyMultiplier::mul_assign(&mut multiplier, &mut product, base);
        result
            .as_montgomery_mut()
            .ct_assign(product.as_montgomery(), exponent.bit(bit));
    }
    result
}
