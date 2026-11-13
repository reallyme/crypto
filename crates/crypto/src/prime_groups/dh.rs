// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_bigint::{modular::BoxedMontyForm, BoxedUint, CtEq};
use secrecy::SecretSlice;
use zeroize::Zeroizing;

use super::{field, CryptoError, PrimeGroup};

pub(super) fn validate(group: PrimeGroup, bytes: &[u8]) -> Result<(), CryptoError> {
    let params = field::params(group.modulus())?;
    let value = field::integer(bytes, params.bits_precision())?;
    let one = BoxedUint::one_with_precision(params.bits_precision());
    if *value <= one || *value >= **params.modulus() {
        return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER);
    }
    let element = Zeroizing::new(BoxedMontyForm::new((*value).clone(), &params));
    let order = field::integer(group.order(), field::precision(group.scalar_len())?)?;
    let check = field::pow(&element, &order);
    // RFC 2631 section 2.1.5: range validation alone does not establish that
    // an attacker-supplied value is in the subgroup of prime order q.
    if !bool::from(check.ct_eq(&BoxedMontyForm::one(&params))) {
        return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER);
    }
    Ok(())
}

pub(super) fn multiply(
    group: PrimeGroup,
    base: &[u8],
    scalar: &[u8],
) -> Result<SecretSlice<u8>, CryptoError> {
    operation(group, base, scalar, None)
}

pub(super) fn combine(
    group: PrimeGroup,
    base: &[u8],
    scalar: &[u8],
    offset: &[u8],
) -> Result<SecretSlice<u8>, CryptoError> {
    operation(group, base, scalar, Some(offset))
}

fn operation(
    group: PrimeGroup,
    base: &[u8],
    scalar: &[u8],
    offset: Option<&[u8]>,
) -> Result<SecretSlice<u8>, CryptoError> {
    let params = field::params(group.modulus())?;
    let base = field::form(base, &params)?;
    let exponent = field::integer(scalar, field::precision(group.scalar_len())?)?;
    // The public subgroup storage width fixes the complete scan, independently
    // of a private exponent's leading zeros.
    let result = field::pow(&base, &exponent);
    let result = if let Some(offset) = offset {
        let offset = field::form(offset, &params)?;
        // A BoxedMontyForm assignment would free its previous allocation
        // without clearing it. Retain each value in its own erasing owner.
        Zeroizing::new(&*result * &*offset)
    } else {
        result
    };
    if bool::from(result.ct_eq(&BoxedMontyForm::one(&params))) || bool::from(result.is_zero()) {
        return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER);
    }
    field::encode_form(&result, group.field_len())
}
