// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_bigint::{
    modular::{BoxedMontyForm, BoxedMontyParams},
    BoxedUint, CtEq, CtSelect, Limb,
};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretSlice};
use zeroize::Zeroizing;

use super::{field, secret, CryptoError, GroupElement, PrimeGroup};

impl PrimeGroup {
    /// Constant-time reduction of a bounded unsigned input modulo the field
    /// characteristic. The returned encoding has the field's exact byte width.
    pub fn reduce_to_field(self, input: &[u8]) -> Result<SecretSlice<u8>, CryptoError> {
        let params = field::params(self.modulus())?;
        let value = field::reduce(input, &params)?;
        field::encode(&value, self.field_len())
    }

    /// Encode a canonical nonzero field element into this subgroup.
    ///
    /// EC uses the affine Icart encoding in ICAO Doc 9303 Part 11 Appendix B.2
    /// (p = 3 mod 4). DH uses cofactor exponentiation x^((p-1)/q). Inputs at
    /// exceptional Icart denominators and identity outputs fail closed.
    pub fn encode_field(self, input: &[u8]) -> Result<GroupElement, CryptoError> {
        if input.len() != self.field_len() {
            return Err(CryptoError::PRIMITIVE_INVALID_LENGTH);
        }
        let params = field::params(self.modulus())?;
        let value = field::integer(input, params.bits_precision())?;
        if bool::from(value.is_zero()) || *value >= **params.modulus() {
            return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER);
        }
        let bytes = if self.is_elliptic_curve() {
            icart(self, &params, &value)?
        } else {
            cofactor(self, &params, &value)?
        };
        // This independent boundary also catches any field-encoding/backend
        // invariant failure before a result can be used as a supplied base.
        self.element(bytes.expose_secret())
    }
}

fn cofactor(
    group: PrimeGroup,
    params: &BoxedMontyParams,
    value: &BoxedUint,
) -> Result<SecretSlice<u8>, CryptoError> {
    let p_minus_one = params.modulus().as_ref().wrapping_sub(Limb::ONE);
    let q = field::params(group.order())?;
    let (exponent, remainder) = p_minus_one.div_rem(q.modulus().as_nz_ref());
    if !bool::from(remainder.is_zero()) {
        return Err(CryptoError::BACKEND_INTERNAL);
    }
    let base = Zeroizing::new(BoxedMontyForm::new(value.clone(), params));
    let result = field::pow(&base, &exponent);
    if bool::from(result.ct_eq(&BoxedMontyForm::one(params))) || bool::from(result.is_zero()) {
        return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER);
    }
    field::encode_form(&result, group.field_len())
}

fn icart(
    group: PrimeGroup,
    params: &BoxedMontyParams,
    value: &BoxedUint,
) -> Result<SecretSlice<u8>, CryptoError> {
    if group.modulus().last().map(|byte| byte & 3) != Some(3) {
        return Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM);
    }
    let domain = group.domain();
    let t = Zeroizing::new(BoxedMontyForm::new(value.clone(), params));
    let a = field::form(domain.a, params)?;
    let b = field::form(domain.b, params)?;
    let one = BoxedMontyForm::one(params);
    let t_squared = Zeroizing::new(t.square());
    let alpha = Zeroizing::new(-&*t_squared);
    let alpha_squared = Zeroizing::new(alpha.square());
    let alpha_sum = Zeroizing::new(&*alpha + &*alpha_squared);
    let denominator = Zeroizing::new(&*a * &*alpha_sum);
    // The inverse is computed by a fixed public exponent, including exceptional
    // inputs. No variable-time inversion or secret-dependent point selection.
    let p_minus_two = params.modulus().as_ref().wrapping_sub(Limb::from(2u8));
    let inverse = field::pow(&denominator, &p_minus_two);
    let numerator_sum = Zeroizing::new(&one + &*alpha_sum);
    let negative_b = Zeroizing::new(-&*b);
    let numerator = Zeroizing::new(&*negative_b * &*numerator_sum);
    let x2 = Zeroizing::new(&*numerator * &*inverse);
    let x3 = Zeroizing::new(&*alpha * &*x2);
    let x2_squared = Zeroizing::new(x2.square());
    let x2_cubed = Zeroizing::new(&*x2_squared * &*x2);
    let ax2 = Zeroizing::new(&*a * &*x2);
    let h2_partial = Zeroizing::new(&*x2_cubed + &*ax2);
    let h2 = Zeroizing::new(&*h2_partial + &*b);
    let t_cubed = Zeroizing::new(&*t_squared * &*t);
    let u = Zeroizing::new(&*t_cubed * &*h2);
    let p_plus_one = params.modulus().as_ref().wrapping_add(Limb::ONE);
    let quarter = p_plus_one.shr(2);
    let p_minus_one = params.modulus().as_ref().wrapping_sub(Limb::ONE);
    let exponent = p_minus_one.wrapping_sub(&quarter);
    let big_a = field::pow(&h2, &exponent);
    let a_squared = Zeroizing::new(big_a.square());
    let test = Zeroizing::new(&*a_squared * &*h2);
    let use_x2 = test.ct_eq(&one);
    let y2 = Zeroizing::new(&*big_a * &*h2);
    let y3 = Zeroizing::new(&*big_a * &*u);
    let x = Zeroizing::new(x3.ct_select(&x2, use_x2));
    let y = Zeroizing::new(y3.ct_select(&y2, use_x2));
    if bool::from(denominator.is_zero()) {
        return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER);
    }
    encode_point(group, &x, &y)
}

fn encode_point(
    group: PrimeGroup,
    x: &BoxedMontyForm,
    y: &BoxedMontyForm,
) -> Result<SecretSlice<u8>, CryptoError> {
    let x = field::encode_form(x, group.field_len())?;
    let y = field::encode_form(y, group.field_len())?;
    let mut encoded = secret::zeros(group.element_len())?;
    let x_end = group
        .field_len()
        .checked_add(1)
        .ok_or(CryptoError::BACKEND_INTERNAL)?;
    let destination = encoded.expose_secret_mut();
    *destination
        .first_mut()
        .ok_or(CryptoError::BACKEND_INTERNAL)? = 0x04;
    destination
        .get_mut(1..x_end)
        .ok_or(CryptoError::BACKEND_INTERNAL)?
        .copy_from_slice(x.expose_secret());
    destination
        .get_mut(x_end..)
        .ok_or(CryptoError::BACKEND_INTERNAL)?
        .copy_from_slice(y.expose_secret());
    Ok(encoded)
}
