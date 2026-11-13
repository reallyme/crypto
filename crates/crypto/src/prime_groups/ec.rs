// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::brainpool_parameters::{bp320, bp512};

use elliptic_curve::{
    group::Group,
    point::AffineCoordinates,
    sec1::FromSec1Point,
    subtle::{Choice, ConditionallySelectable},
};
use secrecy::{ExposeSecretMut, SecretSlice};
use zeroize::Zeroizing;

use super::legacy_curves::{bp192, bp224, nistp192};
use super::{secret, CryptoError, PrimeGroup};

macro_rules! with_curve {
    ($group:expr, $curve:ident, $body:block) => {
        match $group {
            PrimeGroup::NistP192 => {
                type $curve = nistp192::NistP192;
                $body
            }
            PrimeGroup::BrainpoolP192r1 => {
                type $curve = bp192::BrainpoolP192r1;
                $body
            }
            PrimeGroup::BrainpoolP224r1 => {
                type $curve = bp224::BrainpoolP224r1;
                $body
            }
            PrimeGroup::NistP256 => {
                type $curve = p256::NistP256;
                $body
            }
            PrimeGroup::NistP384 => {
                type $curve = p384::NistP384;
                $body
            }
            PrimeGroup::NistP521 => {
                type $curve = p521::NistP521;
                $body
            }
            PrimeGroup::BrainpoolP256r1 => {
                type $curve = bp256::BrainpoolP256r1;
                $body
            }
            PrimeGroup::BrainpoolP320r1 => {
                type $curve = bp320::BrainpoolP320r1;
                $body
            }
            PrimeGroup::BrainpoolP384r1 => {
                type $curve = bp384::BrainpoolP384r1;
                $body
            }
            PrimeGroup::BrainpoolP512r1 => {
                type $curve = bp512::BrainpoolP512r1;
                $body
            }
            _ => Err(CryptoError::PRIMITIVE_INVALID_PARAMETER),
        }
    };
}

macro_rules! point {
    ($curve:ident, $bytes:expr) => {{
        if $bytes.first() != Some(&0x04) {
            return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER);
        }
        let encoded = Zeroizing::new(
            elliptic_curve::sec1::Sec1Point::<$curve>::from_bytes($bytes)
                .map_err(|_| CryptoError::PRIMITIVE_INVALID_PARAMETER)?,
        );
        let affine = Zeroizing::new(
            Option::<elliptic_curve::AffinePoint<$curve>>::from(elliptic_curve::AffinePoint::<
                $curve,
            >::from_sec1_point(
                &encoded
            ))
            .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?,
        );
        // All EC domains exposed here have cofactor one. On-curve, nonidentity
        // validation consequently also establishes prime-subgroup membership.
        let projective = Zeroizing::new(elliptic_curve::ProjectivePoint::<$curve>::from(*affine));
        if bool::from(projective.is_identity()) {
            return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER);
        }
        projective
    }};
}

pub(super) fn validate(group: PrimeGroup, bytes: &[u8]) -> Result<(), CryptoError> {
    with_curve!(group, C, {
        let _point = point!(C, bytes);
        Ok(())
    })
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
    with_curve!(group, C, {
        if scalar.len() != group.scalar_len() {
            return Err(CryptoError::PRIMITIVE_INVALID_LENGTH);
        }
        let base = point!(C, base);
        // Fixed-width binary multiplication composes the existing complete
        // point operations. It never creates a plain scalar-digit buffer or
        // a table of secret points. Every complete accumulator is guarded.
        let mut result = Zeroizing::new(elliptic_curve::ProjectivePoint::<C>::identity());
        for byte in scalar {
            for shift in (0..u8::BITS).rev() {
                let doubled = Zeroizing::new(result.double());
                let added = Zeroizing::new(*doubled + *base);
                result.conditional_assign(&doubled, Choice::from(1));
                result.conditional_assign(&added, Choice::from((byte >> shift) & 1));
            }
        }
        if let Some(offset) = offset {
            let offset = point!(C, offset);
            *result += *offset;
        }
        if bool::from(result.is_identity()) {
            return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER);
        }
        // Direct coordinate output avoids a serializer constructing and then
        // selecting a second complete, unguarded SEC1 point buffer.
        let affine = Zeroizing::new(result.to_affine());
        let x = Zeroizing::new(affine.x());
        let y = Zeroizing::new(affine.y());
        let mut output = secret::zeros(group.element_len())?;
        let end = group
            .field_len()
            .checked_add(1)
            .ok_or(CryptoError::BACKEND_INTERNAL)?;
        let encoded = output.expose_secret_mut();
        *encoded.first_mut().ok_or(CryptoError::BACKEND_INTERNAL)? = 0x04;
        encoded
            .get_mut(1..end)
            .ok_or(CryptoError::BACKEND_INTERNAL)?
            .copy_from_slice(&x);
        encoded
            .get_mut(end..)
            .ok_or(CryptoError::BACKEND_INTERNAL)?
            .copy_from_slice(&y);
        Ok(output)
    })
}
