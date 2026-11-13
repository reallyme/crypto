// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// This provider is selected explicitly and never replaces a NIST backend.
// OpenSSL owns its internal EC private keys; their final free clears the
// private scalar. Imported BIGNUMs additionally have a local clearing guard.

use core::cmp::Ordering;
use openssl::{
    bn::{BigNum, BigNumContext},
    derive::Deriver,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    ecdsa::EcdsaSig,
    nid::Nid,
    pkey::{PKey, Private, Public},
};
use secrecy::SecretSlice;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{key::secret_copy, CryptoError, EcdsaCurve, EcdsaEncoding};

const COMPRESSED_EVEN_POINT_PREFIX: u8 = 0x02;
const COMPRESSED_ODD_POINT_PREFIX: u8 = 0x03;
const UNCOMPRESSED_POINT_PREFIX: u8 = 0x04;

struct SecretNumber(BigNum);

impl Zeroize for SecretNumber {
    fn zeroize(&mut self) {
        self.0.clear();
    }
}

impl Drop for SecretNumber {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SecretNumber {}

fn group(curve: EcdsaCurve) -> Result<EcGroup, CryptoError> {
    if !crate::native_provider::is_available() {
        return Err(CryptoError::PROVIDER_UNSUPPORTED_BACKEND);
    }
    let nid = match curve {
        EcdsaCurve::BrainpoolP256r1 => Nid::BRAINPOOL_P256R1,
        EcdsaCurve::BrainpoolP320r1 => Nid::BRAINPOOL_P320R1,
        EcdsaCurve::BrainpoolP384r1 => Nid::BRAINPOOL_P384R1,
        EcdsaCurve::BrainpoolP512r1 => Nid::BRAINPOOL_P512R1,
        _ => return Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
    };
    EcGroup::from_curve_name(nid).map_err(|_| CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
}

fn order(group: &EcGroup, context: &mut BigNumContext) -> Result<BigNum, CryptoError> {
    let mut order = BigNum::new().map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    group
        .order(&mut order, context)
        .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    Ok(order)
}

fn private_key(curve: EcdsaCurve, bytes: &[u8]) -> Result<EcKey<Private>, CryptoError> {
    if bytes.len() != curve.scalar_len()? {
        return Err(CryptoError::PRIMITIVE_INVALID_PRIVATE_KEY);
    }
    let group = group(curve)?;
    // A secure BN context clears temporary values when it is released.
    let mut context = BigNumContext::new_secure().map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    let mut scalar =
        SecretNumber(BigNum::from_slice(bytes).map_err(|_| CryptoError::BACKEND_INTERNAL)?);
    scalar.0.set_const_time();
    let order = order(&group, &mut context)?;
    if scalar.0.num_bits() == 0 || scalar.0.ucmp(&order) != Ordering::Less {
        return Err(CryptoError::PRIMITIVE_INVALID_PRIVATE_KEY);
    }
    let mut public = EcPoint::new(&group).map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    public
        .mul_generator2(&group, &scalar.0, &mut context)
        .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    let key = EcKey::from_private_components(&group, &scalar.0, &public)
        .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    key.check_key()
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_PRIVATE_KEY)?;
    Ok(key)
}

fn public_key(curve: EcdsaCurve, bytes: &[u8]) -> Result<EcKey<Public>, CryptoError> {
    let width = curve.scalar_len()?;
    let expected = match bytes.first().copied() {
        Some(COMPRESSED_EVEN_POINT_PREFIX | COMPRESSED_ODD_POINT_PREFIX) => width.checked_add(1),
        Some(UNCOMPRESSED_POINT_PREFIX) => width
            .checked_mul(2)
            .and_then(|length| length.checked_add(1)),
        _ => return Err(CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY),
    }
    .ok_or(CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)?;
    if bytes.len() != expected {
        return Err(CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY);
    }
    let group = group(curve)?;
    let mut context = BigNumContext::new().map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    let public = EcPoint::from_bytes(&group, bytes, &mut context)
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)?;
    if public.is_infinity(&group)
        || !public
            .is_on_curve(&group, &mut context)
            .map_err(|_| CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)?
    {
        return Err(CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY);
    }
    let key = EcKey::from_public_key(&group, &public)
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)?;
    key.check_key()
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)?;
    Ok(key)
}

pub(super) fn public_from_private(curve: EcdsaCurve, bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let key = private_key(curve, bytes)?;
    let mut context = BigNumContext::new().map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    key.public_key()
        .to_bytes(key.group(), PointConversionForm::UNCOMPRESSED, &mut context)
        .map_err(|_| CryptoError::BACKEND_INTERNAL)
}

pub(super) fn validate_public(curve: EcdsaCurve, bytes: &[u8]) -> Result<(), CryptoError> {
    public_key(curve, bytes).map(|_| ())
}

fn parse_signature(
    curve: EcdsaCurve,
    bytes: &[u8],
    encoding: EcdsaEncoding,
) -> Result<EcdsaSig, CryptoError> {
    let signature = match encoding {
        EcdsaEncoding::Der => {
            // The provider parser may accept a prefix. Comparing its canonical
            // serialization rejects trailing bytes and nonminimal encodings.
            let signature =
                EcdsaSig::from_der(bytes).map_err(|_| CryptoError::PRIMITIVE_INVALID_SIGNATURE)?;
            if signature
                .to_der()
                .map_err(|_| CryptoError::BACKEND_INTERNAL)?
                != bytes
            {
                return Err(CryptoError::PRIMITIVE_INVALID_SIGNATURE);
            }
            signature
        }
        EcdsaEncoding::FixedWidth => {
            let width = curve.scalar_len()?;
            if bytes.len()
                != width
                    .checked_mul(2)
                    .ok_or(CryptoError::PRIMITIVE_INVALID_SIGNATURE)?
            {
                return Err(CryptoError::PRIMITIVE_INVALID_SIGNATURE);
            }
            let r =
                BigNum::from_slice(&bytes[..width]).map_err(|_| CryptoError::BACKEND_INTERNAL)?;
            let s =
                BigNum::from_slice(&bytes[width..]).map_err(|_| CryptoError::BACKEND_INTERNAL)?;
            EcdsaSig::from_private_components(r, s).map_err(|_| CryptoError::BACKEND_INTERNAL)?
        }
    };
    let group = group(curve)?;
    let mut context = BigNumContext::new().map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    let order = order(&group, &mut context)?;
    for scalar in [signature.r(), signature.s()] {
        if scalar.is_negative() || scalar.num_bits() == 0 || scalar.ucmp(&order) != Ordering::Less {
            return Err(CryptoError::PRIMITIVE_INVALID_SIGNATURE);
        }
    }
    Ok(signature)
}

pub(super) fn der_to_fixed(curve: EcdsaCurve, bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let signature = parse_signature(curve, bytes, EcdsaEncoding::Der)?;
    let width = i32::try_from(curve.scalar_len()?).map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    let mut output = signature
        .r()
        .to_vec_padded(width)
        .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    output.extend_from_slice(
        &signature
            .s()
            .to_vec_padded(width)
            .map_err(|_| CryptoError::BACKEND_INTERNAL)?,
    );
    Ok(output)
}

pub(super) fn fixed_to_der(curve: EcdsaCurve, bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
    parse_signature(curve, bytes, EcdsaEncoding::FixedWidth)?
        .to_der()
        .map_err(|_| CryptoError::BACKEND_INTERNAL)
}

pub(super) fn sign(
    curve: EcdsaCurve,
    private: &[u8],
    digest: &[u8],
    encoding: EcdsaEncoding,
) -> Result<Vec<u8>, CryptoError> {
    let key = private_key(curve, private)?;
    let signature = EcdsaSig::sign(digest, &key).map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    let der = signature
        .to_der()
        .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    match encoding {
        EcdsaEncoding::Der => Ok(der),
        EcdsaEncoding::FixedWidth => der_to_fixed(curve, &der),
    }
}

pub(super) fn verify(
    curve: EcdsaCurve,
    public: &[u8],
    digest: &[u8],
    signature: &[u8],
    encoding: EcdsaEncoding,
) -> Result<(), CryptoError> {
    let key = public_key(curve, public)?;
    let signature = parse_signature(curve, signature, encoding)?;
    if signature
        .verify(digest, &key)
        .map_err(|_| CryptoError::BACKEND_INTERNAL)?
    {
        Ok(())
    } else {
        Err(CryptoError::PRIMITIVE_INVALID_SIGNATURE)
    }
}

pub(super) fn agree(
    curve: EcdsaCurve,
    private: &[u8],
    public: &[u8],
) -> Result<SecretSlice<u8>, CryptoError> {
    let private = PKey::from_ec_key(private_key(curve, private)?)
        .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    let public =
        PKey::from_ec_key(public_key(curve, public)?).map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    let mut deriver = Deriver::new(&private).map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    deriver
        .set_peer(&public)
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)?;
    let length = curve.scalar_len()?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(length)
        .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    bytes.resize(length, 0);
    let written = deriver
        .derive(bytes.as_mut_slice())
        .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    if written != length {
        return Err(CryptoError::BACKEND_INTERNAL);
    }
    secret_copy(bytes.as_slice())
}
