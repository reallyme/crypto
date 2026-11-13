// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded public RSA operation for independently specified signature encodings.
use crate::{key::parse_public_key, RsaPublicKeyDerEncoding};
use crypto_bigint::{
    modular::{BoxedMontyForm, BoxedMontyParams},
    BoxedUint, CtAssign, MontyForm, MontyMultiplier,
};
use crypto_core::CryptoError;
use secrecy::{ExposeSecret, ExposeSecretMut, SecretSlice};
use zeroize::Zeroizing;

/// Canonical schema-defined error returned by the public RSA operation.
pub use crypto_core::CryptoError as RsaRepresentativeError;

/// Exact-width public representatives s^e mod n and n-(s^e mod n).
///
/// Ownership is protected because a recovered message can contain identity or
/// session evidence. Neither result establishes signature validity or trust.
///
/// ```compile_fail
/// use crypto_rsa::RsaPublicRepresentatives;
/// fn duplicate(value: RsaPublicRepresentatives) { let _ = value.clone(); }
/// ```
/// ```compile_fail
/// use crypto_rsa::RsaPublicRepresentatives;
/// fn disclose(value: RsaPublicRepresentatives) { let _ = format!("{value:?}"); }
/// ```
/// ```compile_fail
/// use crypto_rsa::RsaPublicRepresentatives;
/// fn serialize(value: RsaPublicRepresentatives) { let _ = serde_json::to_vec(&value); }
/// ```
pub struct RsaPublicRepresentatives {
    ordinary: SecretSlice<u8>,
    complement: SecretSlice<u8>,
}
impl RsaPublicRepresentatives {
    /// RFC 8017 RSAVP1 output in the exact key width.
    pub fn ordinary(&self) -> &[u8] {
        self.ordinary.expose_secret()
    }
    /// The modulus complement, for protocols that explicitly specify its use.
    pub fn complement(&self) -> &[u8] {
        self.complement.expose_secret()
    }
}
impl zeroize::ZeroizeOnDrop for RsaPublicRepresentatives {}

/// RFC 8017 5.2.2 public RSA operation without signature-format interpretation.
///
/// The exponent and modulus are public, bounded by the existing RSA key policy.
/// Private keys and signing operations are deliberately outside this interface.
pub fn rsa_public_representatives(
    public_key_der: &[u8],
    encoding: RsaPublicKeyDerEncoding,
    signature: &[u8],
) -> Result<RsaPublicRepresentatives, CryptoError> {
    let key = parse_public_key(public_key_der, encoding).map_err(public_key_error)?;
    if signature.len() != key.size() {
        return Err(CryptoError::PRIMITIVE_INVALID_LENGTH);
    }
    let value = Zeroizing::new(
        BoxedUint::from_be_slice(signature, key.modulus().bits_precision())
            .map_err(|_| CryptoError::PRIMITIVE_INVALID_LENGTH)?,
    );
    if *value >= *key.modulus() {
        return Err(CryptoError::PRIMITIVE_INVALID_SIGNATURE);
    }
    let params = BoxedMontyParams::new_vartime(key.modulus_odd().map_err(public_key_error)?);
    let base = Zeroizing::new(BoxedMontyForm::new((*value).clone(), &params));
    let mut result = Zeroizing::new(BoxedMontyForm::one(&params));
    let mut multiplier = <BoxedMontyForm as MontyForm>::Multiplier::from(&params);
    // The bounded public exponent controls the loop. Guard complete working
    // values and reuse clearing multiplier scratch instead of a power table.
    for bit in (0..key.exponent().bits_precision()).rev() {
        MontyMultiplier::square_assign(&mut multiplier, &mut result);
        let mut product = Zeroizing::new((*result).clone());
        MontyMultiplier::mul_assign(&mut multiplier, &mut product, &base);
        result
            .as_montgomery_mut()
            .ct_assign(product.as_montgomery(), key.exponent().bit(bit));
    }
    let ordinary = Zeroizing::new(result.retrieve());
    let complement = Zeroizing::new(key.modulus().wrapping_sub(&ordinary));
    Ok(RsaPublicRepresentatives {
        ordinary: encode(&ordinary, key.size())?,
        complement: encode(&complement, key.size())?,
    })
}
fn encode(value: &BoxedUint, width: usize) -> Result<SecretSlice<u8>, CryptoError> {
    let bytes = Zeroizing::new(value.to_be_bytes());
    let begin = bytes
        .len()
        .checked_sub(width)
        .ok_or(CryptoError::BACKEND_INTERNAL)?;
    if bytes
        .get(..begin)
        .ok_or(CryptoError::BACKEND_INTERNAL)?
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(CryptoError::BACKEND_INTERNAL);
    }
    let mut storage = Zeroizing::new(Vec::new());
    storage
        .try_reserve_exact(width)
        .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    storage.resize(width, 0);
    if storage.capacity() != width {
        return Err(CryptoError::BACKEND_INTERNAL);
    }
    let mut output = SecretSlice::from(core::mem::take(&mut *storage).into_boxed_slice());
    output
        .expose_secret_mut()
        .copy_from_slice(bytes.get(begin..).ok_or(CryptoError::BACKEND_INTERNAL)?);
    Ok(output)
}

// Add public-key context only to the shared parser's generic key rejection.
// Provider, resource and internal failures must retain their canonical reason.
fn public_key_error(error: CryptoError) -> CryptoError {
    if error == CryptoError::PRIMITIVE_INVALID_KEY {
        CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY
    } else {
        error
    }
}

#[cfg(test)]
#[path = "representative_error_tests.rs"]
mod error_tests;
