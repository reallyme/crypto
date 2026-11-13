// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded public RSA operation for independently specified signature encodings.
use crate::{key::parse_public_key, RsaPublicKeyDerEncoding};
use crypto_bigint::{
    modular::{BoxedMontyForm, BoxedMontyParams},
    BoxedUint, CtAssign, MontyForm, MontyMultiplier,
};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretSlice};
use thiserror::Error;
use zeroize::Zeroizing;

/// Stable public-operation failure reasons; no key or message bytes are retained.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RsaRepresentativeErrorReason {
    /// Invalid or unsupported encoded RSA key.
    #[error("invalid RSA public key")]
    PublicKey,
    /// The signature is not the exact public modulus width.
    #[error("invalid RSA signature width")]
    Length,
    /// Signature representative is outside 0..n.
    #[error("RSA signature representative is out of range")]
    Range,
    /// A bounded result could not be allocated.
    #[error("RSA result allocation failed")]
    Allocation,
    /// Public length or representation arithmetic failed.
    #[error("RSA representation arithmetic failed")]
    Arithmetic,
}
/// Typed public-operation error, independent of provider diagnostic text.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("RSA public operation failed: {reason}")]
pub struct RsaRepresentativeError {
    reason: RsaRepresentativeErrorReason,
}
impl RsaRepresentativeError {
    /// Stable reason suitable for protocol/FFI mapping.
    pub fn reason(self) -> RsaRepresentativeErrorReason {
        self.reason
    }
}
impl From<RsaRepresentativeErrorReason> for RsaRepresentativeError {
    fn from(reason: RsaRepresentativeErrorReason) -> Self {
        Self { reason }
    }
}
use RsaRepresentativeErrorReason as Reason;

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
) -> Result<RsaPublicRepresentatives, RsaRepresentativeError> {
    let key = parse_public_key(public_key_der, encoding).map_err(|_| Reason::PublicKey)?;
    if signature.len() != key.size() {
        return Err(Reason::Length.into());
    }
    let value = Zeroizing::new(
        BoxedUint::from_be_slice(signature, key.modulus().bits_precision())
            .map_err(|_| Reason::Length)?,
    );
    if *value >= *key.modulus() {
        return Err(Reason::Range.into());
    }
    let params = BoxedMontyParams::new_vartime(key.modulus_odd().map_err(|_| Reason::PublicKey)?);
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
fn encode(value: &BoxedUint, width: usize) -> Result<SecretSlice<u8>, RsaRepresentativeError> {
    let bytes = Zeroizing::new(value.to_be_bytes());
    let begin = bytes.len().checked_sub(width).ok_or(Reason::Arithmetic)?;
    if bytes
        .get(..begin)
        .ok_or(Reason::Arithmetic)?
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(Reason::Arithmetic.into());
    }
    let mut storage = Zeroizing::new(Vec::new());
    storage
        .try_reserve_exact(width)
        .map_err(|_| Reason::Allocation)?;
    storage.resize(width, 0);
    if storage.capacity() != width {
        return Err(Reason::Allocation.into());
    }
    let mut output = SecretSlice::from(core::mem::take(&mut *storage).into_boxed_slice());
    output
        .expose_secret_mut()
        .copy_from_slice(bytes.get(begin..).ok_or(Reason::Arithmetic)?);
    Ok(output)
}
