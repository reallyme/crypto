// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded, blinded RS256 signing with private state owned by a zeroizing key.

use crypto_core::CryptoError;
#[cfg(any(feature = "native", feature = "wasm"))]
use rsa_backend::pkcs8::der::Decode;
#[cfg(any(feature = "native", feature = "wasm"))]
use rsa_backend::pkcs8::{DecodePrivateKey, EncodePublicKey};
#[cfg(any(feature = "native", feature = "wasm"))]
use rsa_backend::traits::PublicKeyParts;
#[cfg(any(feature = "native", feature = "wasm"))]
use secrecy::{ExposeSecret, SecretBox};
#[cfg(any(feature = "native", feature = "wasm"))]
use subtle::ConstantTimeEq;
#[cfg(any(feature = "native", feature = "wasm"))]
use zeroize::Zeroize;
use zeroize::ZeroizeOnDrop;

// Import bounds apply before DER decoding or private arithmetic. Historical
// 1024-bit verification remains supported separately, never for new signatures.
#[cfg(any(feature = "native", feature = "wasm"))]
const MIN_SIGNING_MODULUS_BITS: usize = 2048;
#[cfg(any(feature = "native", feature = "wasm"))]
const MAX_PRIVATE_KEY_DER_BYTES: usize = 16_384;
#[cfg(any(feature = "native", feature = "wasm"))]
const MAX_PUBLIC_EXPONENT_BYTES: usize = 4;

/// Public, canonical RSA material suitable for SPKI and JWK publication.
#[derive(Debug, Clone, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct RsaSigningPublicKey {
    /// DER SubjectPublicKeyInfo containing rsaEncryption and a NULL parameter.
    pub spki_der: Vec<u8>,
    /// Minimal, unsigned, big-endian modulus; never includes a DER sign octet.
    pub modulus: Vec<u8>,
    /// Minimal, unsigned, big-endian public exponent.
    pub exponent: Vec<u8>,
}

/// An imported signing key. No private export, cloning, or formatting is exposed.
/// The backend clears private factors, exponents and CRT precomputations on drop.
pub struct RsaSigningKey {
    #[cfg(any(feature = "native", feature = "wasm"))]
    key: SecretBox<PrivateRsaKey>,
}

// SecretBox invokes this owner on every drop path. Taking the backend key
// destroys its private factors and precomputations without exposing components.
#[cfg(any(feature = "native", feature = "wasm"))]
struct PrivateRsaKey {
    key: Option<rsa_backend::PrivateKey>,
}
#[cfg(any(feature = "native", feature = "wasm"))]
impl Zeroize for PrivateRsaKey {
    fn zeroize(&mut self) {
        drop(self.key.take());
    }
}
#[cfg(any(feature = "native", feature = "wasm"))]
impl Drop for PrivateRsaKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}
#[cfg(any(feature = "native", feature = "wasm"))]
impl ZeroizeOnDrop for PrivateRsaKey {}

impl ZeroizeOnDrop for RsaSigningKey {}

impl RsaSigningKey {
    /// Imports a complete PKCS#8 key and validates its private/public consistency.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, CryptoError> {
        #[cfg(any(feature = "native", feature = "wasm"))]
        {
            if der.is_empty() || der.len() > MAX_PRIVATE_KEY_DER_BYTES {
                return Err(CryptoError::PRIMITIVE_INVALID_KEY);
            }
            // Reject oversized public parameters before the backend allocates big
            // integers or validates secret factors. DER parsing here only borrows.
            let info = rsa_backend::pkcs8::PrivateKeyInfoRef::from_der(der)
                .map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;
            if info.algorithm.oid != rsa_backend::pkcs1::ALGORITHM_OID {
                return Err(CryptoError::PRIMITIVE_INVALID_KEY);
            }
            let inner = rsa_backend::pkcs1::RsaPrivateKeyRef::try_from(info.private_key)
                .map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;
            let max_bytes = crate::RSA_MAX_MODULUS_BITS.div_ceil(8);
            if inner.modulus.as_bytes().len() > max_bytes
                || inner.public_exponent.as_bytes().len() > MAX_PUBLIC_EXPONENT_BYTES
            {
                return Err(CryptoError::PRIMITIVE_INVALID_KEY);
            }
            let key = rsa_backend::PrivateKey::from_pkcs8_der(der)
                .map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;
            let bits = usize::try_from(key.n().bit_width_vartime())
                .map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;
            if !(MIN_SIGNING_MODULUS_BITS..=crate::RSA_MAX_MODULUS_BITS).contains(&bits)
                || key.e_bytes().len() > MAX_PUBLIC_EXPONENT_BYTES
            {
                return Err(CryptoError::PRIMITIVE_INVALID_KEY);
            }
            key.validate()
                .map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;
            // The backend reconstructs CRT values during import. Reject a DER
            // key whose supplied CRT values disagree rather than silently repair
            // corrupted private material. SecretDocument clears this temporary.
            let canonical = rsa_backend::pkcs1::EncodeRsaPrivateKey::to_pkcs1_der(&key)
                .map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;
            if canonical
                .as_bytes()
                .ct_eq(info.private_key.as_bytes())
                .unwrap_u8()
                != 1
            {
                return Err(CryptoError::PRIMITIVE_INVALID_KEY);
            }
            Ok(Self {
                key: SecretBox::new(Box::new(PrivateRsaKey { key: Some(key) })),
            })
        }
        #[cfg(not(any(feature = "native", feature = "wasm")))]
        {
            let _ = der;
            Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
        }
    }

    /// Exports public components only; callers cannot accidentally publish DER
    /// containing the private exponent when constructing a JWKS document.
    pub fn public_key(&self) -> Result<RsaSigningPublicKey, CryptoError> {
        #[cfg(any(feature = "native", feature = "wasm"))]
        {
            let public = self.key()?.as_public_key();
            let spki = public
                .to_public_key_der()
                .map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;
            Ok(RsaSigningPublicKey {
                spki_der: spki.as_bytes().to_vec(),
                modulus: public.n_bytes().into_vec(),
                exponent: public.e_bytes().into_vec(),
            })
        }
        #[cfg(not(any(feature = "native", feature = "wasm")))]
        {
            Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
        }
    }

    /// Signs the exact message with SHA-256 and PKCS#1 v1.5 encoding.
    /// Every private operation uses OS-backed blinding. Entropy failure is an
    /// error, never a reason to retry through an unblinded signing operation.
    pub fn sign_rs256(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        #[cfg(any(feature = "native", feature = "wasm"))]
        {
            self.sign_with_rng(message, &mut getrandom::SysRng)
        }
        #[cfg(not(any(feature = "native", feature = "wasm")))]
        {
            let _ = message;
            Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
        }
    }

    #[cfg(any(feature = "native", feature = "wasm"))]
    fn key(&self) -> Result<&rsa_backend::PrivateKey, CryptoError> {
        self.key
            .expose_secret()
            .key
            .as_ref()
            .ok_or(CryptoError::PRIMITIVE_INVALID_KEY)
    }

    #[cfg(any(feature = "native", feature = "wasm"))]
    fn sign_with_rng(
        &self,
        message: &[u8],
        rng: &mut impl getrandom::rand_core::TryCryptoRng,
    ) -> Result<Vec<u8>, CryptoError> {
        self.key()?
            .pkcs1v15_sign_with_rng::<sha2::Sha256, _>(rng, message)
            .map_err(|error| match error {
                rsa_backend::Error::Rng => CryptoError::PROVIDER_RANDOMNESS_UNAVAILABLE,
                _ => CryptoError::PRIMITIVE_INVALID_KEY,
            })
    }
}

#[cfg(test)]
#[cfg(any(feature = "native", feature = "wasm"))]
#[path = "sign_pkcs1v15_tests.rs"]
mod tests;

#[cfg(test)]
#[cfg(not(any(feature = "native", feature = "wasm")))]
#[path = "sign_pkcs1v15_unavailable_tests.rs"]
mod unavailable_tests;
