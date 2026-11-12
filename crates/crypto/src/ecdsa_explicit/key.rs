// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use ecdsa::signature::hazmat::PrehashSigner;
use p256::elliptic_curve::sec1::ToSec1Point;
use secrecy::{ExposeSecret, SecretSlice};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{
    digest::with_digest, encode::encode, EcdsaCurve, EcdsaEncoding, EcdsaError, EcdsaInput,
};
use crate::key_random::{KeyRng, SystemKeyRng};

const MAX_SCALAR_LEN: usize = super::constants::P521_SCALAR_LEN;
const GENERATION_ATTEMPTS: usize = 128;
const P521_HIGH_BYTE_MASK: u8 = 0x01;

/// Validated, clearing ECDSA/ECDH private scalar, with its public key bound at
/// import. This owner deliberately offers no raw private-key export.
pub struct EcdsaKey {
    curve: EcdsaCurve,
    private: SecretSlice<u8>,
    public: Vec<u8>,
}

impl EcdsaKey {
    /// Import a fixed-width big-endian private scalar. The borrowed source
    /// remains the caller's cleanup responsibility.
    pub fn import(curve: EcdsaCurve, scalar: &[u8]) -> Result<Self, EcdsaError> {
        if scalar.len() != curve.scalar_len()? {
            return Err(EcdsaError::InvalidPrivateKey);
        }
        macro_rules! public_key {
            ($backend:ident) => {{
                let key = $backend::SecretKey::from_slice(scalar)
                    .map_err(|_| EcdsaError::InvalidPrivateKey)?;
                key.public_key().to_sec1_point(false).as_bytes().to_vec()
            }};
        }
        let public = match curve {
            EcdsaCurve::P256 => public_key!(p256),
            EcdsaCurve::P384 => public_key!(p384),
            EcdsaCurve::P521 => public_key!(p521),
            #[cfg(all(feature = "brainpool-openssl", not(target_arch = "wasm32")))]
            curve => super::brainpool::public_from_private(curve, scalar)?,
            #[cfg(not(all(feature = "brainpool-openssl", not(target_arch = "wasm32"))))]
            _ => return Err(EcdsaError::UnsupportedCurve),
        };
        Ok(Self {
            curve,
            private: secret_copy(scalar)?,
            public,
        })
    }

    /// Generate a uniformly sampled nonzero scalar with OS entropy. The
    /// bounded rejection loop fails closed if the entropy provider is faulty.
    pub fn generate(curve: EcdsaCurve) -> Result<Self, EcdsaError> {
        Self::generate_with_rng(curve, &mut SystemKeyRng)
    }

    /// Generate with an injected cryptographic entropy source. Partially
    /// filled or rejected candidate scalars remain in clearing storage.
    pub fn generate_with_rng(curve: EcdsaCurve, rng: &mut impl KeyRng) -> Result<Self, EcdsaError> {
        let length = curve.scalar_len()?;
        let mut scalar = Zeroizing::new([0; MAX_SCALAR_LEN]);
        for _ in 0..GENERATION_ATTEMPTS {
            rng.fill(&mut scalar[..length])
                .map_err(|_| EcdsaError::RandomnessUnavailable)?;
            if curve == EcdsaCurve::P521 {
                scalar[0] &= P521_HIGH_BYTE_MASK;
            }
            match Self::import(curve, &scalar[..length]) {
                Ok(key) => return Ok(key),
                Err(EcdsaError::InvalidPrivateKey) => scalar.zeroize(),
                Err(error) => return Err(error),
            }
        }
        Err(EcdsaError::RandomnessUnavailable)
    }

    /// Curve associated with this key.
    pub fn curve(&self) -> EcdsaCurve {
        self.curve
    }

    /// Uncompressed SEC1 public key (65/81/97/129/133 bytes for supported curves).
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    /// ECDSA with explicit hashing and output representation. Portable NIST
    /// signing uses RFC 6979; the optional Brainpool provider uses randomized
    /// ECDSA and maps provider/entropy failures to `ProviderFailed`.
    pub fn sign(
        &self,
        input: EcdsaInput<'_>,
        encoding: EcdsaEncoding,
    ) -> Result<Vec<u8>, EcdsaError> {
        with_digest(input, |_, digest| {
            macro_rules! sign_curve {
                ($backend:ident) => {{
                    let key = $backend::ecdsa::SigningKey::from_slice(self.private.expose_secret())
                        .map_err(|_| EcdsaError::InvalidPrivateKey)?;
                    let signature: $backend::ecdsa::Signature = key
                        .sign_prehash(digest)
                        .map_err(|_| EcdsaError::ProviderFailed)?;
                    encode(self.curve, signature.to_der().as_bytes().to_vec(), encoding)
                }};
            }
            match self.curve {
                EcdsaCurve::P256 => sign_curve!(p256),
                EcdsaCurve::P384 => sign_curve!(p384),
                EcdsaCurve::P521 => sign_curve!(p521),
                #[cfg(all(feature = "brainpool-openssl", not(target_arch = "wasm32")))]
                curve => {
                    super::brainpool::sign(curve, self.private.expose_secret(), digest, encoding)
                }
                #[cfg(not(all(feature = "brainpool-openssl", not(target_arch = "wasm32"))))]
                _ => Err(EcdsaError::UnsupportedCurve),
            }
        })
    }

    /// Raw ECDH x-coordinate, fixed-width big-endian with leading zeros kept.
    /// No KDF, transcript processing or protocol labels are applied here.
    pub fn agree(&self, peer_sec1: &[u8]) -> Result<SecretSlice<u8>, EcdsaError> {
        macro_rules! agree_curve {
            ($backend:ident) => {{
                let private = $backend::SecretKey::from_slice(self.private.expose_secret())
                    .map_err(|_| EcdsaError::InvalidPrivateKey)?;
                let public = $backend::PublicKey::from_sec1_bytes(peer_sec1)
                    .map_err(|_| EcdsaError::InvalidPublicKey)?;
                let shared =
                    $backend::ecdh::diffie_hellman(private.to_nonzero_scalar(), public.as_affine());
                secret_copy(shared.raw_secret_bytes().as_slice())
            }};
        }
        match self.curve {
            EcdsaCurve::P256 => agree_curve!(p256),
            EcdsaCurve::P384 => agree_curve!(p384),
            EcdsaCurve::P521 => agree_curve!(p521),
            #[cfg(all(feature = "brainpool-openssl", not(target_arch = "wasm32")))]
            curve => super::brainpool::agree(curve, self.private.expose_secret(), peer_sec1),
            #[cfg(not(all(feature = "brainpool-openssl", not(target_arch = "wasm32"))))]
            _ => Err(EcdsaError::UnsupportedCurve),
        }
    }
}

impl Zeroize for EcdsaKey {
    fn zeroize(&mut self) {
        self.private.zeroize();
    }
}

impl ZeroizeOnDrop for EcdsaKey {}

pub(super) fn secret_copy(bytes: &[u8]) -> Result<SecretSlice<u8>, EcdsaError> {
    use secrecy::ExposeSecretMut;
    let mut storage = Zeroizing::new(Vec::new());
    storage
        .try_reserve_exact(bytes.len())
        .map_err(|_| EcdsaError::AllocationFailed)?;
    storage.resize(bytes.len(), 0);
    if storage.capacity() != bytes.len() {
        return Err(EcdsaError::AllocationFailed);
    }
    // Allocate and box while the buffer still contains zeros, then install the
    // secrecy owner before copying any private or shared-secret material.
    let mut owner = SecretSlice::from(core::mem::take(&mut *storage));
    owner.expose_secret_mut().copy_from_slice(bytes);
    Ok(owner)
}
