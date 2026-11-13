// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use ecdsa::signature::hazmat::PrehashSigner;
use p256::elliptic_curve::sec1::ToSec1Point;
use secrecy::{ExposeSecret, SecretSlice};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{
    digest::with_digest, encode::encode, CryptoError, EcdsaCurve, EcdsaEncoding, EcdsaInput,
};
use crate::key_random::{KeyRng, SystemKeyRng};

const MAX_SCALAR_LEN: usize = super::constants::P521_SCALAR_LEN;
const GENERATION_ATTEMPTS: usize =
    crypto_core::contract_constants::ecdsa_explicit::GENERATION_ATTEMPTS;
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
    pub fn import(curve: EcdsaCurve, scalar: &[u8]) -> Result<Self, CryptoError> {
        if scalar.len() != curve.scalar_len()? {
            return Err(CryptoError::PRIMITIVE_INVALID_PRIVATE_KEY);
        }
        macro_rules! public_key {
            ($backend:ident) => {{
                let key = $backend::SecretKey::from_slice(scalar)
                    .map_err(|_| CryptoError::PRIMITIVE_INVALID_PRIVATE_KEY)?;
                key.public_key().to_sec1_point(false).as_bytes().to_vec()
            }};
        }
        let public = match curve {
            EcdsaCurve::P256 => public_key!(p256),
            EcdsaCurve::P384 => public_key!(p384),
            EcdsaCurve::P521 => public_key!(p521),
            #[cfg(all(feature = "brainpool-openssl", not(target_arch = "wasm32")))]
            curve => super::brainpool::public_from_private(curve, scalar)?,
            #[cfg(all(
                feature = "brainpool",
                not(all(feature = "brainpool-openssl", not(target_arch = "wasm32")))
            ))]
            curve => super::portable_brainpool::public_from_private(curve, scalar)?,
            #[cfg(not(any(
                feature = "brainpool",
                all(feature = "brainpool-openssl", not(target_arch = "wasm32"))
            )))]
            _ => return Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
        };
        Ok(Self {
            curve,
            private: secret_copy(scalar)?,
            public,
        })
    }

    /// Generate a uniformly sampled nonzero scalar with OS entropy. The
    /// bounded rejection loop fails closed if the entropy provider is faulty.
    pub fn generate(curve: EcdsaCurve) -> Result<Self, CryptoError> {
        Self::generate_with_rng(curve, &mut SystemKeyRng)
    }

    /// Generate with an injected cryptographic entropy source. Partially
    /// filled or rejected candidate scalars remain in clearing storage.
    pub fn generate_with_rng(
        curve: EcdsaCurve,
        rng: &mut impl KeyRng,
    ) -> Result<Self, CryptoError> {
        let length = curve.scalar_len()?;
        let mut scalar = Zeroizing::new([0; MAX_SCALAR_LEN]);
        for _ in 0..GENERATION_ATTEMPTS {
            rng.fill(&mut scalar[..length])?;
            if curve == EcdsaCurve::P521 {
                scalar[0] &= P521_HIGH_BYTE_MASK;
            }
            match Self::import(curve, &scalar[..length]) {
                Ok(key) => return Ok(key),
                Err(error) if error == CryptoError::PRIMITIVE_INVALID_PRIVATE_KEY => {
                    scalar.zeroize()
                }
                Err(error) => return Err(error),
            }
        }
        Err(CryptoError::PROVIDER_RANDOMNESS_UNAVAILABLE)
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
    /// ECDSA and maps provider/entropy failures to `BACKEND_INTERNAL`.
    pub fn sign(
        &self,
        input: EcdsaInput<'_>,
        encoding: EcdsaEncoding,
    ) -> Result<Vec<u8>, CryptoError> {
        with_digest(input, |_, digest| {
            macro_rules! sign_curve {
                ($backend:ident) => {{
                    let key = $backend::ecdsa::SigningKey::from_slice(self.private.expose_secret())
                        .map_err(|_| CryptoError::PRIMITIVE_INVALID_PRIVATE_KEY)?;
                    let signature: $backend::ecdsa::Signature = key
                        .sign_prehash(digest)
                        .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
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
                #[cfg(all(
                    feature = "brainpool",
                    not(all(feature = "brainpool-openssl", not(target_arch = "wasm32")))
                ))]
                curve => super::portable_brainpool::sign(
                    curve,
                    self.private.expose_secret(),
                    digest,
                    encoding,
                ),
                #[cfg(not(any(
                    feature = "brainpool",
                    all(feature = "brainpool-openssl", not(target_arch = "wasm32"))
                )))]
                _ => Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
            }
        })
    }

    // Keep profile-specific private-key access inside the existing owner. A
    // generic scalar callback would allow adapters to export private material.
    #[cfg(feature = "operation-response")]
    pub(crate) fn sign_p256_low_s(&self, input: EcdsaInput<'_>) -> Result<Vec<u8>, CryptoError> {
        if self.curve != EcdsaCurve::P256 {
            return Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM);
        }
        #[cfg(any(feature = "native", feature = "wasm"))]
        {
            match input {
                EcdsaInput::Message {
                    hash: super::EcdsaHash::Sha256,
                    bytes,
                } => crypto_p256::sign_p256_sha256_message_low_s_der(
                    self.private.expose_secret(),
                    bytes,
                ),
                EcdsaInput::Prehash {
                    hash: super::EcdsaHash::Sha256,
                    bytes,
                } => {
                    let digest = crypto_p256::P256Sha256Digest::try_from_slice(bytes)?;
                    crypto_p256::sign_p256_sha256_digest_low_s_der(
                        self.private.expose_secret(),
                        &digest,
                    )
                }
                _ => Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
            }
        }
        #[cfg(not(any(feature = "native", feature = "wasm")))]
        {
            let _ = input;
            Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
        }
    }

    #[cfg(all(feature = "operation-response", feature = "native"))]
    pub(crate) fn compressed_p256_public_key(
        &self,
    ) -> Result<
        [u8; crypto_core::contract_constants::p256::P256_PUBLIC_KEY_COMPRESSED_LEN],
        CryptoError,
    > {
        if self.curve != EcdsaCurve::P256 {
            return Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM);
        }
        let scalar =
            <&[u8; crypto_p256::P256_SECRET_KEY_LEN]>::try_from(self.private.expose_secret())
                .map_err(|_| CryptoError::PRIMITIVE_INVALID_PRIVATE_KEY)?;
        crypto_p256::compressed_public_key_from_private_key(scalar)
    }

    /// Raw ECDH x-coordinate, fixed-width big-endian with leading zeros kept.
    /// No KDF, transcript processing or protocol labels are applied here.
    pub fn agree(&self, peer_sec1: &[u8]) -> Result<SecretSlice<u8>, CryptoError> {
        macro_rules! agree_curve {
            ($backend:ident) => {{
                let private = $backend::SecretKey::from_slice(self.private.expose_secret())
                    .map_err(|_| CryptoError::PRIMITIVE_INVALID_PRIVATE_KEY)?;
                let public = $backend::PublicKey::from_sec1_bytes(peer_sec1)
                    .map_err(|_| CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)?;
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
            #[cfg(all(
                feature = "brainpool",
                not(all(feature = "brainpool-openssl", not(target_arch = "wasm32")))
            ))]
            curve => {
                super::portable_brainpool::agree(curve, self.private.expose_secret(), peer_sec1)
            }
            #[cfg(not(any(
                feature = "brainpool",
                all(feature = "brainpool-openssl", not(target_arch = "wasm32"))
            )))]
            _ => Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
        }
    }
}

impl Zeroize for EcdsaKey {
    fn zeroize(&mut self) {
        self.private.zeroize();
    }
}

impl ZeroizeOnDrop for EcdsaKey {}

pub(super) fn secret_copy(bytes: &[u8]) -> Result<SecretSlice<u8>, CryptoError> {
    use secrecy::ExposeSecretMut;
    let mut storage = Zeroizing::new(Vec::new());
    storage
        .try_reserve_exact(bytes.len())
        .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    storage.resize(bytes.len(), 0);
    if storage.capacity() != bytes.len() {
        return Err(CryptoError::BACKEND_INTERNAL);
    }
    // Allocate and box while the buffer still contains zeros, then install the
    // secrecy owner before copying any private or shared-secret material.
    let mut owner = SecretSlice::from(core::mem::take(&mut *storage));
    owner.expose_secret_mut().copy_from_slice(bytes);
    Ok(owner)
}
