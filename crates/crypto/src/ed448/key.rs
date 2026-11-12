// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use ed448_goldilocks::EdwardsPoint;
use secrecy::{ExposeSecret, ExposeSecretMut, SecretSlice};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{scalar, transcript, Ed448Error, PUBLIC_KEY_LEN, SEED_LEN, SIGNATURE_LEN};
use crate::key_random::{KeyRng, SystemKeyRng};

/// Protected software Ed448 seed bound to its public key. The seed is never
/// exported, cloned or included in diagnostic formatting.
///
/// ```compile_fail
/// use reallyme_crypto::ed448::Ed448Key;
/// let key = Ed448Key::import(&[0; 57]).unwrap();
/// let _ = format!("{key:?}");
/// ```
pub struct Ed448Key {
    seed: SecretSlice<u8>,
    public: [u8; PUBLIC_KEY_LEN],
    destroyed: bool,
}

impl Ed448Key {
    /// Import an exact 57-byte RFC 8032 seed. All seed values are valid. The
    /// caller retains responsibility for clearing the borrowed source.
    #[allow(clippy::op_ref)] // Borrow guarded scalars instead of explicitly copying secret operands.
    pub fn import(seed: &[u8]) -> Result<Self, Ed448Error> {
        if seed.len() != SEED_LEN {
            return Err(Ed448Error::InvalidPrivateKey);
        }
        let expanded = transcript::expand(seed);
        let scalar = scalar::reduce(&expanded[..SEED_LEN])?;
        let point = Zeroizing::new(&EdwardsPoint::GENERATOR * &*scalar);
        let public = point.to_affine().compress().to_bytes();
        Ok(Self {
            seed: secret_copy(seed)?,
            public,
            destroyed: false,
        })
    }

    /// Generate a seed with operating-system entropy.
    pub fn generate() -> Result<Self, Ed448Error> {
        Self::generate_with_rng(&mut SystemKeyRng)
    }

    /// Generate using an injected cryptographic entropy source. A partial fill
    /// followed by failure still leaves the candidate in clearing storage.
    pub fn generate_with_rng(rng: &mut impl KeyRng) -> Result<Self, Ed448Error> {
        let mut seed = Zeroizing::new([0; SEED_LEN]);
        rng.fill(seed.as_mut())
            .map_err(|_| Ed448Error::RandomnessUnavailable)?;
        Self::import(seed.as_ref())
    }

    /// RFC 8032 compressed public key associated with this seed.
    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public
    }

    /// Sign exact message bytes with ordinary Ed448 and empty context.
    #[allow(clippy::op_ref)] // Keep scalar operands borrowed from their clearing owners.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; SIGNATURE_LEN], Ed448Error> {
        if self.destroyed {
            return Err(Ed448Error::InvalidPrivateKey);
        }
        let expanded = transcript::expand(self.seed.expose_secret());
        let private = scalar::reduce(&expanded[..SEED_LEN])?;
        let nonce_hash = transcript::hash(&[transcript::DOMAIN, &expanded[SEED_LEN..], message]);
        let nonce = scalar::reduce(nonce_hash.as_ref())?;
        let nonce_point = Zeroizing::new(&EdwardsPoint::GENERATOR * &*nonce);
        // R and S become public only as components of the returned signature.
        let encoded_r = nonce_point.to_affine().compress().to_bytes();
        let challenge_hash =
            transcript::hash(&[transcript::DOMAIN, &encoded_r, &self.public, message]);
        let challenge = scalar::reduce(challenge_hash.as_ref())?;
        let product = Zeroizing::new(&*challenge * &*private);
        let s = Zeroizing::new(&*nonce + &*product);
        let encoded_s = Zeroizing::new(s.to_bytes_rfc_8032());
        let mut signature = Zeroizing::new([0; SIGNATURE_LEN]);
        signature[..PUBLIC_KEY_LEN].copy_from_slice(&encoded_r);
        signature[PUBLIC_KEY_LEN..].copy_from_slice(encoded_s.as_ref());
        // Check the exact output against the bound public key before exposing
        // it, including when an explicitly selected native verifier is used.
        super::verify(&self.public, message, signature.as_ref())?;
        Ok(*signature)
    }
}

impl Zeroize for Ed448Key {
    fn zeroize(&mut self) {
        self.seed.zeroize();
        self.public.zeroize();
        // An all-zero seed is itself valid, so erased owners must not be
        // accidentally reused as a different, valid signing key.
        self.destroyed = true;
    }
}

impl ZeroizeOnDrop for Ed448Key {}

impl Drop for Ed448Key {
    fn drop(&mut self) {
        self.zeroize();
    }
}

fn secret_copy(seed: &[u8]) -> Result<SecretSlice<u8>, Ed448Error> {
    let mut storage = Zeroizing::new(Vec::new());
    storage
        .try_reserve_exact(SEED_LEN)
        .map_err(|_| Ed448Error::AllocationFailed)?;
    storage.resize(SEED_LEN, 0);
    if storage.capacity() != SEED_LEN {
        return Err(Ed448Error::AllocationFailed);
    }
    let mut owner = SecretSlice::from(core::mem::take(&mut *storage));
    owner.expose_secret_mut().copy_from_slice(seed);
    Ok(owner)
}

#[cfg(test)]
#[path = "key_tests.rs"]
mod tests;
