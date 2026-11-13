// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use hpke::{Deserializable, Kem as KemTrait, Serializable};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretSlice};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{
    storage, Kem, P256BaseError, P256BaseRng, SystemRandom, PRIVATE_KEY_LEN, PUBLIC_KEY_LEN,
};

/// Validated recipient key with a public-key association and no private export.
/// Private bytes live in a secrecy owner and are cleared when it is dropped.
pub struct P256RecipientKey {
    private: SecretSlice<u8>,
    public: [u8; PUBLIC_KEY_LEN],
}

impl P256RecipientKey {
    /// Import an RFC 9180 big-endian private scalar, checking its range.
    /// The caller retains responsibility for clearing its borrowed source.
    pub fn import(private: &[u8]) -> Result<Self, P256BaseError> {
        if private.len() != PRIVATE_KEY_LEN {
            return Err(P256BaseError::PRIMITIVE_INVALID_PRIVATE_KEY);
        }
        let parsed = <Kem as KemTrait>::PrivateKey::from_bytes(private)
            .map_err(|_| P256BaseError::PRIMITIVE_INVALID_PRIVATE_KEY)?;
        let public = Kem::sk_to_pk(&parsed).to_bytes();
        let mut owner = Self::empty()?;
        owner.public.copy_from_slice(public.as_slice());
        owner.private.expose_secret_mut().copy_from_slice(private);
        Ok(owner)
    }

    /// Generate a fresh key using operating-system entropy and RFC 9180
    /// `DeriveKeyPair`, keeping the IKM and serialized scalar guarded.
    pub fn generate() -> Result<Self, P256BaseError> {
        Self::generate_with_rng(&mut SystemRandom)
    }

    /// Generate a key using an injected cryptographic entropy source.
    pub fn generate_with_rng(rng: &mut impl P256BaseRng) -> Result<Self, P256BaseError> {
        let mut ikm = Zeroizing::new([0; PRIVATE_KEY_LEN]);
        rng.fill(ikm.as_mut_slice())?;
        let (private, public) = Kem::derive_keypair(ikm.as_slice());
        let mut owner = Self::empty()?;
        owner.public.copy_from_slice(public.to_bytes().as_slice());
        // Write directly through the secrecy owner, avoiding an owned scalar
        // serialization temporary. Its size is fixed by this concrete KEM.
        private.write_exact(owner.private.expose_secret_mut());
        Ok(owner)
    }

    /// RFC 9180 uncompressed public key corresponding to the owned scalar.
    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public
    }

    pub(super) fn private_key(&self) -> &[u8] {
        self.private.expose_secret()
    }

    fn empty() -> Result<Self, P256BaseError> {
        let mut storage = storage::buffer(PRIVATE_KEY_LEN)?;
        if storage.capacity() != PRIVATE_KEY_LEN {
            return Err(P256BaseError::BACKEND_INTERNAL);
        }
        // Box conversion happens while storage contains only zeros. This
        // exact capacity also prevents an infallible shrink allocation in
        // Vec::into_boxed_slice after the fallible reservation above.
        let private = SecretSlice::from(core::mem::take(&mut *storage));
        Ok(Self {
            private,
            public: [0; PUBLIC_KEY_LEN],
        })
    }
}

impl Zeroize for P256RecipientKey {
    fn zeroize(&mut self) {
        self.private.zeroize();
    }
}

impl ZeroizeOnDrop for P256RecipientKey {}
