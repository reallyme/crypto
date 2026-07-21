// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! HPKE KEM adapter for the ML-KEM-512 primitive.

use hpke::hybrid_array::typenum::{U32, U64, U768, U800};
use hpke::kem::SharedSecret;
use hpke::rand_core::CryptoRng;
use hpke::{Deserializable, Kem, Serializable};
use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::ml_kem_512::{Ciphertext, DecapsulationKey, EncapsulationKey};
use ml_kem::{Seed, B32};
use shake::digest::{ExtendableOutput, Update, XofReader};
use shake::Shake256;
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

const KEM_ID: u16 = 0x0040;
const PRIVATE_KEY_LEN: usize = 64;
const PUBLIC_KEY_LEN: usize = 800;
const ENCAPSULATED_KEY_LEN: usize = 768;
const VERSION_LABEL: &[u8] = b"HPKE-v1";
const KEM_SUITE_ID: &[u8] = b"KEM\x00\x40";
const DERIVE_KEYPAIR_LABEL: &[u8] = b"DeriveKeyPair";
const EMPTY_CONTEXT: &[u8] = b"";
const DERIVE_KEYPAIR_LABEL_LEN: [u8; 2] = [0, 13];
const PRIVATE_KEY_LEN_U16: [u8; 2] = [0, 64];

/// ML-KEM private keys use the draft-defined 64-byte seed representation.
///
/// `Kem` requires `Clone`; every copy remains an explicit zeroize-on-drop
/// owner so cloning cannot leave an unmanaged secret allocation behind.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct MlKem512PrivateKey([u8; PRIVATE_KEY_LEN]);

impl ConstantTimeEq for MlKem512PrivateKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl Serializable for MlKem512PrivateKey {
    type OutputSize = U64;

    fn write_exact(&self, output: &mut [u8]) {
        if output.len() == PRIVATE_KEY_LEN {
            output.copy_from_slice(&self.0);
        }
    }
}

impl Deserializable for MlKem512PrivateKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, hpke::HpkeError> {
        let bytes = <[u8; PRIVATE_KEY_LEN]>::try_from(encoded)
            .map_err(|_| hpke::HpkeError::IncorrectInputLength(PRIVATE_KEY_LEN, encoded.len()))?;
        Ok(Self(bytes))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MlKem512PublicKey([u8; PUBLIC_KEY_LEN]);

impl Serializable for MlKem512PublicKey {
    type OutputSize = U800;

    fn write_exact(&self, output: &mut [u8]) {
        if output.len() == PUBLIC_KEY_LEN {
            output.copy_from_slice(&self.0);
        }
    }
}

impl Deserializable for MlKem512PublicKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, hpke::HpkeError> {
        let bytes = <[u8; PUBLIC_KEY_LEN]>::try_from(encoded)
            .map_err(|_| hpke::HpkeError::IncorrectInputLength(PUBLIC_KEY_LEN, encoded.len()))?;
        decode_public_key(&bytes)?;
        Ok(Self(bytes))
    }
}

#[derive(Clone)]
pub(crate) struct MlKem512EncappedKey([u8; ENCAPSULATED_KEY_LEN]);

impl Serializable for MlKem512EncappedKey {
    type OutputSize = U768;

    fn write_exact(&self, output: &mut [u8]) {
        if output.len() == ENCAPSULATED_KEY_LEN {
            output.copy_from_slice(&self.0);
        }
    }
}

impl Deserializable for MlKem512EncappedKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, hpke::HpkeError> {
        let bytes = <[u8; ENCAPSULATED_KEY_LEN]>::try_from(encoded).map_err(|_| {
            hpke::HpkeError::IncorrectInputLength(ENCAPSULATED_KEY_LEN, encoded.len())
        })?;
        Ok(Self(bytes))
    }
}

pub(crate) struct MlKem512;

impl Kem for MlKem512 {
    type PublicKey = MlKem512PublicKey;
    type PrivateKey = MlKem512PrivateKey;
    type EncappedKey = MlKem512EncappedKey;
    type NSecret = U32;

    const KEM_ID: u16 = KEM_ID;

    fn sk_to_pk(secret_key: &Self::PrivateKey) -> Self::PublicKey {
        public_key_from_seed(&secret_key.0)
    }

    fn derive_keypair(input_key_material: &[u8]) -> (Self::PrivateKey, Self::PublicKey) {
        let mut seed = [0_u8; PRIVATE_KEY_LEN];
        let mut hasher = Shake256::default();
        hasher.update(input_key_material);
        hasher.update(VERSION_LABEL);
        hasher.update(KEM_SUITE_ID);
        hasher.update(&DERIVE_KEYPAIR_LABEL_LEN);
        hasher.update(DERIVE_KEYPAIR_LABEL);
        hasher.update(&PRIVATE_KEY_LEN_U16);
        hasher.update(EMPTY_CONTEXT);
        hasher.finalize_xof().read(&mut seed);

        let public_key = public_key_from_seed(&seed);
        (MlKem512PrivateKey(seed), public_key)
    }

    fn decap(
        recipient_secret_key: &Self::PrivateKey,
        sender_public_key: Option<&Self::PublicKey>,
        encapsulated_key: &Self::EncappedKey,
    ) -> Result<SharedSecret<Self>, hpke::HpkeError> {
        if sender_public_key.is_some() {
            return Err(hpke::HpkeError::DecapError);
        }

        let decapsulation_key = decapsulation_key_from_seed(&recipient_secret_key.0);
        let ciphertext = Ciphertext::try_from(encapsulated_key.0.as_slice())
            .map_err(|_| hpke::HpkeError::DecapError)?;
        let mut raw_shared_secret = decapsulation_key.decapsulate(&ciphertext);
        let mut shared_secret = SharedSecret::<Self>::default();
        shared_secret.0.copy_from_slice(&raw_shared_secret);
        raw_shared_secret.zeroize();
        Ok(shared_secret)
    }

    fn encap_with_rng(
        recipient_public_key: &Self::PublicKey,
        sender_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
        csprng: &mut impl CryptoRng,
    ) -> Result<(SharedSecret<Self>, Self::EncappedKey), hpke::HpkeError> {
        if sender_keypair.is_some() {
            return Err(hpke::HpkeError::EncapError);
        }

        let public_key = decode_public_key(&recipient_public_key.0)?;
        let mut randomness = B32::default();
        csprng.fill_bytes(&mut randomness);
        let (ciphertext, mut raw_shared_secret) = public_key.encapsulate_deterministic(&randomness);
        randomness.zeroize();

        let mut shared_secret = SharedSecret::<Self>::default();
        shared_secret.0.copy_from_slice(&raw_shared_secret);
        raw_shared_secret.zeroize();

        let mut encapsulated_key = [0_u8; ENCAPSULATED_KEY_LEN];
        encapsulated_key.copy_from_slice(&ciphertext);
        Ok((shared_secret, MlKem512EncappedKey(encapsulated_key)))
    }
}

fn decapsulation_key_from_seed(seed: &[u8; PRIVATE_KEY_LEN]) -> DecapsulationKey {
    let mut typed_seed = Seed::default();
    typed_seed.copy_from_slice(seed);
    DecapsulationKey::from_seed(typed_seed)
}

fn public_key_from_seed(seed: &[u8; PRIVATE_KEY_LEN]) -> MlKem512PublicKey {
    let decapsulation_key = decapsulation_key_from_seed(seed);
    let encoded = decapsulation_key.encapsulation_key().to_bytes();
    let mut public_key = [0_u8; PUBLIC_KEY_LEN];
    public_key.copy_from_slice(&encoded);
    MlKem512PublicKey(public_key)
}

fn decode_public_key(encoded: &[u8; PUBLIC_KEY_LEN]) -> Result<EncapsulationKey, hpke::HpkeError> {
    let key = ml_kem::Key::<EncapsulationKey>::try_from(encoded.as_slice())
        .map_err(|_| hpke::HpkeError::ValidationError)?;
    EncapsulationKey::new(&key).map_err(|_| hpke::HpkeError::ValidationError)
}
