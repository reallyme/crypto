// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! HPKE KEM adapter for the draft ML-KEM-1024/P-384 hybrid.

use hpke::hybrid_array::sizes::{U1665, U32};
use hpke::kem::SharedSecret;
use hpke::rand_core::CryptoRng;
use hpke::{Deserializable, Kem, Serializable};
use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::ml_kem_1024::{Ciphertext, DecapsulationKey, EncapsulationKey};
use ml_kem::{Seed, B32};
use p384::elliptic_curve::{ops::ReduceNonZero, sec1::ToSec1Point};
use p384::{FieldBytes, NonZeroScalar, PublicKey as P384PublicKey, SecretKey as P384SecretKey};
use sha3::{Digest, Sha3_256};
use shake::digest::{ExtendableOutput, Update, XofReader};
use shake::Shake256;
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const KEM_ID: u16 = 0x0051;
const PRIVATE_KEY_LEN: usize = 32;
const ML_KEM_SEED_LEN: usize = 64;
const ML_KEM_PUBLIC_KEY_LEN: usize = 1_568;
const ML_KEM_CIPHERTEXT_LEN: usize = 1_568;
const P384_SCALAR_LEN: usize = 48;
const P384_PUBLIC_KEY_LEN: usize = 97;
const PUBLIC_KEY_LEN: usize = ML_KEM_PUBLIC_KEY_LEN + P384_PUBLIC_KEY_LEN;
const ENCAPSULATED_KEY_LEN: usize = ML_KEM_CIPHERTEXT_LEN + P384_PUBLIC_KEY_LEN;
const VERSION_LABEL: &[u8] = b"HPKE-v1";
const KEM_SUITE_ID: &[u8] = b"KEM\x00\x51";
const DERIVE_KEYPAIR_LABEL: &[u8] = b"DeriveKeyPair";
const DERIVE_KEYPAIR_LABEL_LEN: [u8; 2] = [0, 13];
const PRIVATE_KEY_LEN_U16: [u8; 2] = [0, 32];
const KEM_LABEL: &[u8] = b"MLKEM1024-P384";
const SEC1_UNCOMPRESSED_POINT_TAG: u8 = 0x04;

// `hpke::Kem` requires private keys to be cloneable. Every clone retains the
// same zeroize-on-drop owner semantics; the type remains crate-private and
// deliberately omits `Debug`, serialization frameworks, and display output.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct MlKem1024P384PrivateKey([u8; PRIVATE_KEY_LEN]);

impl ConstantTimeEq for MlKem1024P384PrivateKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl Serializable for MlKem1024P384PrivateKey {
    type OutputSize = U32;

    fn write_exact(&self, output: &mut [u8]) {
        if output.len() == PRIVATE_KEY_LEN {
            output.copy_from_slice(&self.0);
        }
    }
}

impl Deserializable for MlKem1024P384PrivateKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, hpke::HpkeError> {
        let seed = <[u8; PRIVATE_KEY_LEN]>::try_from(encoded)
            .map_err(|_| hpke::HpkeError::IncorrectInputLength(PRIVATE_KEY_LEN, encoded.len()))?;
        Ok(Self(seed))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MlKem1024P384PublicKey([u8; PUBLIC_KEY_LEN]);

impl Serializable for MlKem1024P384PublicKey {
    type OutputSize = U1665;

    fn write_exact(&self, output: &mut [u8]) {
        if output.len() == PUBLIC_KEY_LEN {
            output.copy_from_slice(&self.0);
        }
    }
}

impl Deserializable for MlKem1024P384PublicKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, hpke::HpkeError> {
        let bytes = <[u8; PUBLIC_KEY_LEN]>::try_from(encoded)
            .map_err(|_| hpke::HpkeError::IncorrectInputLength(PUBLIC_KEY_LEN, encoded.len()))?;
        decode_public_key(&bytes)?;
        Ok(Self(bytes))
    }
}

#[derive(Clone)]
pub(crate) struct MlKem1024P384EncappedKey([u8; ENCAPSULATED_KEY_LEN]);

impl Serializable for MlKem1024P384EncappedKey {
    type OutputSize = U1665;

    fn write_exact(&self, output: &mut [u8]) {
        if output.len() == ENCAPSULATED_KEY_LEN {
            output.copy_from_slice(&self.0);
        }
    }
}

impl Deserializable for MlKem1024P384EncappedKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, hpke::HpkeError> {
        let bytes = <[u8; ENCAPSULATED_KEY_LEN]>::try_from(encoded).map_err(|_| {
            hpke::HpkeError::IncorrectInputLength(ENCAPSULATED_KEY_LEN, encoded.len())
        })?;
        decode_p384_public_key(&bytes[ML_KEM_CIPHERTEXT_LEN..])?;
        Ok(Self(bytes))
    }
}

pub(crate) struct MlKem1024P384;

impl Kem for MlKem1024P384 {
    type PublicKey = MlKem1024P384PublicKey;
    type PrivateKey = MlKem1024P384PrivateKey;
    type EncappedKey = MlKem1024P384EncappedKey;
    type NSecret = U32;

    const KEM_ID: u16 = KEM_ID;

    fn sk_to_pk(secret_key: &Self::PrivateKey) -> Self::PublicKey {
        public_key_from_seed(&secret_key.0)
    }

    fn derive_keypair(input_key_material: &[u8]) -> (Self::PrivateKey, Self::PublicKey) {
        let seed = derive_private_seed(input_key_material);
        let public_key = public_key_from_seed(&seed);
        (MlKem1024P384PrivateKey(*seed), public_key)
    }

    fn decap(
        recipient_secret_key: &Self::PrivateKey,
        sender_public_key: Option<&Self::PublicKey>,
        encapsulated_key: &Self::EncappedKey,
    ) -> Result<SharedSecret<Self>, hpke::HpkeError> {
        if sender_public_key.is_some() {
            return Err(hpke::HpkeError::DecapError);
        }

        let (decapsulation_key, p384_secret_key) = expand_private_key(&recipient_secret_key.0);
        let ciphertext = Ciphertext::try_from(&encapsulated_key.0[..ML_KEM_CIPHERTEXT_LEN])
            .map_err(|_| hpke::HpkeError::DecapError)?;
        let mut ml_kem_shared_secret = decapsulation_key.decapsulate(&ciphertext);
        let p384_encapsulated_key =
            decode_p384_public_key(&encapsulated_key.0[ML_KEM_CIPHERTEXT_LEN..])?;
        let p384_shared_secret = p384::ecdh::diffie_hellman(
            p384_secret_key.to_nonzero_scalar(),
            p384_encapsulated_key.as_affine(),
        );
        let recipient_p384_public_key = p384_secret_key.public_key().to_sec1_point(false);
        let combined = combine_shared_secret(
            &ml_kem_shared_secret,
            p384_shared_secret.raw_secret_bytes(),
            &encapsulated_key.0[ML_KEM_CIPHERTEXT_LEN..],
            recipient_p384_public_key.as_bytes(),
        );
        ml_kem_shared_secret.zeroize();

        let mut shared_secret = SharedSecret::<Self>::default();
        shared_secret.0.copy_from_slice(combined.as_slice());
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

        let (ml_kem_public_key, p384_public_key) = decode_public_key(&recipient_public_key.0)?;
        let mut ml_kem_randomness = B32::default();
        csprng.fill_bytes(&mut ml_kem_randomness);
        let (ciphertext, mut ml_kem_shared_secret) =
            ml_kem_public_key.encapsulate_deterministic(&ml_kem_randomness);
        ml_kem_randomness.zeroize();

        let mut p384_randomness = Zeroizing::new([0_u8; P384_SCALAR_LEN]);
        csprng.fill_bytes(p384_randomness.as_mut_slice());
        let ephemeral_secret_key = scalar_from_candidate(&p384_randomness);
        let ephemeral_public_key = ephemeral_secret_key.public_key().to_sec1_point(false);
        let p384_shared_secret = p384::ecdh::diffie_hellman(
            ephemeral_secret_key.to_nonzero_scalar(),
            p384_public_key.as_affine(),
        );
        let recipient_p384_public_key = p384_public_key.to_sec1_point(false);
        let combined = combine_shared_secret(
            &ml_kem_shared_secret,
            p384_shared_secret.raw_secret_bytes(),
            ephemeral_public_key.as_bytes(),
            recipient_p384_public_key.as_bytes(),
        );
        ml_kem_shared_secret.zeroize();

        let mut encoded = [0_u8; ENCAPSULATED_KEY_LEN];
        encoded[..ML_KEM_CIPHERTEXT_LEN].copy_from_slice(&ciphertext);
        encoded[ML_KEM_CIPHERTEXT_LEN..].copy_from_slice(ephemeral_public_key.as_bytes());

        let mut shared_secret = SharedSecret::<Self>::default();
        shared_secret.0.copy_from_slice(combined.as_slice());
        Ok((shared_secret, MlKem1024P384EncappedKey(encoded)))
    }
}

fn derive_private_seed(input_key_material: &[u8]) -> Zeroizing<[u8; PRIVATE_KEY_LEN]> {
    let mut seed = Zeroizing::new([0_u8; PRIVATE_KEY_LEN]);
    let mut hasher = Shake256::default();
    hasher.update(input_key_material);
    hasher.update(VERSION_LABEL);
    hasher.update(KEM_SUITE_ID);
    hasher.update(&DERIVE_KEYPAIR_LABEL_LEN);
    hasher.update(DERIVE_KEYPAIR_LABEL);
    hasher.update(&PRIVATE_KEY_LEN_U16);
    hasher.update(&[]);
    hasher.finalize_xof().read(seed.as_mut_slice());
    seed
}

fn expand_private_key(seed: &[u8; PRIVATE_KEY_LEN]) -> (DecapsulationKey, P384SecretKey) {
    let mut ml_kem_seed = Zeroizing::new([0_u8; ML_KEM_SEED_LEN]);
    let mut p384_seed = Zeroizing::new([0_u8; P384_SCALAR_LEN]);
    let mut reader = Shake256::default().chain(seed).finalize_xof();
    reader.read(ml_kem_seed.as_mut_slice());
    reader.read(p384_seed.as_mut_slice());

    let mut typed_seed = Seed::default();
    typed_seed.copy_from_slice(ml_kem_seed.as_slice());
    let decapsulation_key = DecapsulationKey::from_seed(typed_seed);
    let p384_secret_key = scalar_from_candidate(&p384_seed);
    (decapsulation_key, p384_secret_key)
}

fn public_key_from_seed(seed: &[u8; PRIVATE_KEY_LEN]) -> MlKem1024P384PublicKey {
    let (decapsulation_key, p384_secret_key) = expand_private_key(seed);
    let ml_kem_public_key = decapsulation_key.encapsulation_key().to_bytes();
    let p384_public_key = p384_secret_key.public_key().to_sec1_point(false);
    let mut encoded = [0_u8; PUBLIC_KEY_LEN];
    encoded[..ML_KEM_PUBLIC_KEY_LEN].copy_from_slice(&ml_kem_public_key);
    encoded[ML_KEM_PUBLIC_KEY_LEN..].copy_from_slice(p384_public_key.as_bytes());
    MlKem1024P384PublicKey(encoded)
}

fn decode_public_key(
    encoded: &[u8; PUBLIC_KEY_LEN],
) -> Result<(EncapsulationKey, P384PublicKey), hpke::HpkeError> {
    let ml_kem_key = ml_kem::Key::<EncapsulationKey>::try_from(&encoded[..ML_KEM_PUBLIC_KEY_LEN])
        .map_err(|_| hpke::HpkeError::ValidationError)?;
    let ml_kem_public_key =
        EncapsulationKey::new(&ml_kem_key).map_err(|_| hpke::HpkeError::ValidationError)?;
    let p384_public_key = decode_p384_public_key(&encoded[ML_KEM_PUBLIC_KEY_LEN..])?;
    Ok((ml_kem_public_key, p384_public_key))
}

fn decode_p384_public_key(encoded: &[u8]) -> Result<P384PublicKey, hpke::HpkeError> {
    if encoded.len() != P384_PUBLIC_KEY_LEN
        || encoded.first().copied() != Some(SEC1_UNCOMPRESSED_POINT_TAG)
    {
        return Err(hpke::HpkeError::ValidationError);
    }
    P384PublicKey::from_sec1_bytes(encoded).map_err(|_| hpke::HpkeError::ValidationError)
}

fn scalar_from_candidate(candidate: &[u8; P384_SCALAR_LEN]) -> P384SecretKey {
    if let Ok(secret_key) = P384SecretKey::from_slice(candidate) {
        return secret_key;
    }

    // Rejection has negligible probability for a uniform P-384 candidate, but
    // the backend KEM trait cannot return a derivation error. Reducing the same
    // candidate into [1, order) avoids an inherited panic while leaving every
    // conforming execution byte-for-byte unchanged.
    let mut field_bytes = FieldBytes::default();
    field_bytes.copy_from_slice(candidate);
    let scalar = NonZeroScalar::reduce_nonzero(&field_bytes);
    P384SecretKey::from(scalar)
}

fn combine_shared_secret(
    ml_kem_shared_secret: &[u8],
    p384_shared_secret: &[u8],
    encapsulated_p384_key: &[u8],
    recipient_p384_key: &[u8],
) -> Zeroizing<[u8; 32]> {
    let digest = Zeroizing::new(
        Sha3_256::new()
            .chain_update(ml_kem_shared_secret)
            .chain_update(p384_shared_secret)
            .chain_update(encapsulated_p384_key)
            .chain_update(recipient_p384_key)
            .chain_update(KEM_LABEL)
            .finalize(),
    );
    let mut output = Zeroizing::new([0_u8; 32]);
    output.copy_from_slice(&digest);
    output
}
