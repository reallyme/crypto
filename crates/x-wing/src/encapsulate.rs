// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, KemFailureKind, KeyAgreementFailureKind};
use ml_kem::{
    ml_kem_768::{EncapsulationKey as MlKem768EncapsulationKey, MlKem768},
    EncapsulationKey, Key, B32,
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::combine::combine_shared_secret;
use crate::random::fill_random;
use crate::suite::{
    XWingSuite, ML_KEM_SHARED_SECRET_LEN, X25519_KEY_LEN, X_WING_768_CIPHERTEXT_LEN,
    X_WING_ENCAPS_SEED_LEN, X_WING_SHARED_SECRET_LEN,
};

type MlKemEncapsulateFn = fn(
    &[u8],
    &[u8; ML_KEM_SHARED_SECRET_LEN],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError>;

fn checked_ciphertext_capacity(suite: XWingSuite) -> Result<usize, CryptoError> {
    suite
        .ml_kem_ciphertext_len()
        .checked_add(X25519_KEY_LEN)
        .ok_or(CryptoError::KemFailure {
            kind: KemFailureKind::EncapsulateFailed,
        })
}

fn split_public_key(
    suite: XWingSuite,
    public_key: &[u8],
) -> Result<(&[u8], &[u8; X25519_KEY_LEN]), CryptoError> {
    if public_key.len() != suite.public_key_len() {
        return Err(CryptoError::InvalidKey);
    }
    let ml_kem_public_len = suite.ml_kem_public_key_len();
    let (ml_kem_public_key, x25519_public_key) = public_key.split_at(ml_kem_public_len);
    let x25519_public_key = <&[u8; X25519_KEY_LEN]>::try_from(x25519_public_key)
        .map_err(|_| CryptoError::InvalidKey)?;
    Ok((ml_kem_public_key, x25519_public_key))
}

fn ml_kem_encapsulate_derand(
    public_key: &[u8],
    randomness: &[u8; ML_KEM_SHARED_SECRET_LEN],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    let public_key = Key::<EncapsulationKey<MlKem768>>::try_from(public_key)
        .map_err(|_| CryptoError::InvalidKey)?;
    let encapsulation_key =
        MlKem768EncapsulationKey::new(&public_key).map_err(|_| CryptoError::InvalidKey)?;
    let randomness = B32::try_from(&randomness[..]).map_err(|_| CryptoError::InvalidKey)?;
    let (mut ciphertext, mut shared_secret) =
        encapsulation_key.encapsulate_deterministic(&randomness);
    let ciphertext_bytes = ciphertext.as_slice().to_vec();
    let shared_secret_bytes = Zeroizing::new(shared_secret.as_slice().to_vec());
    ciphertext.zeroize();
    shared_secret.zeroize();
    Ok((ciphertext_bytes, shared_secret_bytes))
}

fn encapsulate_derand(
    suite: XWingSuite,
    public_key: &[u8],
    seed: &[u8],
    ml_kem_encapsulate_fn: MlKemEncapsulateFn,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    if seed.len() != X_WING_ENCAPS_SEED_LEN {
        return Err(CryptoError::InvalidKey);
    }

    let (ml_kem_public_key, x25519_public_key) = split_public_key(suite, public_key)?;
    let mut ml_kem_randomness = Zeroizing::new([0u8; ML_KEM_SHARED_SECRET_LEN]);
    ml_kem_randomness.copy_from_slice(&seed[..ML_KEM_SHARED_SECRET_LEN]);
    let mut x25519_ephemeral_secret = Zeroizing::new([0u8; X25519_KEY_LEN]);
    x25519_ephemeral_secret.copy_from_slice(&seed[ML_KEM_SHARED_SECRET_LEN..]);

    let x25519_secret = StaticSecret::from(*x25519_ephemeral_secret);
    let x25519_ciphertext = PublicKey::from(&x25519_secret).to_bytes();
    let x25519_peer = PublicKey::from(*x25519_public_key);
    let x25519_shared = x25519_secret.diffie_hellman(&x25519_peer);
    if !x25519_shared.was_contributory() {
        return Err(CryptoError::KeyAgreementFailure {
            kind: KeyAgreementFailureKind::DeriveSharedSecretFailed,
        });
    }
    let x25519_shared_secret = Zeroizing::new(x25519_shared.to_bytes());

    let (ml_kem_ciphertext, ml_kem_shared_secret) =
        ml_kem_encapsulate_fn(ml_kem_public_key, &ml_kem_randomness)?;
    ml_kem_randomness.zeroize();

    let shared_secret = combine_shared_secret(
        &ml_kem_shared_secret,
        &x25519_shared_secret,
        &x25519_ciphertext,
        x25519_public_key,
        KemFailureKind::EncapsulateFailed,
    )?;

    let mut ciphertext = Vec::with_capacity(checked_ciphertext_capacity(suite)?);
    ciphertext.extend_from_slice(&ml_kem_ciphertext);
    ciphertext.extend_from_slice(&x25519_ciphertext);

    debug_assert_eq!(ciphertext.len(), suite.ciphertext_len());
    debug_assert_eq!(shared_secret.len(), X_WING_SHARED_SECRET_LEN);
    Ok((ciphertext, shared_secret))
}

fn encapsulate(
    suite: XWingSuite,
    public_key: &[u8],
    ml_kem_encapsulate_fn: MlKemEncapsulateFn,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    let mut seed = Zeroizing::new([0u8; X_WING_ENCAPS_SEED_LEN]);
    fill_random(&mut *seed)?;
    let result = encapsulate_derand(suite, public_key, &*seed, ml_kem_encapsulate_fn);
    seed.zeroize();
    result
}

/// Encapsulate to an X-Wing public key using the standard ML-KEM-768 suite.
pub fn x_wing_768_encapsulate(
    public_key: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    encapsulate(XWingSuite::MlKem768, public_key, ml_kem_encapsulate_derand)
}

/// Deterministically encapsulate to an X-Wing public key using a 64-byte seed.
pub fn x_wing_768_encapsulate_derand(
    public_key: &[u8],
    seed: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    let result = encapsulate_derand(
        XWingSuite::MlKem768,
        public_key,
        seed,
        ml_kem_encapsulate_derand,
    )?;
    debug_assert_eq!(result.0.len(), X_WING_768_CIPHERTEXT_LEN);
    Ok(result)
}
