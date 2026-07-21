// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use ml_kem::{
    kem::Decapsulate,
    ml_kem_768::{Ciphertext as MlKem768Ciphertext, DecapsulationKey as MlKem768DecapsulationKey},
    Seed,
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::combine::combine_shared_secret;
use crate::expand::expand_decapsulation_key;
use crate::suite::{XWingSuite, ML_KEM_SECRET_SEED_LEN, X25519_KEY_LEN, X_WING_768_CIPHERTEXT_LEN};

type MlKemDecapsulateFn =
    fn(&[u8; ML_KEM_SECRET_SEED_LEN], &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError>;

fn split_ciphertext(
    suite: XWingSuite,
    ciphertext: &[u8],
) -> Result<(&[u8], &[u8; X25519_KEY_LEN]), CryptoError> {
    if ciphertext.len() != suite.ciphertext_len() {
        return Err(CryptoError::InvalidCiphertextLength {
            minimum: suite.ciphertext_len(),
            actual: ciphertext.len(),
        });
    }
    let ml_kem_ciphertext_len = suite.ml_kem_ciphertext_len();
    let (ml_kem_ciphertext, x25519_ciphertext) = ciphertext.split_at(ml_kem_ciphertext_len);
    let x25519_ciphertext = <&[u8; X25519_KEY_LEN]>::try_from(x25519_ciphertext).map_err(|_| {
        CryptoError::InvalidCiphertextLength {
            minimum: X25519_KEY_LEN,
            actual: x25519_ciphertext.len(),
        }
    })?;
    Ok((ml_kem_ciphertext, x25519_ciphertext))
}

fn ml_kem_768_decapsulate(
    seed_bytes: &[u8; ML_KEM_SECRET_SEED_LEN],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let seed = Seed::try_from(&seed_bytes[..]).map_err(|_| CryptoError::InvalidKey)?;
    let decapsulation_key = MlKem768DecapsulationKey::from_seed(seed);
    let ciphertext = MlKem768Ciphertext::try_from(ciphertext).map_err(|_| {
        CryptoError::InvalidCiphertextLength {
            minimum: XWingSuite::MlKem768.ml_kem_ciphertext_len(),
            actual: ciphertext.len(),
        }
    })?;
    let mut shared_secret = decapsulation_key.decapsulate(&ciphertext);
    let shared_secret_bytes = Zeroizing::new(shared_secret.as_slice().to_vec());
    shared_secret.zeroize();
    Ok(shared_secret_bytes)
}

fn decapsulate(
    suite: XWingSuite,
    ciphertext: &[u8],
    secret_key: &[u8],
    ml_kem_decapsulate_fn: MlKemDecapsulateFn,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let (ml_kem_ciphertext, x25519_ciphertext) = split_ciphertext(suite, ciphertext)?;
    let expanded = expand_decapsulation_key(secret_key)?;

    let ml_kem_shared_secret = ml_kem_decapsulate_fn(&expanded.ml_kem_seed, ml_kem_ciphertext)?;
    let x25519_secret = StaticSecret::from(*expanded.x25519_secret_key);
    let x25519_peer = PublicKey::from(*x25519_ciphertext);
    let x25519_shared = x25519_secret.diffie_hellman(&x25519_peer);
    let x25519_shared_secret = Zeroizing::new(x25519_shared.to_bytes());

    combine_shared_secret(
        &ml_kem_shared_secret,
        &x25519_shared_secret,
        x25519_ciphertext,
        &expanded.x25519_public_key,
        crypto_core::KemFailureKind::DecapsulateFailed,
    )
}

/// Decapsulate an X-Wing ciphertext using the standard ML-KEM-768 suite.
pub fn x_wing_768_decapsulate(
    ciphertext: &[u8],
    secret_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let result = decapsulate(
        XWingSuite::MlKem768,
        ciphertext,
        secret_key,
        ml_kem_768_decapsulate,
    )?;
    debug_assert_eq!(ciphertext.len(), X_WING_768_CIPHERTEXT_LEN);
    Ok(result)
}
