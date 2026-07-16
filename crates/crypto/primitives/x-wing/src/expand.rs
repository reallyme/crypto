// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use crypto_sha3::shake256_expand;
use ml_kem::{
    kem::KeyExport, ml_kem_1024::DecapsulationKey as MlKem1024DecapsulationKey,
    ml_kem_768::DecapsulationKey as MlKem768DecapsulationKey, Seed,
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::suite::{
    ML_KEM_SECRET_SEED_LEN, X25519_KEY_LEN, X_WING_EXPANDED_SECRET_LEN, X_WING_SECRET_KEY_LEN,
};

pub(crate) struct ExpandedXWingKey {
    pub(crate) ml_kem_seed: Zeroizing<[u8; ML_KEM_SECRET_SEED_LEN]>,
    pub(crate) x25519_secret_key: Zeroizing<[u8; X25519_KEY_LEN]>,
    pub(crate) x25519_public_key: [u8; X25519_KEY_LEN],
}

pub(crate) fn expand_decapsulation_key(secret_key: &[u8]) -> Result<ExpandedXWingKey, CryptoError> {
    if secret_key.len() != X_WING_SECRET_KEY_LEN {
        return Err(CryptoError::InvalidKey);
    }

    let mut expanded = Zeroizing::new([0u8; X_WING_EXPANDED_SECRET_LEN]);
    shake256_expand(secret_key, &mut *expanded);

    let mut ml_kem_seed = Zeroizing::new([0u8; ML_KEM_SECRET_SEED_LEN]);
    ml_kem_seed.copy_from_slice(&expanded[..ML_KEM_SECRET_SEED_LEN]);

    let mut x25519_secret_key = Zeroizing::new([0u8; X25519_KEY_LEN]);
    x25519_secret_key.copy_from_slice(&expanded[ML_KEM_SECRET_SEED_LEN..]);
    let x25519_secret = StaticSecret::from(*x25519_secret_key);
    let x25519_public_key = PublicKey::from(&x25519_secret).to_bytes();

    expanded.zeroize();

    Ok(ExpandedXWingKey {
        ml_kem_seed,
        x25519_secret_key,
        x25519_public_key,
    })
}

pub(crate) fn ml_kem_768_public_key(
    seed_bytes: &[u8; ML_KEM_SECRET_SEED_LEN],
) -> Result<Vec<u8>, CryptoError> {
    let seed = Seed::try_from(&seed_bytes[..]).map_err(|_| CryptoError::InvalidKey)?;
    let decapsulation_key = MlKem768DecapsulationKey::from_seed(seed);
    Ok(decapsulation_key.encapsulation_key().to_bytes().to_vec())
}

pub(crate) fn ml_kem_1024_public_key(
    seed_bytes: &[u8; ML_KEM_SECRET_SEED_LEN],
) -> Result<Vec<u8>, CryptoError> {
    let seed = Seed::try_from(&seed_bytes[..]).map_err(|_| CryptoError::InvalidKey)?;
    let decapsulation_key = MlKem1024DecapsulationKey::from_seed(seed);
    Ok(decapsulation_key.encapsulation_key().to_bytes().to_vec())
}
